import gzip
import json
import os
import pickle
import urllib.parse
import logging
from datetime import datetime
from io import BytesIO

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError, NoCredentialsError, PartialCredentialsError
from config.config_loader import load_runtime_config


# Global cache for model (persists across warm Lambda invocations)
MODEL_CACHE = {}

RETRY_CONFIG = Config(retries={'max_attempts': 8, 'mode': 'standard'})
LOGGER = logging.getLogger(__name__)
if not LOGGER.handlers:
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(name)s %(message)s')

# Suspicious API calls that should always be flagged
SUSPICIOUS_APIS = [
    'DeleteTrail', 'StopLogging', 'UpdateTrail',
    'DeleteBucket', 'DeleteBucketPolicy',
    'CreateUser', 'CreateAccessKey', 'DeleteUser',
    'AttachUserPolicy', 'AttachRolePolicy',
    'PutBucketPolicy', 'PutBucketAcl',
    'AuthorizeSecurityGroupIngress', 'AuthorizeSecurityGroupEgress',
    'CreateKeyPair', 'ImportKeyPair',
    'RunInstances', 'CreateRole', 'CreateFunction'
]


def log_event(level, message, **fields):
    payload = {
        'timestamp': datetime.utcnow().isoformat(),
        'level': level,
        'message': message,
    }
    payload.update(fields)
    log_level = getattr(logging, str(level).upper(), logging.INFO)
    LOGGER.log(log_level, json.dumps(payload, default=str))


def s3_client():
    return boto3.client('s3', config=RETRY_CONFIG)


def load_model(model_bucket, model_key, rule_only_mode):
    """Load the trained model from S3 (with caching)."""
    if rule_only_mode:
        log_event('WARN', 'Rule-only mode enabled; ML model will be skipped')
        return None

    if not model_bucket:
        log_event('WARN', 'Model bucket not provided; skipping ML model loading')
        return None

    cache_key = f"{model_bucket}/{model_key}"
    if cache_key in MODEL_CACHE:
        log_event('INFO', 'Using cached model')
        return MODEL_CACHE[cache_key]

    log_event('INFO', 'Loading model from S3', model_bucket=model_bucket, model_key=model_key)

    try:
        response = s3_client().get_object(Bucket=model_bucket, Key=model_key)
        MODEL_CACHE[cache_key] = pickle.loads(response['Body'].read())
        log_event('INFO', 'Model loaded successfully')
        return MODEL_CACHE[cache_key]
    except (ClientError, NoCredentialsError, PartialCredentialsError, pickle.PickleError, EOFError, ValueError) as exc:
        log_event('ERROR', 'Error loading model', error=str(exc))
        return None


def parse_cloudtrail_log(bucket, key):
    """Download and parse a CloudTrail log file from S3."""
    log_event('INFO', 'Parsing CloudTrail log', source_bucket=bucket, source_key=key)

    try:
        response = s3_client().get_object(Bucket=bucket, Key=key)
        body = response['Body'].read()
        if not body:
            log_event('WARN', 'CloudTrail log object is empty', source_bucket=bucket, source_key=key)
            return []

        if key.endswith('.gz'):
            with gzip.GzipFile(fileobj=BytesIO(body)) as gzip_file:
                decompressed = gzip_file.read()
                if not decompressed:
                    log_event('WARN', 'Gzipped CloudTrail log has no content', source_key=key)
                    return []
                log_data = json.loads(decompressed.decode('utf-8'))
        else:
            log_data = json.loads(body.decode('utf-8'))

        if not isinstance(log_data, dict):
            log_event('WARN', 'CloudTrail payload is not a JSON object', source_key=key)
            return []

        events = log_data.get('Records', [])
        if not isinstance(events, list):
            log_event('WARN', 'CloudTrail payload Records key is not a list', source_key=key)
            return []
        log_event('INFO', 'Parsed CloudTrail events', source_key=key, event_count=len(events))
        return events
    except (json.JSONDecodeError, UnicodeDecodeError, OSError, ClientError, NoCredentialsError, PartialCredentialsError) as exc:
        log_event('ERROR', 'Error parsing CloudTrail log', source_key=key, error=str(exc))
        return []


def extract_features_for_event(event, model_package):
    """Extract features from a single CloudTrail event."""
    try:
        encoders = model_package['encoders']
        api_name = event.get('eventName', 'Unknown')
        service = event.get('eventSource', 'unknown.amazonaws.com').replace('.amazonaws.com', '')
        source_ip = event.get('sourceIPAddress', 'unknown')
        user_identity = event.get('userIdentity', {})
        user_name = user_identity.get('userName', user_identity.get('type', 'unknown'))

        event_time = event.get('eventTime', '')
        try:
            hour = datetime.fromisoformat(event_time.replace('Z', '+00:00')).hour
        except Exception:
            hour = 12

        is_root = 1 if user_identity.get('type') == 'Root' else 0
        is_error = 1 if event.get('errorCode') else 0

        def safe_encode(encoder, value, default=0):
            try:
                return encoder.transform([value])[0]
            except ValueError:
                return default

        return [
            safe_encode(encoders['api'], api_name),
            safe_encode(encoders['service'], service),
            safe_encode(encoders['ip'], source_ip),
            safe_encode(encoders['user'], user_name),
            hour,
            is_root,
            is_error,
        ]
    except (KeyError, TypeError, ValueError) as exc:
        log_event('ERROR', 'Feature extraction error', error=str(exc))
        return None


def analyze_event(event, model_package):
    """Analyze a single CloudTrail event for anomalies."""
    result = {
        'eventId': event.get('eventID', 'unknown'),
        'eventTime': event.get('eventTime', ''),
        'eventName': event.get('eventName', ''),
        'eventSource': event.get('eventSource', ''),
        'sourceIPAddress': event.get('sourceIPAddress', ''),
        'userIdentity': event.get('userIdentity', {}),
        'is_anomaly': False,
        'anomaly_score': 0.0,
        'anomaly_reasons': []
    }

    api_name = event.get('eventName', '')
    if api_name in SUSPICIOUS_APIS:
        result['anomaly_reasons'].append(f"Suspicious API call: {api_name}")
        result['is_anomaly'] = True

    user_identity = event.get('userIdentity', {})
    if user_identity.get('type') == 'Root':
        result['anomaly_reasons'].append('Root account used')
        result['is_anomaly'] = True

    if event.get('errorCode') in ['AccessDenied', 'UnauthorizedAccess', 'InvalidClientTokenId']:
        result['anomaly_reasons'].append(f"Access error: {event.get('errorCode')}")
        result['is_anomaly'] = True

    if model_package:
        features = extract_features_for_event(event, model_package)
        if features:
            try:
                model = model_package['model']
                prediction = model.predict([features])[0]
                score = model.decision_function([features])[0]
                result['anomaly_score'] = float(score)
                if prediction == -1:
                    result['is_anomaly'] = True
                    result['anomaly_reasons'].append(f"ML model detected anomaly (score: {score:.4f})")
            except Exception as exc:
                log_event('ERROR', 'ML prediction error', error=str(exc), event_id=result['eventId'])

    return result


def save_anomalies(anomalies, source_bucket, source_key, events_analyzed, output_bucket):
    """Save detected anomalies for one source object to S3."""
    if not anomalies:
        log_event('INFO', 'No anomalies to save', source_key=source_key)
        return

    timestamp = datetime.utcnow().strftime('%Y/%m/%d/%H')
    filename = os.path.basename(source_key).replace('.json.gz', '_anomalies.json')
    output_key = f"anomalies/{timestamp}/{filename}"

    output = {
        'source_bucket': source_bucket,
        'source_log': source_key,
        'analyzed_at': datetime.utcnow().isoformat(),
        'events_analyzed': events_analyzed,
        'total_anomalies': len(anomalies),
        'anomalies': anomalies,
    }

    try:
        s3_client().put_object(
            Bucket=output_bucket,
            Key=output_key,
            Body=json.dumps(output, indent=2, default=str),
            ContentType='application/json',
        )
        log_event('INFO', 'Anomalies saved', output_bucket=output_bucket, output_key=output_key)
    except (ClientError, NoCredentialsError, PartialCredentialsError, OSError, TypeError, ValueError) as exc:
        log_event('ERROR', 'Error saving anomalies', output_key=output_key, error=str(exc))


def lambda_handler(event, context):
    """Lambda handler triggered by S3 events."""
    request_id = getattr(context, 'aws_request_id', 'unknown')
    log_event('INFO', 'CloudTrail Anomaly Detection Lambda started', request_id=request_id)

    if not isinstance(event, dict):
        log_event('ERROR', 'Invalid event payload type', request_id=request_id, event_type=str(type(event)))
        return {
            'statusCode': 400,
            'body': {
                'message': 'event payload must be a JSON object',
                'request_id': request_id,
            }
        }

    try:
        return _handle_event(event, context, request_id)
    except Exception as exc:
        log_event('ERROR', 'Unhandled lambda processing error', request_id=request_id, error=str(exc))
        return {
            'statusCode': 500,
            'body': {
                'message': 'internal processing error',
                'request_id': request_id,
            }
        }


def _handle_event(event, context, request_id):

    runtime_payload = event.get('runtime_config')
    if not runtime_payload:
        records = event.get('Records', [])
        source_bucket = 'fallback-cloudtrail-bucket'
        if records:
            source_bucket = records[0].get('s3', {}).get('bucket', {}).get('name', '')
        if not source_bucket:
            source_bucket = 'fallback-cloudtrail-bucket'

        account_id = '000000000000'
        try:
            account_id = boto3.client('sts').get_caller_identity().get('Account', account_id)
        except Exception as exc:
            log_event('WARN', 'Could not resolve account ID for fallback runtime config', error=str(exc))

        fallback_region = 'us-east-1'
        invoked_arn = getattr(context, 'invoked_function_arn', '')
        if invoked_arn and ':' in invoked_arn:
            arn_parts = invoked_arn.split(':')
            if len(arn_parts) > 3 and arn_parts[3]:
                fallback_region = arn_parts[3]

        runtime_payload = {
            'account_id': account_id,
            'role_arn': f'arn:aws:iam::{account_id}:role/fallback-runtime-role',
            'region': fallback_region,
            'cloudtrail_bucket': source_bucket,
            'output_bucket': source_bucket,
            'email': 'alerts@example.com',
            'rule_only_mode': True,
        }
        log_event('WARN', 'runtime_config missing, using fallback runtime values', request_id=request_id)

    try:
        runtime_cfg = load_runtime_config(
            account_id=runtime_payload.get('account_id'),
            role_arn=runtime_payload.get('role_arn'),
            region=runtime_payload.get('region'),
            cloudtrail_bucket=runtime_payload.get('cloudtrail_bucket'),
            output_bucket=runtime_payload.get('output_bucket'),
            email=runtime_payload.get('email'),
        )
    except ValueError as exc:
        log_event('ERROR', 'Invalid runtime_config payload', request_id=request_id, error=str(exc))
        return {
            'statusCode': 400,
            'body': {
                'message': str(exc),
                'request_id': request_id,
            }
        }

    rule_only_mode = bool(runtime_payload.get('rule_only_mode', False))
    model_key = runtime_payload.get('model_key', 'models/cloudtrail_anomaly_model.pkl')
    model_bucket = runtime_payload.get('model_bucket')
    if not model_bucket and not rule_only_mode:
        log_event('WARN', 'model_bucket missing; forcing rule-only mode', request_id=request_id)
        rule_only_mode = True

    model_package = load_model(model_bucket, model_key, rule_only_mode)
    if not model_package and not rule_only_mode:
        log_event('WARN', 'Model not loaded; using rule-based detection only', request_id=request_id)

    total_events = 0
    total_anomalies = 0

    records = event.get('Records', [])
    if not isinstance(records, list):
        log_event('WARN', 'Records field missing or invalid, nothing to process', request_id=request_id)
        records = []

    for record in records:
        if not isinstance(record, dict):
            log_event('WARN', 'Skipping non-dict record', request_id=request_id)
            continue

        s3_info = record.get('s3', {})
        bucket = s3_info.get('bucket', {}).get('name')
        raw_key = s3_info.get('object', {}).get('key')
        if not bucket or not raw_key:
            log_event('WARN', 'Skipping record with missing S3 bucket/key', request_id=request_id)
            continue

        key = urllib.parse.unquote_plus(raw_key)

        if 'CloudTrail' not in key:
            log_event('INFO', 'Skipping non-CloudTrail file', source_key=key, request_id=request_id)
            continue

        object_anomalies = []
        events = parse_cloudtrail_log(bucket, key)
        total_events += len(events)

        for ct_event in events:
            if not isinstance(ct_event, dict):
                log_event('WARN', 'Skipping malformed CloudTrail record', request_id=request_id, source_key=key)
                continue
            result = analyze_event(ct_event, model_package)
            if result['is_anomaly']:
                total_anomalies += 1
                object_anomalies.append(result)
                log_event(
                    'WARN',
                    'Anomaly detected',
                    request_id=request_id,
                    source_key=key,
                    event_id=result['eventId'],
                    event_name=result['eventName'],
                    reasons=result['anomaly_reasons'],
                    score=result['anomaly_score'],
                )

        save_anomalies(
            anomalies=object_anomalies,
            source_bucket=bucket,
            source_key=key,
            events_analyzed=len(events),
            output_bucket=runtime_cfg.output_bucket,
        )

    summary_body = {
        'total_events_analyzed': total_events,
        'total_anomalies_detected': total_anomalies,
        'model_used': model_package is not None,
        'rule_only_mode': rule_only_mode,
        'account_id': runtime_cfg.account_id,
    }
    log_event('INFO', 'CloudTrail analysis complete', request_id=request_id, **summary_body)
    return {'statusCode': 200, 'body': summary_body}
