import json
import boto3
import pickle
import gzip
import os
from datetime import datetime
from io import BytesIO
import urllib.parse


# Global cache for model (persists across warm Lambda invocations)
MODEL_CACHE = None

# Configuration
MODEL_BUCKET = os.environ.get('MODEL_BUCKET', 'akshit-ml-models-4679')
MODEL_KEY = os.environ.get('MODEL_KEY', 'models/cloudtrail_anomaly_model.pkl')
OUTPUT_BUCKET = os.environ.get('OUTPUT_BUCKET', 'akshit-cloudtrail-logs-4679')

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


def load_model():
    """Load the trained model from S3 (with caching)."""
    global MODEL_CACHE
    
    if MODEL_CACHE is not None:
        print("Using cached model")
        return MODEL_CACHE
    
    print(f"Loading model from s3://{MODEL_BUCKET}/{MODEL_KEY}")
    
    s3 = boto3.client('s3')
    
    try:
        response = s3.get_object(Bucket=MODEL_BUCKET, Key=MODEL_KEY)
        model_data = response['Body'].read()
        MODEL_CACHE = pickle.loads(model_data)
        print("Model loaded successfully")
        return MODEL_CACHE
    except Exception as e:
        print(f"Error loading model: {e}")
        return None


def parse_cloudtrail_log(bucket, key):
    """
    Download and parse a CloudTrail log file from S3.
    
    Args:
        bucket: S3 bucket name
        key: S3 object key
    
    Returns:
        list of CloudTrail events
    """
    print(f"Parsing CloudTrail log: s3://{bucket}/{key}")
    
    s3 = boto3.client('s3')
    
    try:
        response = s3.get_object(Bucket=bucket, Key=key)
        
        # CloudTrail logs are gzipped
        if key.endswith('.gz'):
            with gzip.GzipFile(fileobj=BytesIO(response['Body'].read())) as f:
                log_data = json.loads(f.read().decode('utf-8'))
        else:
            log_data = json.loads(response['Body'].read().decode('utf-8'))
        
        events = log_data.get('Records', [])
        print(f"Parsed {len(events)} events from log")
        return events
        
    except Exception as e:
        print(f"Error parsing log: {e}")
        return []


def extract_features_for_event(event, model_package):
    """
    Extract features from a single CloudTrail event.
    
    Args:
        event: CloudTrail event dictionary
        model_package: Model package with encoders
    
    Returns:
        feature vector or None if extraction fails
    """
    try:
        encoders = model_package['encoders']
        
        # Extract basic fields
        api_name = event.get('eventName', 'Unknown')
        service = event.get('eventSource', 'unknown.amazonaws.com').replace('.amazonaws.com', '')
        source_ip = event.get('sourceIPAddress', 'unknown')
        user_identity = event.get('userIdentity', {})
        user_name = user_identity.get('userName', user_identity.get('type', 'unknown'))
        
        # Parse time
        event_time = event.get('eventTime', '')
        try:
            hour = datetime.fromisoformat(event_time.replace('Z', '+00:00')).hour
        except:
            hour = 12  # Default to noon
        
        # Determine if root
        is_root = 1 if user_identity.get('type') == 'Root' else 0
        
        # Determine if error
        is_error = 1 if event.get('errorCode') else 0
        
        # Encode features (handle unknown values)
        def safe_encode(encoder, value, default=0):
            try:
                return encoder.transform([value])[0]
            except ValueError:
                return default  # Unknown value
        
        feature_vector = [
            safe_encode(encoders['api'], api_name),
            safe_encode(encoders['service'], service),
            safe_encode(encoders['ip'], source_ip),
            safe_encode(encoders['user'], user_name),
            hour,
            is_root,
            is_error
        ]
        
        return feature_vector
        
    except Exception as e:
        print(f"Feature extraction error: {e}")
        return None


def analyze_event(event, model_package):
    """
    Analyze a single CloudTrail event for anomalies.
    
    Args:
        event: CloudTrail event dictionary
        model_package: Model package with model and encoders
    
    Returns:
        dict with analysis results
    """
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
    
    # Rule-based checks first
    api_name = event.get('eventName', '')
    
    # Check for suspicious APIs
    if api_name in SUSPICIOUS_APIS:
        result['anomaly_reasons'].append(f"Suspicious API call: {api_name}")
        result['is_anomaly'] = True
    
    # Check for root account usage
    user_identity = event.get('userIdentity', {})
    if user_identity.get('type') == 'Root':
        result['anomaly_reasons'].append("Root account used")
        result['is_anomaly'] = True
    
    # Check for errors (potential unauthorized access attempts)
    if event.get('errorCode') in ['AccessDenied', 'UnauthorizedAccess', 'InvalidClientTokenId']:
        result['anomaly_reasons'].append(f"Access error: {event.get('errorCode')}")
        result['is_anomaly'] = True
    
    # ML-based detection
    if model_package:
        features = extract_features_for_event(event, model_package)
        if features:
            try:
                model = model_package['model']
                # -1 = anomaly, 1 = normal
                prediction = model.predict([features])[0]
                score = model.decision_function([features])[0]
                
                result['anomaly_score'] = float(score)
                
                if prediction == -1:
                    result['is_anomaly'] = True
                    result['anomaly_reasons'].append(f"ML model detected anomaly (score: {score:.4f})")
            except Exception as e:
                print(f"ML prediction error: {e}")
    
    return result


def save_anomalies(anomalies, source_key):
    """
    Save detected anomalies to S3.
    
    Args:
        anomalies: list of anomaly results
        source_key: original CloudTrail log key
    """
    if not anomalies:
        print("No anomalies to save")
        return
    
    s3 = boto3.client('s3')
    
    # Create output key
    timestamp = datetime.utcnow().strftime('%Y/%m/%d/%H')
    filename = os.path.basename(source_key).replace('.json.gz', '_anomalies.json')
    output_key = f"anomalies/{timestamp}/{filename}"
    
    output = {
        'source_log': source_key,
        'analyzed_at': datetime.utcnow().isoformat(),
        'total_anomalies': len(anomalies),
        'anomalies': anomalies
    }
    
    try:
        s3.put_object(
            Bucket=OUTPUT_BUCKET,
            Key=output_key,
            Body=json.dumps(output, indent=2, default=str),
            ContentType='application/json'
        )
        print(f"Anomalies saved to s3://{OUTPUT_BUCKET}/{output_key}")
    except Exception as e:
        print(f"Error saving anomalies: {e}")


def lambda_handler(event, context):
    """
    Lambda handler triggered by S3 events.
    
    Args:
        event: S3 event notification
        context: Lambda context
    
    Returns:
        dict with processing results
    """
    print("=" * 50)
    print("CloudTrail Anomaly Detection Lambda")
    print("=" * 50)
    print(f"Event: {json.dumps(event, indent=2)}")
    
    # Load model
    model_package = load_model()
    
    if not model_package:
        print("WARNING: Model not loaded, using rule-based detection only")
    
    total_events = 0
    total_anomalies = 0
    all_anomalies = []
    
    # Process each S3 record
    for record in event.get('Records', []):
        # Get bucket and key from S3 event
        bucket = record['s3']['bucket']['name']
        key = urllib.parse.unquote_plus(record['s3']['object']['key'])
        
        # Skip non-CloudTrail files
        if 'CloudTrail' not in key:
            print(f"Skipping non-CloudTrail file: {key}")
            continue
        
        # Parse the log file
        events = parse_cloudtrail_log(bucket, key)
        total_events += len(events)
        
        # Analyze each event
        for ct_event in events:
            result = analyze_event(ct_event, model_package)
            
            if result['is_anomaly']:
                total_anomalies += 1
                all_anomalies.append(result)
                print(f"ANOMALY: {result['eventName']} - {result['anomaly_reasons']}")
        
        # Save anomalies for this log file
        save_anomalies(all_anomalies, key)
    
    summary = {
        'statusCode': 200,
        'body': {
            'total_events_analyzed': total_events,
            'total_anomalies_detected': total_anomalies,
            'model_used': model_package is not None
        }
    }
    
    print("\n" + "=" * 50)
    print(f"Analysis Complete: {total_events} events, {total_anomalies} anomalies")
    print("=" * 50)
    
    return summary
