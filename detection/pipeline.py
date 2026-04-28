import gzip
import json
import logging
from io import BytesIO

from botocore.exceptions import BotoCoreError, ClientError

from auth.sts_helper import get_client_for_role


logger = logging.getLogger(__name__)

REQUIRED_USER_FIELDS = (
    'account_id',
    'role_arn',
    'region',
    'cloudtrail_bucket',
    'output_bucket',
    'email',
)


def _is_sensitive_api(event_name: str) -> bool:
    if not event_name:
        return False
    return event_name.startswith('Delete') or event_name.startswith('Stop') or event_name.startswith('Terminate')


def _extract_username(record: dict) -> str:
    identity = record.get('userIdentity', {})
    if not isinstance(identity, dict):
        return 'unknown'

    username = identity.get('userName') or identity.get('arn') or identity.get('type')
    return username or 'unknown'


def _parse_log_body(key: str, body: bytes):
    try:
        if key.endswith('.gz'):
            with gzip.GzipFile(fileobj=BytesIO(body)) as gz:
                decoded = gz.read().decode('utf-8')
        else:
            decoded = body.decode('utf-8')

        payload = json.loads(decoded)
        records = payload.get('Records', []) if isinstance(payload, dict) else []
        if not isinstance(records, list):
            return []
        return records
    except (json.JSONDecodeError, UnicodeDecodeError, OSError) as exc:
        logger.error('Failed to parse CloudTrail log key=%s: %s', key, exc)
        return None


def _validate_user(user: dict) -> bool:
    if not isinstance(user, dict):
        logger.error('Invalid user payload type: %s', type(user))
        return False

    missing = [field for field in REQUIRED_USER_FIELDS if user.get(field) in (None, '')]
    if missing:
        logger.error('Missing required user fields: %s', ', '.join(missing))
        return False

    return True


def run_detection(user: dict, bucket=None, key=None) -> list[dict]:
    if not _validate_user(user):
        return []

    account_id = user['account_id']
    role_arn = user['role_arn']
    region = user['region']
    default_bucket = user['cloudtrail_bucket']

    try:
        s3_client = get_client_for_role('s3', role_arn, region)
    except RuntimeError as exc:
        logger.error('Failed to create assumed-role S3 client for account_id=%s: %s', account_id, exc)
        return []

    anomalies = []

    try:
        if bucket is not None and key is not None:
            try:
                response = s3_client.get_object(Bucket=bucket, Key=key)
                body = response['Body'].read()
            except ClientError as exc:
                logger.error('ClientError fetching s3://%s/%s: %s', bucket, key, exc)
                raise RuntimeError(f'Failed to fetch s3://{bucket}/{key}') from exc
            except BotoCoreError as exc:
                logger.error('BotoCoreError fetching s3://%s/%s: %s', bucket, key, exc)
                raise RuntimeError(f'Failed to fetch s3://{bucket}/{key}') from exc

            if body:
                records = _parse_log_body(key, body)
                if records is not None:
                    for record in records:
                        if not isinstance(record, dict):
                            continue

                        event_name = record.get('eventName', '')
                        username = _extract_username(record)
                        timestamp = record.get('eventTime', '')
                        identity = record.get('userIdentity', {})
                        is_root = isinstance(identity, dict) and identity.get('type') == 'Root'
                        error_code = record.get('errorCode')

                        reasons = []
                        if is_root:
                            reasons.append('Root account usage detected')
                        if _is_sensitive_api(event_name):
                            reasons.append(f'Sensitive API call detected: {event_name}')
                        if error_code == 'AccessDenied':
                            reasons.append('AccessDenied error detected')

                        for reason in reasons:
                            anomalies.append(
                                {
                                    'account_id': account_id,
                                    'event_name': event_name or 'Unknown',
                                    'username': username,
                                    'reason': reason,
                                    'timestamp': timestamp,
                                }
                            )
            else:
                logger.warning('Skipping empty CloudTrail object s3://%s/%s', bucket, key)
        else:
            paginator = s3_client.get_paginator('list_objects_v2')
            page_iter = paginator.paginate(Bucket=default_bucket)

            for page in page_iter:
                for obj in page.get('Contents', []):
                    key = obj.get('Key')
                    if not key:
                        continue

                    try:
                        response = s3_client.get_object(Bucket=default_bucket, Key=key)
                        body = response['Body'].read()
                    except ClientError as exc:
                        logger.error('ClientError fetching s3://%s/%s: %s', default_bucket, key, exc)
                        continue
                    except BotoCoreError as exc:
                        logger.error('BotoCoreError fetching s3://%s/%s: %s', default_bucket, key, exc)
                        continue

                    if not body:
                        logger.warning('Skipping empty CloudTrail object s3://%s/%s', default_bucket, key)
                        continue

                    records = _parse_log_body(key, body)
                    if records is None:
                        continue

                    for record in records:
                        if not isinstance(record, dict):
                            continue

                        event_name = record.get('eventName', '')
                        username = _extract_username(record)
                        timestamp = record.get('eventTime', '')
                        identity = record.get('userIdentity', {})
                        is_root = isinstance(identity, dict) and identity.get('type') == 'Root'
                        error_code = record.get('errorCode')

                        reasons = []
                        if is_root:
                            reasons.append('Root account usage detected')
                        if _is_sensitive_api(event_name):
                            reasons.append(f'Sensitive API call detected: {event_name}')
                        if error_code == 'AccessDenied':
                            reasons.append('AccessDenied error detected')

                        for reason in reasons:
                            anomalies.append(
                                {
                                    'account_id': account_id,
                                    'event_name': event_name or 'Unknown',
                                    'username': username,
                                    'reason': reason,
                                    'timestamp': timestamp,
                                }
                            )

    except ClientError as exc:
        logger.error('ClientError listing CloudTrail logs for bucket=%s account_id=%s: %s', default_bucket, account_id, exc)
        raise RuntimeError(f'Failed to list CloudTrail logs for bucket={default_bucket}') from exc
    except BotoCoreError as exc:
        logger.error('BotoCoreError listing CloudTrail logs for bucket=%s account_id=%s: %s', default_bucket, account_id, exc)
        raise RuntimeError(f'Failed to list CloudTrail logs for bucket={default_bucket}') from exc

    logger.info('Detection complete account_id=%s anomalies=%d', account_id, len(anomalies))
    return anomalies
