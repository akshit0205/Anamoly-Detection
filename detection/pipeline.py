import gzip
import json
import logging
from io import BytesIO
from datetime import datetime, timezone

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


def _get_severity(event_name: str, is_root: bool, error_code: str) -> str:
    if is_root:
        return 'critical'
    if event_name in [
        'DeleteTrail', 'StopLogging', 'UpdateTrail',
        'DeleteUser', 'DeleteRole', 'DeletePolicy',
        'AuthorizeSecurityGroupIngress', 'DeleteBucket'
    ]:
        return 'high'
    if event_name in [
        'CreateUser', 'CreateRole', 'AttachRolePolicy',
        'DetachRolePolicy', 'PutRolePolicy', 'AddUserToGroup',
        'RemoveUserFromGroup', 'AssumeRole', 'ConsoleLogin'
    ]:
        return 'medium'
    if error_code == 'AccessDenied':
        return 'low'
    return 'low'


def _is_sensitive_api(event_name: str) -> bool:
    sensitive = [
        # IAM — identity threats
        'DeleteGroup', 'DeleteUser', 'DeleteRole', 'DeletePolicy',
        'CreateUser', 'CreateRole', 'CreateGroup',
        'AttachRolePolicy', 'DetachRolePolicy', 'PutRolePolicy',
        'AttachUserPolicy', 'DetachUserPolicy', 'PutUserPolicy',
        'AttachGroupPolicy', 'DetachGroupPolicy', 'PutGroupPolicy',
        'AddUserToGroup', 'RemoveUserFromGroup',
        'CreateAccessKey', 'DeleteAccessKey', 'UpdateAccessKey',
        'CreateLoginProfile', 'DeleteLoginProfile', 'UpdateLoginProfile',
        'CreateVirtualMFADevice', 'DeactivateMFADevice', 'DeleteVirtualMFADevice',
        # EC2 — compute threats
        'StopInstances', 'TerminateInstances', 'RunInstances',
        'AuthorizeSecurityGroupIngress', 'AuthorizeSecurityGroupEgress',
        'RevokeSecurityGroupIngress', 'DeleteSecurityGroup',
        'CreateKeyPair', 'DeleteKeyPair', 'ImportKeyPair',
        # S3 — data threats
        'DeleteBucket', 'DeleteBucketPolicy', 'PutBucketPolicy',
        'PutBucketAcl', 'DeleteBucketEncryption',
        # CloudTrail — covering tracks
        'DeleteTrail', 'StopLogging', 'UpdateTrail',
        'PutEventSelectors', 'DeleteEventDataStore',
        # Auth events
        'ConsoleLogin', 'AssumeRole',
        # Network
        'CreateVpc', 'DeleteVpc', 'CreateSubnet',
        'AttachInternetGateway', 'CreateRoute',
        # KMS
        'DisableKey', 'ScheduleKeyDeletion', 'DeleteAlias',
    ]
    return event_name in sensitive


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

    mode = 'single_object' if (bucket is not None and key is not None) else 'full_scan'
    logger.info('RUN_DETECTION_START', extra={'account_id': account_id, 'bucket': bucket or default_bucket, 'mode': mode})
    logger.info('MODE_SELECTED', extra={'mode': mode, 'account_id': account_id})

    try:
        s3_client = get_client_for_role('s3', role_arn, region)
    except RuntimeError as exc:
        logger.error('STS_FAILURE', extra={'account_id': account_id, 'role_arn': role_arn, 'region': region})
        logger.error('Failed to create assumed-role S3 client for account_id=%s: %s', account_id, exc)
        raise RuntimeError(f'Failed to create assumed-role S3 client for account_id={account_id}') from exc

    anomalies = []
    seen_events = set()

    try:
        if bucket is not None and key is not None:
            try:
                logger.info('S3_OBJECT_READ', extra={'bucket': bucket, 'key': key})
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
                if records is None:
                    logger.warning('PARSE_FAILED', extra={'bucket': bucket, 'key': key})
                else:
                    logger.info('PARSE_COUNT', extra={'bucket': bucket, 'key': key, 'record_count': len(records)})
                    for record in records:
                        if not isinstance(record, dict):
                            continue

                        event_name = record.get('eventName', '')
                        logger.debug('EVENT_SEEN', extra={'account_id': account_id, 'event_name': event_name})
                        username = _extract_username(record)
                        timestamp = record.get('eventTime', '')
                        identity = record.get('userIdentity', {})
                        is_root = isinstance(identity, dict) and identity.get('type') == 'Root'
                        error_code = record.get('errorCode')

                        reasons = []
                        if is_root:
                            reasons.append('Root account usage detected')
                            logger.info('ANOMALY_DETECTED', extra={'account_id': account_id, 'event_name': event_name, 'rule': 'Root'})
                        if _is_sensitive_api(event_name):
                            reasons.append(f'Sensitive API call detected: {event_name}')
                            logger.info('ANOMALY_DETECTED', extra={'account_id': account_id, 'event_name': event_name, 'rule': 'SensitiveAPI'})
                        if error_code == 'AccessDenied':
                            reasons.append('AccessDenied error detected')
                            logger.info('ANOMALY_DETECTED', extra={'account_id': account_id, 'event_name': event_name, 'rule': 'AccessDenied'})

                        for reason in reasons:
                            dedup_key = f"{event_name}:{username}:{error_code}"
                            if dedup_key not in seen_events:
                                seen_events.add(dedup_key)
                                anomalies.append(
                                    {
                                        'account_id': account_id,
                                        'event_name': event_name or 'Unknown',
                                        'username': username,
                                        'reason': reason,
                                        'timestamp': timestamp,
                                        'severity': _get_severity(event_name, is_root, error_code),
                                    }
                                )
            else:
                logger.warning('Skipping empty CloudTrail object s3://%s/%s', bucket, key)
        else:
            paginator = s3_client.get_paginator('list_objects_v2')
            logger.info('S3_LIST_START', extra={'bucket': default_bucket})
            today = datetime.now(timezone.utc)
            prefix = (
                f"AWSLogs/{account_id}/CloudTrail/{region}/"
                f"{today.year}/{today.month:02d}/{today.day:02d}/"
            )
            page_iter = paginator.paginate(
                Bucket=default_bucket,
                Prefix=prefix,
                PaginationConfig={"MaxItems": 20}
            )
            total_objects = 0
            files_processed = 0
            MAX_FILES = 50

            for page in page_iter:
                objs = page.get('Contents', [])
                logger.info('S3_PAGE', extra={'bucket': default_bucket, 'objects_in_page': len(objs)})
                total_objects += len(objs)
                for obj in objs:
                    if files_processed >= MAX_FILES:
                        break

                    key = obj.get('Key')
                    if not key:
                        continue

                    try:
                        logger.info('S3_OBJECT_READ', extra={'bucket': default_bucket, 'key': key})
                        response = s3_client.get_object(Bucket=default_bucket, Key=key)
                        body = response['Body'].read()
                    except ClientError as exc:
                        logger.error('ClientError fetching s3://%s/%s: %s', default_bucket, key, exc)
                        raise RuntimeError(f'Failed to fetch s3://{default_bucket}/{key}') from exc
                    except BotoCoreError as exc:
                        logger.error('BotoCoreError fetching s3://%s/%s: %s', default_bucket, key, exc)
                        raise RuntimeError(f'Failed to fetch s3://{default_bucket}/{key}') from exc

                    if not body:
                        logger.warning('Skipping empty CloudTrail object s3://%s/%s', default_bucket, key)
                        continue

                    records = _parse_log_body(key, body)
                    if records is None:
                        logger.warning('PARSE_FAILED', extra={'bucket': default_bucket, 'key': key})
                        continue
                    if isinstance(records, list) and len(records) == 0:
                        logger.info('NO_RECORDS', extra={'bucket': default_bucket, 'key': key})
                        continue
                    logger.info('PARSE_COUNT', extra={'bucket': default_bucket, 'key': key, 'record_count': len(records)})

                    for record in records:
                        if not isinstance(record, dict):
                            continue

                        event_name = record.get('eventName', '')
                        logger.debug('EVENT_SEEN', extra={'account_id': account_id, 'event_name': event_name})
                        username = _extract_username(record)
                        timestamp = record.get('eventTime', '')
                        identity = record.get('userIdentity', {})
                        is_root = isinstance(identity, dict) and identity.get('type') == 'Root'
                        error_code = record.get('errorCode')

                        reasons = []
                        if is_root:
                            reasons.append('Root account usage detected')
                            logger.info('ANOMALY_DETECTED', extra={'account_id': account_id, 'event_name': event_name, 'rule': 'Root'})
                        if _is_sensitive_api(event_name):
                            reasons.append(f'Sensitive API call detected: {event_name}')
                            logger.info('ANOMALY_DETECTED', extra={'account_id': account_id, 'event_name': event_name, 'rule': 'SensitiveAPI'})
                        if error_code == 'AccessDenied':
                            reasons.append('AccessDenied error detected')
                            logger.info('ANOMALY_DETECTED', extra={'account_id': account_id, 'event_name': event_name, 'rule': 'AccessDenied'})

                        for reason in reasons:
                            dedup_key = f"{event_name}:{username}:{error_code}"
                            if dedup_key not in seen_events:
                                seen_events.add(dedup_key)
                                anomalies.append(
                                    {
                                        'account_id': account_id,
                                        'event_name': event_name or 'Unknown',
                                        'username': username,
                                        'reason': reason,
                                        'timestamp': timestamp,
                                        'severity': _get_severity(event_name, is_root, error_code),
                                    }
                                )
                    files_processed += 1
            logger.info('S3_LIST_COMPLETE', extra={'bucket': default_bucket, 'total_objects': total_objects})

    except ClientError as exc:
        logger.error('TOP_LEVEL_EXCEPTION', extra={'error': str(exc)})
        logger.error('ClientError listing CloudTrail logs for bucket=%s account_id=%s: %s', default_bucket, account_id, exc)
        raise RuntimeError(f'Failed to list CloudTrail logs for bucket={default_bucket}') from exc
    except BotoCoreError as exc:
        logger.error('TOP_LEVEL_EXCEPTION', extra={'error': str(exc)})
        logger.error('BotoCoreError listing CloudTrail logs for bucket=%s account_id=%s: %s', default_bucket, account_id, exc)
        raise RuntimeError(f'Failed to list CloudTrail logs for bucket={default_bucket}') from exc

    logger.info('Detection complete account_id=%s anomalies=%d', account_id, len(anomalies))
    return anomalies
