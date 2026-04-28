import logging
import os
import re

import boto3

from alerts.alert_dispatcher import dispatch_alerts
from detection.pipeline import run_detection
from storage.dynamodb_store import get_user as storage_get_user


logger = logging.getLogger(__name__)
ACCOUNT_ID_PATTERN = re.compile(r'^AWSLogs/(\d{12})/CloudTrail/')


def _storage_region() -> str:
    region = boto3.session.Session().region_name
    if not region:
        raise RuntimeError('DynamoDB region is not configured in the runtime environment')
    return region


def get_user(account_id: str):
    return storage_get_user(account_id, _storage_region())


def _extract_bucket_and_key(event: dict) -> tuple[str, str]:
    records = event.get('Records', [])
    if not records:
        raise ValueError('S3 event has no Records')

    first_record = records[0]
    bucket = first_record['s3']['bucket']['name']
    key = first_record['s3']['object']['key']
    return bucket, key


def _extract_account_id_from_key(key: str) -> str:
    match = ACCOUNT_ID_PATTERN.match(key)
    if not match:
        raise ValueError(f'Could not derive account_id from key: {key}')
    return match.group(1)


def handler(event, context) -> dict:
    try:
        bucket, key = _extract_bucket_and_key(event)
        logger.info('Received S3 event bucket=%s key=%s', bucket, key)

        if '/CloudTrail-Digest/' in key:
            logger.info(f"Skipping digest file: {key}")
            return {"status": "skipped", "reason": "digest file"}

        account_id = _extract_account_id_from_key(key)
        user = get_user(account_id)

        if not user:
            logger.warning('No user config found for account_id=%s', account_id)
            return {'status': 'skipped'}

        sender_email = os.environ.get('SENDER_EMAIL')
        if not sender_email:
            raise RuntimeError('SENDER_EMAIL environment variable is not set')

        anomalies = run_detection(user, bucket=bucket, key=key)
        dispatch_alerts(anomalies, user, sender_email)

        return {'status': 'ok', 'anomalies_found': len(anomalies)}
    except Exception as exc:
        logger.exception('Lambda handler failed: %s', exc)
        return {'status': 'error', 'message': str(exc)}
