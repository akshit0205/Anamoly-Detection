import json
import logging

from botocore.exceptions import BotoCoreError, ClientError

from auth.sts_helper import get_client_for_role
from alerts.ses_alerter import send_anomaly_alert


logger = logging.getLogger(__name__)

REQUIRED_USER_KEYS = (
    'account_id',
    'role_arn',
    'region',
    'output_bucket',
    'email',
)


def _sanitize_key_part(value: str) -> str:
    return str(value).replace(' ', '_').replace(':', '_')


def dispatch_alerts(anomalies: list[dict], user: dict, sender_email: str) -> None:
    for key in REQUIRED_USER_KEYS:
        if user.get(key) is None or str(user.get(key)).strip() == '':
            raise ValueError(key)

    if anomalies is None:
        anomalies = []

    if len(anomalies) == 0:
        logger.info('No anomalies to dispatch')
        return

    account_id = user['account_id']
    role_arn = user['role_arn']
    region = user['region']
    output_bucket = user['output_bucket']
    recipient_email = user['email']

    for anomaly in anomalies:
        if not isinstance(anomaly, dict):
            logger.error('Skipping anomaly with invalid type: %s', type(anomaly))
            continue

        timestamp = _sanitize_key_part(anomaly.get('timestamp', 'unknown_timestamp'))
        event_name = _sanitize_key_part(anomaly.get('event_name', 'unknown_event'))
        key = f"anomalies/{account_id}/{timestamp}_{event_name}.json"

        try:
            s3_client = get_client_for_role('s3', role_arn, region)
            s3_client.put_object(
                Bucket=output_bucket,
                Key=key,
                Body=json.dumps(anomaly).encode('utf-8'),
                ContentType='application/json',
            )
            logger.info('Saved anomaly to s3://%s/%s', output_bucket, key)
        except RuntimeError as exc:
            logger.error('Failed to get assumed-role S3 client for account_id=%s: %s', account_id, exc)
            continue
        except ClientError as exc:
            logger.error('ClientError saving anomaly to s3://%s/%s: %s', output_bucket, key, exc)
            continue
        except BotoCoreError as exc:
            logger.error('BotoCoreError saving anomaly to s3://%s/%s: %s', output_bucket, key, exc)
            continue

        email_sent = send_anomaly_alert(anomaly, recipient_email, sender_email, region)
        if not email_sent:
            logger.error('Failed to send anomaly email account_id=%s event_name=%s', account_id, anomaly.get('event_name', 'unknown_event'))
