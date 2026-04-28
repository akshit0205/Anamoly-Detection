import logging

import boto3
from botocore.exceptions import BotoCoreError, ClientError


logger = logging.getLogger(__name__)

REQUIRED_ANOMALY_KEYS = (
    'account_id',
    'event_name',
    'username',
    'reason',
    'timestamp',
)


def _validate_non_empty(value, field_name: str) -> None:
    if value is None or str(value).strip() == '':
        raise ValueError(field_name)


def _validate_anomaly(anomaly: dict) -> None:
    if not isinstance(anomaly, dict):
        raise ValueError('anomaly')

    missing = [key for key in REQUIRED_ANOMALY_KEYS if anomaly.get(key) in (None, '')]
    if missing:
        raise ValueError(missing[0])


def send_anomaly_alert(anomaly: dict, recipient_email: str, sender_email: str, region: str) -> bool:
    _validate_non_empty(recipient_email, 'recipient_email')
    _validate_non_empty(sender_email, 'sender_email')
    _validate_non_empty(region, 'region')
    _validate_anomaly(anomaly)

    event_name = anomaly.get('event_name', 'Unknown')

    subject = f'⚠️ CloudTrail Anomaly Detected: {event_name}'
    body_text = (
        'A CloudTrail anomaly was detected.\n\n'
        f"Account ID: {anomaly.get('account_id')}\n"
        f"Event: {anomaly.get('event_name')}\n"
        f"User: {anomaly.get('username')}\n"
        f"Reason: {anomaly.get('reason')}\n"
        f"Timestamp: {anomaly.get('timestamp')}\n"
    )

    try:
        ses_client = boto3.client('ses', region_name=region)
        response = ses_client.send_email(
            Source=sender_email,
            Destination={
                'ToAddresses': [recipient_email],
            },
            Message={
                'Subject': {'Data': subject},
                'Body': {'Text': {'Data': body_text}},
            },
        )
        message_id = response.get('MessageId', 'unknown')
        logger.info('SES anomaly alert sent to %s message_id=%s', recipient_email, message_id)
        return True
    except ClientError as exc:
        logger.error('SES ClientError while sending anomaly alert to %s: %s', recipient_email, exc)
        return False
    except BotoCoreError as exc:
        logger.error('SES BotoCoreError while sending anomaly alert to %s: %s', recipient_email, exc)
        return False
