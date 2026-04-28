import logging

import boto3
from botocore.exceptions import BotoCoreError, ClientError


logger = logging.getLogger(__name__)


def assume_role(role_arn, session_name='CloudTrailAnomalySession', region=None) -> dict:
    if role_arn is None or str(role_arn).strip() == '':
        raise ValueError('role_arn')
    if region is None or str(region).strip() == '':
        raise ValueError('region')
    if session_name is None or str(session_name).strip() == '':
        session_name = 'CloudTrailAnomalySession'

    try:
        logger.info('ASSUME_ROLE_START', extra={'role_arn': role_arn, 'region': region})
        sts_client = boto3.client('sts', region_name=region)
        response = sts_client.assume_role(RoleArn=role_arn, RoleSessionName=session_name)
        creds = response.get('Credentials', {})

        mapped = {
            'aws_access_key_id': creds.get('AccessKeyId'),
            'aws_secret_access_key': creds.get('SecretAccessKey'),
            'aws_session_token': creds.get('SessionToken'),
        }

        if not all(mapped.values()):
            logger.error('ASSUME_ROLE_FAILED', extra={'role_arn': role_arn, 'reason': 'incomplete_credentials'})
            raise RuntimeError('Failed to assume role: STS returned incomplete credentials')

        logger.info('ASSUME_ROLE_SUCCESS', extra={'role_arn': role_arn})
        return mapped
    except ClientError as exc:
        logger.error('ASSUME_ROLE_FAILED', extra={'role_arn': role_arn, 'error': str(exc)})
        raise RuntimeError(f'Failed to assume role due to AWS client error: {exc}') from exc
    except BotoCoreError as exc:
        logger.error('ASSUME_ROLE_FAILED', extra={'role_arn': role_arn, 'error': str(exc)})
        raise RuntimeError(f'Failed to assume role due to boto core error: {exc}') from exc


def get_client_for_role(service, role_arn, region):
    if service is None or str(service).strip() == '':
        raise ValueError('service')
    if role_arn is None or str(role_arn).strip() == '':
        raise ValueError('role_arn')
    if region is None or str(region).strip() == '':
        raise ValueError('region')

    try:
        logger.info('GET_CLIENT_FOR_ROLE_START', extra={'service': service, 'role_arn': role_arn, 'region': region})
        creds = assume_role(role_arn=role_arn, session_name='CloudTrailAnomalySession', region=region)
    except RuntimeError:
        raise

    logger.info('GET_CLIENT_FOR_ROLE_SUCCESS', extra={'service': service, 'role_arn': role_arn, 'region': region})
    return boto3.client(
        service,
        region_name=region,
        aws_access_key_id=creds['aws_access_key_id'],
        aws_secret_access_key=creds['aws_secret_access_key'],
        aws_session_token=creds['aws_session_token'],
    )
