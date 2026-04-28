import logging
from typing import Optional

import boto3
from botocore.exceptions import BotoCoreError, ClientError


logger = logging.getLogger(__name__)

USERS_TABLE_NAME = 'users'
REQUIRED_FIELDS = (
    'account_id',
    'role_arn',
    'region',
    'cloudtrail_bucket',
    'output_bucket',
    'email',
)


def _validate_user_data(user_data: dict) -> None:
    if not isinstance(user_data, dict):
        raise ValueError('user_data')

    for field in REQUIRED_FIELDS:
        value = user_data.get(field)
        if value is None or str(value).strip() == '':
            raise ValueError(field)


def _users_table(region: str):
    dynamodb = boto3.resource('dynamodb', region_name=region)
    return dynamodb.Table(USERS_TABLE_NAME)


def save_user(user_data: dict, region: str) -> bool:
    _validate_user_data(user_data)

    try:
        table = _users_table(region)
        table.put_item(Item=user_data)
        logger.info('Saved user for account_id=%s', user_data.get('account_id'))
        return True
    except ClientError as exc:
        logger.error('DynamoDB ClientError while saving user account_id=%s: %s', user_data.get('account_id'), exc)
        return False
    except BotoCoreError as exc:
        logger.error('DynamoDB BotoCoreError while saving user account_id=%s: %s', user_data.get('account_id'), exc)
        return False


def get_user(account_id: str, region: str) -> Optional[dict]:
    if account_id is None or str(account_id).strip() == '':
        raise ValueError('account_id')

    try:
        table = _users_table(region)
        response = table.get_item(Key={'account_id': account_id})
        item = response.get('Item')
        logger.info('Fetched user for account_id=%s found=%s', account_id, item is not None)
        return item
    except ClientError as exc:
        logger.error('DynamoDB ClientError while getting user account_id=%s: %s', account_id, exc)
        raise RuntimeError(f'Failed to get user account_id={account_id}') from exc
    except BotoCoreError as exc:
        logger.error('DynamoDB BotoCoreError while getting user account_id=%s: %s', account_id, exc)
        raise RuntimeError(f'Failed to get user account_id={account_id}') from exc


def list_users(region: str) -> list[dict]:
    users: list[dict] = []

    try:
        table = _users_table(region)

        scan_kwargs = {}
        while True:
            response = table.scan(**scan_kwargs)
            users.extend(response.get('Items', []))

            last_key = response.get('LastEvaluatedKey')
            if not last_key:
                break
            scan_kwargs['ExclusiveStartKey'] = last_key

        logger.info('Listed users count=%d', len(users))
        return users
    except ClientError as exc:
        logger.error('DynamoDB ClientError while listing users: %s', exc)
        raise RuntimeError('Failed to list users') from exc
    except BotoCoreError as exc:
        logger.error('DynamoDB BotoCoreError while listing users: %s', exc)
        raise RuntimeError('Failed to list users') from exc


def delete_user(account_id: str, region: str) -> bool:
    if account_id is None or str(account_id).strip() == '':
        raise ValueError('account_id')

    try:
        table = _users_table(region)
        table.delete_item(Key={'account_id': account_id})
        logger.info('Deleted user for account_id=%s', account_id)
        return True
    except ClientError as exc:
        logger.error('DynamoDB ClientError while deleting user account_id=%s: %s', account_id, exc)
        return False
    except BotoCoreError as exc:
        logger.error('DynamoDB BotoCoreError while deleting user account_id=%s: %s', account_id, exc)
        return False
