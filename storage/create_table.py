import argparse
import logging
import time

import boto3
from botocore.exceptions import BotoCoreError, ClientError


logger = logging.getLogger(__name__)
USERS_TABLE_NAME = 'users'


def create_users_table(region: str) -> bool:
    dynamodb = boto3.client('dynamodb', region_name=region)

    try:
        logger.info('Creating DynamoDB table %s in region=%s', USERS_TABLE_NAME, region)
        dynamodb.create_table(
            TableName=USERS_TABLE_NAME,
            KeySchema=[
                {'AttributeName': 'account_id', 'KeyType': 'HASH'},
            ],
            AttributeDefinitions=[
                {'AttributeName': 'account_id', 'AttributeType': 'S'},
            ],
            BillingMode='PAY_PER_REQUEST',
        )
    except ClientError as exc:
        code = exc.response.get('Error', {}).get('Code', '')
        if code == 'ResourceInUseException':
            logger.warning('Table %s already exists in region=%s', USERS_TABLE_NAME, region)
            return True
        logger.error('ClientError while creating table %s: %s', USERS_TABLE_NAME, exc)
        return False
    except BotoCoreError as exc:
        logger.error('BotoCoreError while creating table %s: %s', USERS_TABLE_NAME, exc)
        return False

    logger.info('Waiting for table %s to become ACTIVE', USERS_TABLE_NAME)
    try:
        waiter = dynamodb.get_waiter('table_exists')
        waiter.wait(TableName=USERS_TABLE_NAME)

        for _ in range(30):
            description = dynamodb.describe_table(TableName=USERS_TABLE_NAME)
            status = description.get('Table', {}).get('TableStatus')
            if status == 'ACTIVE':
                logger.info('Table %s is ACTIVE', USERS_TABLE_NAME)
                return True
            time.sleep(2)

        logger.error('Timed out waiting for table %s to become ACTIVE', USERS_TABLE_NAME)
        return False
    except ClientError as exc:
        logger.error('ClientError while waiting for table %s ACTIVE state: %s', USERS_TABLE_NAME, exc)
        return False
    except BotoCoreError as exc:
        logger.error('BotoCoreError while waiting for table %s ACTIVE state: %s', USERS_TABLE_NAME, exc)
        return False


def main() -> None:
    parser = argparse.ArgumentParser(description='Create DynamoDB users table')
    parser.add_argument('--region', default='us-east-1', help='AWS region for DynamoDB table creation')
    args = parser.parse_args()

    success = create_users_table(region=args.region)
    if success:
        logger.info('users table setup completed')
    else:
        logger.error('users table setup failed')


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(name)s %(message)s')
    main()
