from dataclasses import dataclass
import logging
import re

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError, NoCredentialsError, PartialCredentialsError


BOTO_RETRY_CONFIG = Config(
    retries={
        'max_attempts': 8,
        'mode': 'standard'
    }
)

LOGGER = logging.getLogger(__name__)


class ConfigValidationError(ValueError):
    """Raised when runtime config validation fails."""


class AwsOperationError(RuntimeError):
    """Raised when AWS operations fail with actionable context."""


@dataclass
class RuntimeConfig:
    account_id: str
    role_arn: str
    region: str
    cloudtrail_bucket: str
    output_bucket: str
    email: str


ACCOUNT_ID_PATTERN = re.compile(r'^\d{12}$')
ROLE_ARN_PATTERN = re.compile(r'^arn:aws:iam::\d{12}:role\/.+$')
REGION_PATTERN = re.compile(r'^[a-z]{2}-[a-z]+-\d$')
BUCKET_PATTERN = re.compile(r'^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$')
EMAIL_PATTERN = re.compile(r'^[^@\s]+@[^@\s]+\.[^@\s]+$')


def _validate_runtime_values(values):
    missing = [key for key, value in values.items() if value is None or str(value).strip() == '']
    if missing:
        raise ConfigValidationError(f"Missing required runtime config values: {', '.join(missing)}")

    if not ACCOUNT_ID_PATTERN.match(values['account_id']):
        raise ConfigValidationError('account_id must be a 12-digit AWS account ID')
    if not ROLE_ARN_PATTERN.match(values['role_arn']):
        raise ConfigValidationError('role_arn must be a valid IAM role ARN')
    if not REGION_PATTERN.match(values['region']):
        raise ConfigValidationError('region must look like ap-south-1 or us-east-1')
    if not BUCKET_PATTERN.match(values['cloudtrail_bucket']):
        raise ConfigValidationError('cloudtrail_bucket must be a valid S3 bucket name')
    if not BUCKET_PATTERN.match(values['output_bucket']):
        raise ConfigValidationError('output_bucket must be a valid S3 bucket name')
    if not EMAIL_PATTERN.match(values['email']):
        raise ConfigValidationError('email must be a valid email address')


def load_runtime_config(account_id, role_arn, region, cloudtrail_bucket, output_bucket, email):
    """Build and validate runtime config passed by caller at execution time."""
    values = {
        'account_id': account_id,
        'role_arn': role_arn,
        'region': region,
        'cloudtrail_bucket': cloudtrail_bucket,
        'output_bucket': output_bucket,
        'email': email,
    }

    _validate_runtime_values(values)

    return RuntimeConfig(**values)


def aws_client(service_name, region_name, credentials=None):
    """Create boto3 clients with runtime region and optional temporary credentials."""
    client_kwargs = {
        'region_name': region_name,
        'config': BOTO_RETRY_CONFIG,
    }
    if credentials:
        client_kwargs.update({
            'aws_access_key_id': credentials.get('AccessKeyId'),
            'aws_secret_access_key': credentials.get('SecretAccessKey'),
            'aws_session_token': credentials.get('SessionToken'),
        })

    try:
        return boto3.client(service_name, **client_kwargs)
    except NoCredentialsError as exc:
        LOGGER.error('AWS credentials not found while creating %s client in %s', service_name, region_name)
        raise AwsOperationError(f'AWS credentials not found for {service_name} client') from exc
    except PartialCredentialsError as exc:
        LOGGER.error('Partial AWS credentials for %s client in %s: %s', service_name, region_name, exc)
        raise AwsOperationError(f'Partial AWS credentials for {service_name} client') from exc
    except Exception as exc:
        LOGGER.exception('Unexpected error creating %s client in %s', service_name, region_name)
        raise AwsOperationError(f'Unexpected error creating {service_name} client') from exc


def safe_aws_call(action, fn, *args, **kwargs):
    """Execute an AWS operation with consistent credential and client error handling."""
    try:
        return fn(*args, **kwargs)
    except NoCredentialsError as exc:
        LOGGER.error('No AWS credentials while attempting: %s', action)
        raise AwsOperationError(f'AWS credentials not configured for action: {action}') from exc
    except PartialCredentialsError as exc:
        LOGGER.error('Partial AWS credentials while attempting %s: %s', action, exc)
        raise AwsOperationError(f'Incomplete AWS credentials for action: {action}') from exc
    except ClientError as exc:
        code = exc.response.get('Error', {}).get('Code', 'Unknown')
        LOGGER.error('AWS client error during %s: %s', action, code)
        raise AwsOperationError(f'AWS error during {action}: {code}') from exc
    except Exception as exc:
        LOGGER.exception('Unexpected error during AWS action: %s', action)
        raise AwsOperationError(f'Unexpected AWS error during {action}') from exc
