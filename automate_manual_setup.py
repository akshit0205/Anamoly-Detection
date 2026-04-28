import argparse
import os
import time
import zipfile
import logging

from botocore.exceptions import ClientError, NoCredentialsError, PartialCredentialsError

from config.config_loader import AwsOperationError, aws_client, load_runtime_config, safe_aws_call
from train_and_upload import extract_features, generate_training_data, save_and_upload, train_model


LOGGER = logging.getLogger(__name__)


def _aws_error_code(exc):
    if isinstance(exc, ClientError):
        return exc.response.get('Error', {}).get('Code', '')
    return ''


def train_and_upload_model(samples, model_bucket, region):
    print('\n[STEP] Training and uploading model...')
    events = generate_training_data(n_samples=samples)
    features, encoders = extract_features(events)
    model = train_model(features)
    save_and_upload(model, encoders, model_bucket, region)
    print('[OK] Model training and upload completed')


def package_lambda_code(zip_path='lambda_package.zip'):
    source_file = 'lambda_function.py'
    if not os.path.exists(source_file):
        raise FileNotFoundError(f'{source_file} not found')

    try:
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zf:
            zf.write(source_file, arcname='lambda_function.py')
    except OSError as exc:
        LOGGER.error('Failed to create Lambda package %s: %s', zip_path, exc)
        raise

    size_kb = os.path.getsize(zip_path) / 1024
    print(f'[OK] Lambda package created: {zip_path} ({size_kb:.2f} KB)')
    return zip_path


def update_lambda_code_and_config(zip_path, runtime_cfg, lambda_function_name, model_bucket, rule_only_mode):
    print('\n[STEP] Updating Lambda code and configuration...')
    try:
        lambda_client = aws_client('lambda', runtime_cfg.region)
        with open(zip_path, 'rb') as f:
            zip_content = f.read()
    except OSError as exc:
        LOGGER.error('Failed to read package %s: %s', zip_path, exc)
        raise
    except (ClientError, NoCredentialsError, PartialCredentialsError, AwsOperationError) as exc:
        LOGGER.error('Failed to initialize Lambda client: %s', exc)
        raise RuntimeError(f'Lambda client initialization failed: {exc}') from exc

    env_vars = {
        'MODEL_BUCKET': model_bucket,
        'MODEL_KEY': 'models/cloudtrail_anomaly_model.pkl',
        'OUTPUT_BUCKET': runtime_cfg.output_bucket,
        'RULE_ONLY_MODE': str(rule_only_mode).lower(),
    }

    try:
        safe_aws_call(
            'update Lambda code',
            lambda_client.update_function_code,
            FunctionName=lambda_function_name,
            ZipFile=zip_content,
            Publish=False,
        )
        safe_aws_call(
            'wait for Lambda code update',
            lambda_client.get_waiter('function_updated').wait,
            FunctionName=lambda_function_name
        )

        for attempt in range(1, 6):
            try:
                safe_aws_call(
                    'update Lambda configuration',
                    lambda_client.update_function_configuration,
                    FunctionName=lambda_function_name,
                    Runtime='python3.11',
                    Handler='lambda_function.lambda_handler',
                    Timeout=60,
                    MemorySize=512,
                    Environment={'Variables': env_vars},
                )
                break
            except ClientError as inner_exc:
                inner_code = inner_exc.response.get('Error', {}).get('Code', '')
                if inner_code == 'ResourceConflictException' and attempt < 5:
                    print(f'[WARN] Lambda busy, retrying config update ({attempt}/5)...')
                    time.sleep(4)
                    continue
                raise

        safe_aws_call(
            'wait for Lambda configuration update',
            lambda_client.get_waiter('function_updated').wait,
            FunctionName=lambda_function_name
        )
        print('[OK] Lambda code and config updated')
    except (ClientError, NoCredentialsError, PartialCredentialsError, AwsOperationError) as exc:
        code = _aws_error_code(exc)
        if code != 'ResourceNotFoundException':
            LOGGER.error('Lambda update failed for %s: %s', lambda_function_name, exc)
            raise RuntimeError(f'Lambda update failed: {exc}') from exc

        print('[WARN] Lambda function not found, creating it...')
        safe_aws_call(
            'create Lambda function',
            lambda_client.create_function,
            FunctionName=lambda_function_name,
            Runtime='python3.11',
            Role=runtime_cfg.role_arn,
            Handler='lambda_function.lambda_handler',
            Code={'ZipFile': zip_content},
            Description='CloudTrail anomaly detector',
            Timeout=60,
            MemorySize=512,
            Environment={'Variables': env_vars},
            Publish=False,
        )
        print('[OK] Lambda function created and configured')


def cleanup_package(zip_path):
    if os.path.exists(zip_path):
        os.remove(zip_path)
        print('[OK] Cleaned up temporary package')


def ensure_s3_trigger(runtime_cfg, lambda_function_name):
    print('\n[STEP] Ensuring S3 trigger configuration...')
    try:
        lambda_client = aws_client('lambda', runtime_cfg.region)
        s3_client = aws_client('s3', runtime_cfg.region)
    except (ClientError, NoCredentialsError, PartialCredentialsError, AwsOperationError) as exc:
        LOGGER.error('Failed to initialize trigger clients: %s', exc)
        raise RuntimeError(f'Failed to initialize trigger clients: {exc}') from exc

    try:
        safe_aws_call(
            'add S3 invoke permission to Lambda',
            lambda_client.add_permission,
            FunctionName=lambda_function_name,
            StatementId='S3InvokePermission',
            Action='lambda:InvokeFunction',
            Principal='s3.amazonaws.com',
            SourceArn=f"arn:aws:s3:::{runtime_cfg.cloudtrail_bucket}",
            SourceAccount=runtime_cfg.account_id,
        )
        print('[OK] Added Lambda invoke permission for S3')
    except (ClientError, NoCredentialsError, PartialCredentialsError, AwsOperationError) as exc:
        code = _aws_error_code(exc)
        if code == 'ResourceConflictException':
            print('[OK] Lambda invoke permission already exists')
        else:
            LOGGER.error('Failed adding Lambda invoke permission: %s', exc)
            raise RuntimeError(f'Failed to add S3 invoke permission: {exc}') from exc

    function_arn = safe_aws_call(
        'get Lambda function metadata',
        lambda_client.get_function,
        FunctionName=lambda_function_name
    )['Configuration']['FunctionArn']
    desired_config = {
        'Id': 'CloudTrailInvokeLambda',
        'LambdaFunctionArn': function_arn,
        'Events': ['s3:ObjectCreated:*'],
        'Filter': {
            'Key': {
                'FilterRules': [
                    {'Name': 'prefix', 'Value': 'AWSLogs/'},
                    {'Name': 'suffix', 'Value': '.json.gz'},
                ]
            }
        },
    }

    try:
        existing = safe_aws_call(
            'get S3 bucket notification configuration',
            s3_client.get_bucket_notification_configuration,
            Bucket=runtime_cfg.cloudtrail_bucket
        )
    except (ClientError, NoCredentialsError, PartialCredentialsError, AwsOperationError) as exc:
        code = _aws_error_code(exc)
        if code in {'AccessDenied', 'AllAccessDisabled'}:
            print('[WARN] No permission to manage S3 bucket notifications')
            print('       Required: s3:GetBucketNotification and s3:PutBucketNotification')
            print(f'       Bucket: {runtime_cfg.cloudtrail_bucket}')
            return
        LOGGER.error('Failed to read S3 notifications for %s: %s', runtime_cfg.cloudtrail_bucket, exc)
        raise

    existing_lambdas = existing.get('LambdaFunctionConfigurations', [])
    updated_lambdas = [
        item for item in existing_lambdas if item.get('Id') != desired_config['Id']
    ]
    updated_lambdas.append(desired_config)

    notification_configuration = {
        'LambdaFunctionConfigurations': updated_lambdas,
    }
    if existing.get('QueueConfigurations'):
        notification_configuration['QueueConfigurations'] = existing.get('QueueConfigurations')
    if existing.get('TopicConfigurations'):
        notification_configuration['TopicConfigurations'] = existing.get('TopicConfigurations')
    if existing.get('EventBridgeConfiguration'):
        notification_configuration['EventBridgeConfiguration'] = existing.get('EventBridgeConfiguration')

    try:
        safe_aws_call(
            'set S3 bucket notification configuration',
            s3_client.put_bucket_notification_configuration,
            Bucket=runtime_cfg.cloudtrail_bucket,
            NotificationConfiguration=notification_configuration,
        )
        print('[OK] S3 trigger configured')
    except (ClientError, NoCredentialsError, PartialCredentialsError, AwsOperationError) as exc:
        code = _aws_error_code(exc)
        if code in {'AccessDenied', 'AllAccessDisabled'}:
            print('[WARN] Could not apply S3 trigger due to permissions')
            print('       Required: s3:PutBucketNotification')
            print(f'       Bucket: {runtime_cfg.cloudtrail_bucket}')
            return
        LOGGER.error('Failed to update S3 notifications for %s: %s', runtime_cfg.cloudtrail_bucket, exc)
        raise


def main():
    parser = argparse.ArgumentParser(description='Automate manual AWS setup flow using runtime config')

    parser.add_argument('--account-id', required=True, help='AWS account ID for the tenant')
    parser.add_argument('--role-arn', required=True, help='IAM role ARN used by Lambda runtime')
    parser.add_argument('--region', required=True, help='AWS region')
    parser.add_argument('--cloudtrail-bucket', required=True, help='CloudTrail source bucket')
    parser.add_argument('--output-bucket', required=True, help='Anomaly output bucket')
    parser.add_argument('--email', required=True, help='Tenant alert email')

    parser.add_argument('--lambda-function-name', required=True, help='Lambda function name to create/update')
    parser.add_argument('--model-bucket', required=True, help='Model bucket used by Lambda/training')
    parser.add_argument('--rule-only-mode', action='store_true', help='Skip ML model usage in Lambda')

    parser.add_argument('--skip-model', action='store_true', help='Skip model train/upload')
    parser.add_argument('--skip-lambda', action='store_true', help='Skip lambda update')
    parser.add_argument('--skip-trigger', action='store_true', help='Skip S3 trigger configuration')
    parser.add_argument('--samples', type=int, default=10000, help='Training sample count')
    args = parser.parse_args()

    runtime_cfg = load_runtime_config(
        account_id=args.account_id,
        role_arn=args.role_arn,
        region=args.region,
        cloudtrail_bucket=args.cloudtrail_bucket,
        output_bucket=args.output_bucket,
        email=args.email,
    )

    print('=' * 60)
    print('Manual Setup Automation')
    print('=' * 60)
    print('[OK] Runtime configuration loaded')
    print(f'      Account ID: {runtime_cfg.account_id}')
    print(f'      Region: {runtime_cfg.region}')
    print(f'      CloudTrail bucket: {runtime_cfg.cloudtrail_bucket}')
    print(f'      Output bucket: {runtime_cfg.output_bucket}')
    print(f'      Lambda function: {args.lambda_function_name}')
    print(f'      Model bucket: {args.model_bucket}')
    print(f'      Rule only mode: {args.rule_only_mode}')

    if not args.skip_model and not args.rule_only_mode:
        train_and_upload_model(samples=args.samples, model_bucket=args.model_bucket, region=runtime_cfg.region)
    elif args.rule_only_mode:
        print('[INFO] Rule-only mode enabled, skipping model training/upload')
    else:
        print('[INFO] Model training/upload skipped by flag')

    zip_path = None
    if not args.skip_lambda:
        zip_path = package_lambda_code()
        update_lambda_code_and_config(
            zip_path=zip_path,
            runtime_cfg=runtime_cfg,
            lambda_function_name=args.lambda_function_name,
            model_bucket=args.model_bucket,
            rule_only_mode=args.rule_only_mode,
        )
    else:
        print('[INFO] Lambda update skipped by flag')

    if zip_path:
        cleanup_package(zip_path)

    if not args.skip_trigger:
        ensure_s3_trigger(runtime_cfg, args.lambda_function_name)
    else:
        print('[INFO] S3 trigger setup skipped by flag')

    print('\n' + '=' * 60)
    print('[OK] Automation complete')
    print('Next: generate a few AWS actions and verify CloudWatch + S3 anomalies/')
    print('=' * 60)


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(name)s %(message)s')
    try:
        main()
    except Exception as exc:
        LOGGER.exception('Automation failed: %s', exc)
        raise
