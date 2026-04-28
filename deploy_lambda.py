import argparse
import json
import zipfile
import os
import time
import logging
from botocore.exceptions import ClientError, NoCredentialsError, PartialCredentialsError
from config.config_loader import AwsOperationError, aws_client, safe_aws_call


LOGGER = logging.getLogger(__name__)


def _aws_error_code(exc):
    if isinstance(exc, ClientError):
        return exc.response.get('Error', {}).get('Code', '')
    return ''


def create_lambda_role(lambda_role_name, model_bucket, cloudtrail_bucket, region):
    """Create IAM role for Lambda function."""
    # Trust policy for Lambda
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "lambda.amazonaws.com"},
            "Action": "sts:AssumeRole"
        }]
    }
    
    # Permissions policy
    permissions_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "logs:CreateLogGroup",
                    "logs:CreateLogStream",
                    "logs:PutLogEvents"
                ],
                "Resource": "arn:aws:logs:*:*:*"
            },
            {
                "Effect": "Allow",
                "Action": [
                    "s3:GetObject"
                ],
                "Resource": [
                    f"arn:aws:s3:::{model_bucket}/models/*",
                    f"arn:aws:s3:::{cloudtrail_bucket}/AWSLogs/*"
                ]
            },
            {
                "Effect": "Allow",
                "Action": [
                    "s3:PutObject"
                ],
                "Resource": [
                    f"arn:aws:s3:::{cloudtrail_bucket}/anomalies/*"
                ]
            },
            {
                "Effect": "Allow",
                "Action": [
                    "s3:ListBucket"
                ],
                "Resource": [
                    f"arn:aws:s3:::{model_bucket}",
                    f"arn:aws:s3:::{cloudtrail_bucket}"
                ]
            }
        ]
    }
    
    try:
        iam = aws_client('iam', region)
        # Create role
        print(f"Creating IAM role: {lambda_role_name}")
        
        try:
            response = safe_aws_call(
                'create Lambda IAM role',
                iam.create_role,
                RoleName=lambda_role_name,
                AssumeRolePolicyDocument=json.dumps(trust_policy),
                Description='Role for CloudTrail anomaly detection Lambda'
            )
            role_arn = response['Role']['Arn']
            print(f"[OK] Role created: {role_arn}")
        except ClientError as e:
            if e.response['Error']['Code'] == 'EntityAlreadyExists':
                role_arn = safe_aws_call(
                    'get existing Lambda IAM role',
                    iam.get_role,
                    RoleName=lambda_role_name
                )['Role']['Arn']
                print(f"[OK] Role already exists: {role_arn}")
            else:
                raise e
        
        # Attach inline policy
        print("Attaching permissions policy...")
        safe_aws_call(
            'attach Lambda IAM inline policy',
            iam.put_role_policy,
            RoleName=lambda_role_name,
            PolicyName='cloudtrail-anomaly-detector-policy',
            PolicyDocument=json.dumps(permissions_policy)
        )
        print("[OK] Permissions policy attached")
        
        # Wait for role to propagate
        print("Waiting for role to propagate...")
        time.sleep(10)
        
        return role_arn
        
    except (ClientError, NoCredentialsError, PartialCredentialsError, AwsOperationError) as e:
        LOGGER.error('IAM role setup failed: %s', e)
        print(f"[FAIL] Error creating role: {e}")
        raise


def create_lambda_package():
    """Create a deployment package from repository runtime source."""
    print("\nCreating Lambda deployment package...")
    lambda_source_path = 'lambda_function.py'
    if not os.path.exists(lambda_source_path):
        raise FileNotFoundError('lambda_function.py not found in repository root')

    # Create zip file
    zip_path = 'lambda_package.zip'
    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zf:
        zf.write(lambda_source_path, arcname='lambda_function.py')
    
    file_size = os.path.getsize(zip_path)
    print(f"[OK] Package created: {zip_path} ({file_size / 1024:.2f} KB)")
    
    return zip_path


def deploy_lambda_function(role_arn, zip_path, lambda_function_name, model_bucket, cloudtrail_bucket, rule_only_mode, region):
    """Deploy or update the Lambda function."""
    print(f"\nDeploying Lambda function: {lambda_function_name}")

    try:
        lambda_client = aws_client('lambda', region)
        with open(zip_path, 'rb') as f:
            zip_content = f.read()
    except OSError as exc:
        LOGGER.error('Failed to read Lambda deployment package %s: %s', zip_path, exc)
        raise
    
    try:
        # Try to create new function
        response = safe_aws_call(
            'create Lambda function',
            lambda_client.create_function,
            FunctionName=lambda_function_name,
            Runtime='python3.11',
            Role=role_arn,
            Handler='lambda_function.lambda_handler',
            Code={'ZipFile': zip_content},
            Description='Detects anomalies in CloudTrail logs',
            Timeout=60,
            MemorySize=512,
            Environment={
                'Variables': {
                    'MODEL_BUCKET': model_bucket,
                    'MODEL_KEY': 'models/cloudtrail_anomaly_model.pkl',
                    'OUTPUT_BUCKET': cloudtrail_bucket,
                    'RULE_ONLY_MODE': str(rule_only_mode).lower(),
                }
            }
        )
        print(f"[OK] Lambda created: {response['FunctionArn']}")
        return response['FunctionArn']
        
    except (ClientError, NoCredentialsError, PartialCredentialsError, AwsOperationError) as e:
        if _aws_error_code(e) == 'ResourceConflictException':
            # Update existing function
            print("Function exists, updating...")
            safe_aws_call(
                'update Lambda function code',
                lambda_client.update_function_code,
                FunctionName=lambda_function_name,
                ZipFile=zip_content
            )

            safe_aws_call(
                'wait for Lambda function update',
                lambda_client.get_waiter('function_updated').wait,
                FunctionName=lambda_function_name
            )

            for attempt in range(1, 6):
                try:
                    safe_aws_call(
                        'update Lambda function configuration',
                        lambda_client.update_function_configuration,
                        FunctionName=lambda_function_name,
                        Runtime='python3.11',
                        Role=role_arn,
                        Handler='lambda_function.lambda_handler',
                        Timeout=60,
                        MemorySize=512,
                        Environment={
                            'Variables': {
                                'MODEL_BUCKET': model_bucket,
                                'MODEL_KEY': 'models/cloudtrail_anomaly_model.pkl',
                                'OUTPUT_BUCKET': cloudtrail_bucket,
                                'RULE_ONLY_MODE': str(rule_only_mode).lower(),
                            }
                        }
                    )
                    break
                except ClientError as inner_e:
                    if inner_e.response['Error']['Code'] == 'ResourceConflictException' and attempt < 5:
                        print(f"[WARN] Lambda busy, retrying configuration update ({attempt}/5)...")
                        time.sleep(4)
                        continue
                    raise

            safe_aws_call(
                'wait for Lambda configuration update',
                lambda_client.get_waiter('function_updated').wait,
                FunctionName=lambda_function_name
            )
            
            response = safe_aws_call(
                'fetch Lambda function details',
                lambda_client.get_function,
                FunctionName=lambda_function_name
            )
            print(f"[OK] Lambda updated: {response['Configuration']['FunctionArn']}")
            return response['Configuration']['FunctionArn']
        else:
            LOGGER.error('Lambda deployment failed: %s', e)
            raise


def setup_s3_trigger(function_arn, lambda_function_name, cloudtrail_bucket, region):
    """Configure S3 to trigger Lambda when CloudTrail delivers logs."""
    print(f"\nSetting up S3 trigger from {cloudtrail_bucket}")

    try:
        lambda_client = aws_client('lambda', region)
        s3_client = aws_client('s3', region)
        account_id = safe_aws_call(
            'resolve AWS account ID for S3 trigger',
            aws_client('sts', region).get_caller_identity
        )['Account']
    except (ClientError, NoCredentialsError, PartialCredentialsError, AwsOperationError) as e:
        LOGGER.error('Failed to initialize clients for trigger setup: %s', e)
        print(f"[WARN] Could not initialize trigger setup clients: {e}")
        return
    
    # Add permission for S3 to invoke Lambda
    try:
        safe_aws_call(
            'add S3 invoke permission to Lambda',
            lambda_client.add_permission,
            FunctionName=lambda_function_name,
            StatementId='S3InvokePermission',
            Action='lambda:InvokeFunction',
            Principal='s3.amazonaws.com',
            SourceArn=f'arn:aws:s3:::{cloudtrail_bucket}',
            SourceAccount=account_id
        )
        print("[OK] Lambda permission added for S3")
    except (ClientError, NoCredentialsError, PartialCredentialsError, AwsOperationError) as e:
        if _aws_error_code(e) == 'ResourceConflictException':
            print("[OK] Lambda permission already exists")
        else:
            print(f"[WARN] Could not add permission: {e}")
    
    # Configure S3 bucket notification
    desired_lambda_config = {
        'Id': 'CloudTrailInvokeLambda',
        'LambdaFunctionArn': function_arn,
        'Events': ['s3:ObjectCreated:*'],
        'Filter': {
            'Key': {
                'FilterRules': [
                    {'Name': 'prefix', 'Value': 'AWSLogs/'},
                    {'Name': 'suffix', 'Value': '.json.gz'}
                ]
            }
        }
    }
    
    try:
        existing = safe_aws_call(
            'get existing S3 bucket notifications',
            s3_client.get_bucket_notification_configuration,
            Bucket=cloudtrail_bucket
        )
        existing_lambda_configs = existing.get('LambdaFunctionConfigurations', [])
        merged_lambda_configs = [
            item for item in existing_lambda_configs if item.get('Id') != desired_lambda_config['Id']
        ]
        merged_lambda_configs.append(desired_lambda_config)

        notification_config = {
            'LambdaFunctionConfigurations': merged_lambda_configs
        }
        if existing.get('QueueConfigurations'):
            notification_config['QueueConfigurations'] = existing.get('QueueConfigurations')
        if existing.get('TopicConfigurations'):
            notification_config['TopicConfigurations'] = existing.get('TopicConfigurations')
        if existing.get('EventBridgeConfiguration'):
            notification_config['EventBridgeConfiguration'] = existing.get('EventBridgeConfiguration')

        safe_aws_call(
            'set S3 bucket notification configuration',
            s3_client.put_bucket_notification_configuration,
            Bucket=cloudtrail_bucket,
            NotificationConfiguration=notification_config
        )
        print("[OK] S3 trigger configured")
    except (ClientError, NoCredentialsError, PartialCredentialsError, AwsOperationError) as e:
        LOGGER.error('S3 trigger configuration failed for bucket %s: %s', cloudtrail_bucket, e)
        print(f"[WARN] Could not configure S3 trigger: {e}")
        print("You may need to configure this manually in the AWS Console")


def main():
    """Main deployment function."""
    parser = argparse.ArgumentParser(description='Deploy CloudTrail anomaly detector Lambda')
    parser.add_argument('--region', required=True, help='AWS region')
    parser.add_argument('--cloudtrail-bucket', required=True, help='CloudTrail source bucket')
    parser.add_argument('--model-bucket', required=True, help='Model bucket')
    parser.add_argument('--lambda-function-name', required=True, help='Lambda function name')
    parser.add_argument('--lambda-role-name', required=True, help='Lambda IAM role name')
    parser.add_argument('--rule-only-mode', action='store_true', help='Deploy in rule-only mode')
    args = parser.parse_args()

    region = args.region
    cloudtrail_bucket = args.cloudtrail_bucket
    model_bucket = args.model_bucket
    lambda_function_name = args.lambda_function_name
    lambda_role_name = args.lambda_role_name
    rule_only_mode = args.rule_only_mode

    print("=" * 60)
    print("CloudTrail Anomaly Detection - Lambda Deployment")
    print("=" * 60)
    print(f"Function: {lambda_function_name}")
    print(f"Region: {region}")
    print(f"CloudTrail Bucket: {cloudtrail_bucket}")
    print(f"Model Bucket: {model_bucket}")
    print(f"Rule Only Mode: {rule_only_mode}")
    print("=" * 60 + "\n")
    
    # Step 1: Create IAM role
    role_arn = create_lambda_role(lambda_role_name, model_bucket, cloudtrail_bucket, region)
    
    # Step 2: Create deployment package
    zip_path = create_lambda_package()
    
    # Step 3: Deploy Lambda
    function_arn = deploy_lambda_function(
        role_arn=role_arn,
        zip_path=zip_path,
        lambda_function_name=lambda_function_name,
        model_bucket=model_bucket,
        cloudtrail_bucket=cloudtrail_bucket,
        rule_only_mode=rule_only_mode,
        region=region,
    )
    
    # Step 4: Setup S3 trigger
    setup_s3_trigger(function_arn, lambda_function_name, cloudtrail_bucket, region)
    
    # Cleanup
    os.remove(zip_path)
    
    print("\n" + "=" * 60)
    print("Lambda Deployment Complete!")
    print("=" * 60)
    print(f"Function ARN: {function_arn}")
    print(f"Trigger: s3://{cloudtrail_bucket}/AWSLogs/*.json.gz")
    print("\nNext Steps:")
    print("1. Wait for CloudTrail to deliver logs (~15-30 min)")
    print("2. Check CloudWatch Logs for Lambda invocations")
    print(f"3. Check s3://{cloudtrail_bucket}/anomalies/ for results")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(name)s %(message)s')
    try:
        main()
    except Exception as exc:
        LOGGER.exception('Deployment failed: %s', exc)
        raise
