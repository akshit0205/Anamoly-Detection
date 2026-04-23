import boto3
import json
import zipfile
import os
import time
from botocore.exceptions import ClientError


# Configuration
LAMBDA_FUNCTION_NAME = "cloudtrail-anomaly-detector"
LAMBDA_ROLE_NAME = "cloudtrail-anomaly-detector-role"
MODEL_BUCKET = "akshit-ml-models-4679"
CLOUDTRAIL_BUCKET = "akshit-cloudtrail-logs-4679"
REGION = "us-east-1"


def create_lambda_role():
    """Create IAM role for Lambda function."""
    iam = boto3.client('iam')
    
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
                    "s3:GetObject",
                    "s3:PutObject"
                ],
                "Resource": [
                    f"arn:aws:s3:::{MODEL_BUCKET}/*",
                    f"arn:aws:s3:::{CLOUDTRAIL_BUCKET}/*"
                ]
            },
            {
                "Effect": "Allow",
                "Action": [
                    "s3:ListBucket"
                ],
                "Resource": [
                    f"arn:aws:s3:::{MODEL_BUCKET}",
                    f"arn:aws:s3:::{CLOUDTRAIL_BUCKET}"
                ]
            }
        ]
    }
    
    try:
        # Create role
        print(f"Creating IAM role: {LAMBDA_ROLE_NAME}")
        
        try:
            response = iam.create_role(
                RoleName=LAMBDA_ROLE_NAME,
                AssumeRolePolicyDocument=json.dumps(trust_policy),
                Description='Role for CloudTrail anomaly detection Lambda'
            )
            role_arn = response['Role']['Arn']
            print(f"[OK] Role created: {role_arn}")
        except ClientError as e:
            if e.response['Error']['Code'] == 'EntityAlreadyExists':
                role_arn = iam.get_role(RoleName=LAMBDA_ROLE_NAME)['Role']['Arn']
                print(f"[OK] Role already exists: {role_arn}")
            else:
                raise e
        
        # Attach inline policy
        print("Attaching permissions policy...")
        iam.put_role_policy(
            RoleName=LAMBDA_ROLE_NAME,
            PolicyName='cloudtrail-anomaly-detector-policy',
            PolicyDocument=json.dumps(permissions_policy)
        )
        print("[OK] Permissions policy attached")
        
        # Wait for role to propagate
        print("Waiting for role to propagate...")
        time.sleep(10)
        
        return role_arn
        
    except Exception as e:
        print(f"[FAIL] Error creating role: {e}")
        raise


def create_lambda_package():
    """Create a deployment package for Lambda with dependencies."""
    print("\nCreating Lambda deployment package...")
    
    # Lambda function code (simplified version without sklearn for smaller package)
    lambda_code = '''
"""
CloudTrail Anomaly Detection Lambda (Rule-based version)
"""

import json
import boto3
import gzip
import os
from datetime import datetime
from io import BytesIO
import urllib.parse


OUTPUT_BUCKET = os.environ.get('OUTPUT_BUCKET', 'akshit-cloudtrail-logs-4679')

SUSPICIOUS_APIS = [
    'DeleteTrail', 'StopLogging', 'UpdateTrail',
    'DeleteBucket', 'DeleteBucketPolicy',
    'CreateUser', 'CreateAccessKey', 'DeleteUser',
    'AttachUserPolicy', 'AttachRolePolicy',
    'PutBucketPolicy', 'PutBucketAcl',
    'AuthorizeSecurityGroupIngress', 'AuthorizeSecurityGroupEgress',
    'CreateKeyPair', 'ImportKeyPair',
    'RunInstances', 'CreateRole', 'CreateFunction',
    'DeleteFunction', 'UpdateFunctionCode',
    'CreateVpc', 'DeleteVpc',
    'CreateSecurityGroup', 'DeleteSecurityGroup'
]


def parse_cloudtrail_log(bucket, key):
    s3 = boto3.client('s3')
    
    try:
        response = s3.get_object(Bucket=bucket, Key=key)
        
        if key.endswith('.gz'):
            with gzip.GzipFile(fileobj=BytesIO(response['Body'].read())) as f:
                log_data = json.loads(f.read().decode('utf-8'))
        else:
            log_data = json.loads(response['Body'].read().decode('utf-8'))
        
        return log_data.get('Records', [])
        
    except Exception as e:
        print(f"Error parsing log: {e}")
        return []


def analyze_event(event):
    result = {
        'eventId': event.get('eventID', 'unknown'),
        'eventTime': event.get('eventTime', ''),
        'eventName': event.get('eventName', ''),
        'eventSource': event.get('eventSource', ''),
        'sourceIPAddress': event.get('sourceIPAddress', ''),
        'awsRegion': event.get('awsRegion', ''),
        'userIdentity': event.get('userIdentity', {}),
        'is_anomaly': False,
        'anomaly_reasons': []
    }
    
    api_name = event.get('eventName', '')
    user_identity = event.get('userIdentity', {})
    
    # Check for suspicious APIs
    if api_name in SUSPICIOUS_APIS:
        result['anomaly_reasons'].append(f"Suspicious API: {api_name}")
        result['is_anomaly'] = True
    
    # Check for root account
    if user_identity.get('type') == 'Root':
        result['anomaly_reasons'].append("Root account used")
        result['is_anomaly'] = True
    
    # Check for access errors
    error_code = event.get('errorCode', '')
    if error_code in ['AccessDenied', 'UnauthorizedAccess', 'InvalidClientTokenId', 'SignatureDoesNotMatch']:
        result['anomaly_reasons'].append(f"Access error: {error_code}")
        result['is_anomaly'] = True
    
    # Check for unusual hours (outside 6 AM - 10 PM)
    try:
        event_time = event.get('eventTime', '')
        hour = datetime.fromisoformat(event_time.replace('Z', '+00:00')).hour
        if hour < 6 or hour > 22:
            result['anomaly_reasons'].append(f"Unusual hour: {hour}:00 UTC")
            result['is_anomaly'] = True
    except:
        pass
    
    # Check for console login from new IP
    if api_name == 'ConsoleLogin':
        result['anomaly_reasons'].append("Console login detected")
        result['is_anomaly'] = True
    
    return result


def save_anomalies(anomalies, source_key):
    if not anomalies:
        return
    
    s3 = boto3.client('s3')
    timestamp = datetime.utcnow().strftime('%Y/%m/%d/%H')
    filename = os.path.basename(source_key).replace('.json.gz', '_anomalies.json')
    output_key = f"anomalies/{timestamp}/{filename}"
    
    output = {
        'source_log': source_key,
        'analyzed_at': datetime.utcnow().isoformat(),
        'total_anomalies': len(anomalies),
        'anomalies': anomalies
    }
    
    try:
        s3.put_object(
            Bucket=OUTPUT_BUCKET,
            Key=output_key,
            Body=json.dumps(output, indent=2, default=str),
            ContentType='application/json'
        )
        print(f"Saved: s3://{OUTPUT_BUCKET}/{output_key}")
    except Exception as e:
        print(f"Error saving: {e}")


def lambda_handler(event, context):
    print("CloudTrail Anomaly Detection")
    print(f"Event: {json.dumps(event)}")
    
    total_events = 0
    total_anomalies = 0
    all_anomalies = []
    
    for record in event.get('Records', []):
        bucket = record['s3']['bucket']['name']
        key = urllib.parse.unquote_plus(record['s3']['object']['key'])
        
        if 'CloudTrail' not in key:
            print(f"Skipping: {key}")
            continue
        
        print(f"Processing: {key}")
        events = parse_cloudtrail_log(bucket, key)
        total_events += len(events)
        
        for ct_event in events:
            result = analyze_event(ct_event)
            if result['is_anomaly']:
                total_anomalies += 1
                all_anomalies.append(result)
                print(f"ANOMALY: {result['eventName']} - {result['anomaly_reasons']}")
        
        save_anomalies(all_anomalies, key)
    
    print(f"Complete: {total_events} events, {total_anomalies} anomalies")
    
    return {
        'statusCode': 200,
        'body': {
            'events_analyzed': total_events,
            'anomalies_detected': total_anomalies
        }
    }
'''
    
    # Create zip file
    zip_path = 'lambda_package.zip'
    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zf:
        zf.writestr('lambda_function.py', lambda_code)
    
    file_size = os.path.getsize(zip_path)
    print(f"[OK] Package created: {zip_path} ({file_size / 1024:.2f} KB)")
    
    return zip_path


def deploy_lambda_function(role_arn, zip_path):
    """Deploy or update the Lambda function."""
    lambda_client = boto3.client('lambda', region_name=REGION)
    
    print(f"\nDeploying Lambda function: {LAMBDA_FUNCTION_NAME}")
    
    with open(zip_path, 'rb') as f:
        zip_content = f.read()
    
    try:
        # Try to create new function
        response = lambda_client.create_function(
            FunctionName=LAMBDA_FUNCTION_NAME,
            Runtime='python3.11',
            Role=role_arn,
            Handler='lambda_function.lambda_handler',
            Code={'ZipFile': zip_content},
            Description='Detects anomalies in CloudTrail logs',
            Timeout=60,
            MemorySize=512,
            Environment={
                'Variables': {
                    'MODEL_BUCKET': MODEL_BUCKET,
                    'OUTPUT_BUCKET': CLOUDTRAIL_BUCKET
                }
            }
        )
        print(f"[OK] Lambda created: {response['FunctionArn']}")
        return response['FunctionArn']
        
    except ClientError as e:
        if e.response['Error']['Code'] == 'ResourceConflictException':
            # Update existing function
            print("Function exists, updating...")
            lambda_client.update_function_code(
                FunctionName=LAMBDA_FUNCTION_NAME,
                ZipFile=zip_content
            )
            
            # Wait for update
            time.sleep(5)
            
            lambda_client.update_function_configuration(
                FunctionName=LAMBDA_FUNCTION_NAME,
                Runtime='python3.11',
                Role=role_arn,
                Handler='lambda_function.lambda_handler',
                Timeout=60,
                MemorySize=512,
                Environment={
                    'Variables': {
                        'MODEL_BUCKET': MODEL_BUCKET,
                        'OUTPUT_BUCKET': CLOUDTRAIL_BUCKET
                    }
                }
            )
            
            response = lambda_client.get_function(FunctionName=LAMBDA_FUNCTION_NAME)
            print(f"[OK] Lambda updated: {response['Configuration']['FunctionArn']}")
            return response['Configuration']['FunctionArn']
        else:
            raise e


def setup_s3_trigger(function_arn):
    """Configure S3 to trigger Lambda when CloudTrail delivers logs."""
    lambda_client = boto3.client('lambda', region_name=REGION)
    s3_client = boto3.client('s3', region_name=REGION)
    account_id = boto3.client('sts').get_caller_identity()['Account']
    
    print(f"\nSetting up S3 trigger from {CLOUDTRAIL_BUCKET}")
    
    # Add permission for S3 to invoke Lambda
    try:
        lambda_client.add_permission(
            FunctionName=LAMBDA_FUNCTION_NAME,
            StatementId='S3InvokePermission',
            Action='lambda:InvokeFunction',
            Principal='s3.amazonaws.com',
            SourceArn=f'arn:aws:s3:::{CLOUDTRAIL_BUCKET}',
            SourceAccount=account_id
        )
        print("[OK] Lambda permission added for S3")
    except ClientError as e:
        if e.response['Error']['Code'] == 'ResourceConflictException':
            print("[OK] Lambda permission already exists")
        else:
            print(f"[WARN] Could not add permission: {e}")
    
    # Configure S3 bucket notification
    notification_config = {
        'LambdaFunctionConfigurations': [{
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
        }]
    }
    
    try:
        s3_client.put_bucket_notification_configuration(
            Bucket=CLOUDTRAIL_BUCKET,
            NotificationConfiguration=notification_config
        )
        print("[OK] S3 trigger configured")
    except Exception as e:
        print(f"[WARN] Could not configure S3 trigger: {e}")
        print("You may need to configure this manually in the AWS Console")


def main():
    """Main deployment function."""
    print("=" * 60)
    print("CloudTrail Anomaly Detection - Lambda Deployment")
    print("=" * 60)
    print(f"Function: {LAMBDA_FUNCTION_NAME}")
    print(f"Region: {REGION}")
    print(f"CloudTrail Bucket: {CLOUDTRAIL_BUCKET}")
    print(f"Model Bucket: {MODEL_BUCKET}")
    print("=" * 60 + "\n")
    
    # Step 1: Create IAM role
    role_arn = create_lambda_role()
    
    # Step 2: Create deployment package
    zip_path = create_lambda_package()
    
    # Step 3: Deploy Lambda
    function_arn = deploy_lambda_function(role_arn, zip_path)
    
    # Step 4: Setup S3 trigger
    setup_s3_trigger(function_arn)
    
    # Cleanup
    os.remove(zip_path)
    
    print("\n" + "=" * 60)
    print("Lambda Deployment Complete!")
    print("=" * 60)
    print(f"Function ARN: {function_arn}")
    print(f"Trigger: s3://{CLOUDTRAIL_BUCKET}/AWSLogs/*.json.gz")
    print("\nNext Steps:")
    print("1. Wait for CloudTrail to deliver logs (~15-30 min)")
    print("2. Check CloudWatch Logs for Lambda invocations")
    print(f"3. Check s3://{CLOUDTRAIL_BUCKET}/anomalies/ for results")


if __name__ == "__main__":
    main()
