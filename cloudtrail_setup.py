import argparse
import json
import logging
from botocore.exceptions import ClientError, NoCredentialsError, PartialCredentialsError
from config.config_loader import AwsOperationError, aws_client, safe_aws_call


LOGGER = logging.getLogger(__name__)


def create_s3_bucket_for_cloudtrail(bucket_name, region='us-east-1'):
    """
    Create an S3 bucket with encryption and lifecycle policy for CloudTrail logs.
    
    Args:
        bucket_name: Name of the S3 bucket to create
        region: AWS region for the bucket
    
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        s3_client = aws_client('s3', region)
        print(f"Creating S3 bucket: {bucket_name}")
        
        try:
            if region == 'us-east-1':
                safe_aws_call('create CloudTrail bucket', s3_client.create_bucket, Bucket=bucket_name)
            else:
                safe_aws_call(
                    'create CloudTrail bucket with region constraint',
                    s3_client.create_bucket,
                    Bucket=bucket_name,
                    CreateBucketConfiguration={'LocationConstraint': region}
                )
            print(f"[OK] Bucket '{bucket_name}' created successfully")
        except ClientError as bucket_error:
            if bucket_error.response['Error']['Code'] in ['BucketAlreadyOwnedByYou', 'BucketAlreadyExists']:
                print(f"[OK] Bucket '{bucket_name}' already exists, continuing with configuration...")
            else:
                raise bucket_error
        
        print("Enabling server-side encryption...")
        encryption_config = {
            'Rules': [
                {
                    'ApplyServerSideEncryptionByDefault': {
                        'SSEAlgorithm': 'AES256'
                    },
                    'BucketKeyEnabled': True
                }
            ]
        }
        safe_aws_call(
            'enable CloudTrail bucket encryption',
            s3_client.put_bucket_encryption,
            Bucket=bucket_name,
            ServerSideEncryptionConfiguration=encryption_config
        )
        print("[OK] Server-side encryption (AES256) enabled")
        
        print("Blocking public access...")
        safe_aws_call(
            'block CloudTrail bucket public access',
            s3_client.put_public_access_block,
            Bucket=bucket_name,
            PublicAccessBlockConfiguration={
                'BlockPublicAcls': True,
                'IgnorePublicAcls': True,
                'BlockPublicPolicy': True,
                'RestrictPublicBuckets': True
            }
        )
        print("[OK] Public access blocked")

        print("Attaching lifecycle policy (90 days -> Glacier)...")
        lifecycle_config = {
            'Rules': [
                {
                    'ID': 'TransitionToGlacierAfter90Days',
                    'Status': 'Enabled',
                    'Filter': {'Prefix': ''},
                    'Transitions': [
                        {
                            'Days': 90,
                            'StorageClass': 'GLACIER'
                        }
                    ]
                }
            ]
        }
        safe_aws_call(
            'attach CloudTrail bucket lifecycle policy',
            s3_client.put_bucket_lifecycle_configuration,
            Bucket=bucket_name,
            LifecycleConfiguration=lifecycle_config
        )
        print("[OK] Lifecycle policy attached (transition to Glacier after 90 days)")
        
        print("Attaching CloudTrail bucket policy...")
        sts_client = aws_client('sts', region)
        account_id = safe_aws_call('resolve AWS account ID', sts_client.get_caller_identity)['Account']
        
        bucket_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AWSCloudTrailAclCheck",
                    "Effect": "Allow",
                    "Principal": {"Service": "cloudtrail.amazonaws.com"},
                    "Action": "s3:GetBucketAcl",
                    "Resource": f"arn:aws:s3:::{bucket_name}"
                },
                {
                    "Sid": "AWSCloudTrailWrite",
                    "Effect": "Allow",
                    "Principal": {"Service": "cloudtrail.amazonaws.com"},
                    "Action": "s3:PutObject",
                    "Resource": f"arn:aws:s3:::{bucket_name}/AWSLogs/{account_id}/*",
                    "Condition": {
                        "StringEquals": {
                            "s3:x-amz-acl": "bucket-owner-full-control"
                        }
                    }
                }
            ]
        }
        
        safe_aws_call(
            'attach CloudTrail bucket policy',
            s3_client.put_bucket_policy,
            Bucket=bucket_name,
            Policy=json.dumps(bucket_policy)
        )
        print("[OK] CloudTrail bucket policy attached")
        
        return True
        
    except (ClientError, NoCredentialsError, PartialCredentialsError, AwsOperationError) as e:
        LOGGER.error('Failed to configure CloudTrail bucket: %s', e)
        print(f"[FAIL] Error: {e}")
        return False


def enable_cloudtrail(trail_name, bucket_name, region='us-east-1'):
    """
    Create and enable a CloudTrail trail pointing to the S3 bucket.
    
    Args:
        trail_name: Name of the CloudTrail trail
        bucket_name: Name of the S3 bucket for logs
        region: AWS region
    
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        cloudtrail_client = aws_client('cloudtrail', region)
        print(f"\nCreating CloudTrail: {trail_name}")
        trail_arn = None

        try:
            response = safe_aws_call(
                'create CloudTrail trail',
                cloudtrail_client.create_trail,
                Name=trail_name,
                S3BucketName=bucket_name,
                IsMultiRegionTrail=True,
                EnableLogFileValidation=True,
                IncludeGlobalServiceEvents=True
            )
            trail_arn = response['TrailARN']
            print(f"[OK] CloudTrail '{trail_name}' created successfully")
        except ClientError as create_error:
            if create_error.response['Error']['Code'] == 'TrailAlreadyExistsException':
                print(f"[OK] CloudTrail '{trail_name}' already exists, continuing...")
                trails = safe_aws_call(
                    'describe CloudTrail trails',
                    cloudtrail_client.describe_trails,
                    trailNameList=[trail_name],
                    includeShadowTrails=False
                ).get('trailList', [])
                if trails:
                    trail_arn = trails[0].get('TrailARN')
            else:
                raise

        print("Starting CloudTrail logging...")
        safe_aws_call('start CloudTrail logging', cloudtrail_client.start_logging, Name=trail_name)
        print("[OK] CloudTrail logging started")

        print(f"\n{'='*50}")
        print("CloudTrail Setup Complete!")
        print(f"{'='*50}")
        if trail_arn:
            print(f"Trail ARN: {trail_arn}")
        print(f"S3 Bucket: {bucket_name}")
        print(f"Log File Validation: Enabled")
        print(f"Multi-Region: Yes")
        print(f"Lifecycle: Objects move to Glacier after 90 days")

        return True

    except (ClientError, NoCredentialsError, PartialCredentialsError, AwsOperationError) as e:
        LOGGER.error('Failed to create or start CloudTrail: %s', e)
        print(f"[FAIL] Error creating CloudTrail: {e}")
        return False


def main():
    """Main function to set up CloudTrail with S3 bucket."""
    parser = argparse.ArgumentParser(description='Set up CloudTrail with an S3 bucket')
    parser.add_argument('--cloudtrail-bucket', required=True, help='CloudTrail S3 bucket name')
    parser.add_argument('--trail-name', required=True, help='CloudTrail trail name')
    parser.add_argument('--region', required=True, help='AWS region')
    args = parser.parse_args()

    bucket_name = args.cloudtrail_bucket
    trail_name = args.trail_name
    region = args.region
    
    print("=" * 50)
    print("CloudTrail Setup with S3 Bucket")
    print("=" * 50)
    print(f"Bucket Name: {bucket_name}")
    print(f"Trail Name: {trail_name}")
    print(f"Region: {region}")
    print("=" * 50 + "\n")
    if create_s3_bucket_for_cloudtrail(bucket_name, region):
        enable_cloudtrail(trail_name, bucket_name, region)
    else:
        print("\n[FAIL] Failed to create S3 bucket. CloudTrail setup aborted.")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(name)s %(message)s')
    main()
