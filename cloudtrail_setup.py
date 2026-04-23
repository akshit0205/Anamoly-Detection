import boto3
import json
from botocore.exceptions import ClientError


def create_s3_bucket_for_cloudtrail(bucket_name, region='us-east-1'):
    """
    Create an S3 bucket with encryption and lifecycle policy for CloudTrail logs.
    
    Args:
        bucket_name: Name of the S3 bucket to create
        region: AWS region for the bucket
    
    Returns:
        bool: True if successful, False otherwise
    """
    s3_client = boto3.client('s3', region_name=region)
    
    try:
        print(f"Creating S3 bucket: {bucket_name}")
        
        try:
            if region == 'us-east-1':
                s3_client.create_bucket(Bucket=bucket_name)
            else:
                s3_client.create_bucket(
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
        s3_client.put_bucket_encryption(
            Bucket=bucket_name,
            ServerSideEncryptionConfiguration=encryption_config
        )
        print("[OK] Server-side encryption (AES256) enabled")
        
        print("Blocking public access...")
        s3_client.put_public_access_block(
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
        s3_client.put_bucket_lifecycle_configuration(
            Bucket=bucket_name,
            LifecycleConfiguration=lifecycle_config
        )
        print("[OK] Lifecycle policy attached (transition to Glacier after 90 days)")
        
        print("Attaching CloudTrail bucket policy...")
        account_id = boto3.client('sts').get_caller_identity()['Account']
        
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
        
        s3_client.put_bucket_policy(
            Bucket=bucket_name,
            Policy=json.dumps(bucket_policy)
        )
        print("[OK] CloudTrail bucket policy attached")
        
        return True
        
    except ClientError as e:
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
    cloudtrail_client = boto3.client('cloudtrail', region_name=region)
    
    try:
        print(f"\nCreating CloudTrail: {trail_name}")
        
        response = cloudtrail_client.create_trail(
            Name=trail_name,
            S3BucketName=bucket_name,
            IsMultiRegionTrail=True,
            EnableLogFileValidation=True,
            IncludeGlobalServiceEvents=True
        )
        print(f"[OK] CloudTrail '{trail_name}' created successfully")
        
        print("Starting CloudTrail logging...")
        cloudtrail_client.start_logging(Name=trail_name)
        print("[OK] CloudTrail logging started")
        
        print(f"\n{'='*50}")
        print("CloudTrail Setup Complete!")
        print(f"{'='*50}")
        print(f"Trail ARN: {response['TrailARN']}")
        print(f"S3 Bucket: {bucket_name}")
        print(f"Log File Validation: Enabled")
        print(f"Multi-Region: Yes")
        print(f"Lifecycle: Objects move to Glacier after 90 days")
        
        return True
        
    except ClientError as e:
        print(f"[FAIL] Error creating CloudTrail: {e}")
        return False


def main():
    """Main function to set up CloudTrail with S3 bucket."""
    
    BUCKET_NAME = "akshit-cloudtrail-logs-4679" 
    TRAIL_NAME = "akshit-global-cloudtrail"
    REGION = "us-east-1"
    
    print("=" * 50)
    print("CloudTrail Setup with S3 Bucket")
    print("=" * 50)
    print(f"Bucket Name: {BUCKET_NAME}")
    print(f"Trail Name: {TRAIL_NAME}")
    print(f"Region: {REGION}")
    print("=" * 50 + "\n")
    if create_s3_bucket_for_cloudtrail(BUCKET_NAME, REGION):
        enable_cloudtrail(TRAIL_NAME, BUCKET_NAME, REGION)
    else:
        print("\n[FAIL] Failed to create S3 bucket. CloudTrail setup aborted.")


if __name__ == "__main__":
    main()
