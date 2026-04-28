import argparse
import logging
from botocore.exceptions import ClientError, NoCredentialsError, PartialCredentialsError
from config.config_loader import AwsOperationError, aws_client, safe_aws_call


LOGGER = logging.getLogger(__name__)


def create_model_bucket(bucket_name, region='us-east-1'):
    """
    Create an S3 bucket for storing ML models.
    
    Args:
        bucket_name: Name of the S3 bucket
        region: AWS region
    
    Returns:
        bool: True if successful
    """
    try:
        s3_client = aws_client('s3', region)
        # Step 1: Create S3 Bucket
        print(f"Creating S3 bucket: {bucket_name}")
        
        try:
            if region == 'us-east-1':
                safe_aws_call('create model bucket', s3_client.create_bucket, Bucket=bucket_name)
            else:
                safe_aws_call(
                    'create model bucket with region constraint',
                    s3_client.create_bucket,
                    Bucket=bucket_name,
                    CreateBucketConfiguration={'LocationConstraint': region}
                )
            print(f"[OK] Bucket '{bucket_name}' created successfully")
        except ClientError as e:
            if e.response['Error']['Code'] in ['BucketAlreadyOwnedByYou', 'BucketAlreadyExists']:
                print(f"[OK] Bucket '{bucket_name}' already exists, continuing...")
            else:
                raise e
        
        # Step 2: Enable Server-Side Encryption
        print("Enabling server-side encryption...")
        safe_aws_call(
            'enable model bucket encryption',
            s3_client.put_bucket_encryption,
            Bucket=bucket_name,
            ServerSideEncryptionConfiguration={
                'Rules': [{
                    'ApplyServerSideEncryptionByDefault': {
                        'SSEAlgorithm': 'AES256'
                    },
                    'BucketKeyEnabled': True
                }]
            }
        )
        print("[OK] Server-side encryption enabled")
        
        # Step 3: Block Public Access
        print("Blocking public access...")
        safe_aws_call(
            'block model bucket public access',
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
        
        # Step 4: Enable Versioning
        print("Enabling versioning...")
        safe_aws_call(
            'enable model bucket versioning',
            s3_client.put_bucket_versioning,
            Bucket=bucket_name,
            VersioningConfiguration={'Status': 'Enabled'}
        )
        print("[OK] Versioning enabled")
        
        print(f"\n{'='*50}")
        print("Model Bucket Setup Complete!")
        print(f"{'='*50}")
        print(f"Bucket: {bucket_name}")
        print(f"Region: {region}")
        print(f"Encryption: AES256")
        print(f"Versioning: Enabled")
        
        return True
        
    except (ClientError, NoCredentialsError, PartialCredentialsError, AwsOperationError) as e:
        LOGGER.error('Failed to create/configure model bucket: %s', e)
        print(f"[FAIL] Error: {e}")
        return False


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(name)s %(message)s')
    parser = argparse.ArgumentParser(description='Create model bucket for anomaly model artifacts')
    parser.add_argument('--model-bucket', required=True, help='Model S3 bucket name')
    parser.add_argument('--region', required=True, help='AWS region')
    args = parser.parse_args()
    create_model_bucket(args.model_bucket, args.region)
