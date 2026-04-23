import boto3
from botocore.exceptions import ClientError
def create_model_bucket(bucket_name, region='us-east-1'):
    """
    Create an S3 bucket for storing ML models.
    
    Args:
        bucket_name: Name of the S3 bucket
        region: AWS region
    
    Returns:
        bool: True if successful
    """
    s3_client = boto3.client('s3', region_name=region)
    
    try:
        # Step 1: Create S3 Bucket
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
        except ClientError as e:
            if e.response['Error']['Code'] in ['BucketAlreadyOwnedByYou', 'BucketAlreadyExists']:
                print(f"[OK] Bucket '{bucket_name}' already exists, continuing...")
            else:
                raise e
        
        # Step 2: Enable Server-Side Encryption
        print("Enabling server-side encryption...")
        s3_client.put_bucket_encryption(
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
        
        # Step 4: Enable Versioning
        print("Enabling versioning...")
        s3_client.put_bucket_versioning(
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
        
    except ClientError as e:
        print(f"[FAIL] Error: {e}")
        return False


if __name__ == "__main__":
    BUCKET_NAME = "akshit-ml-models-4679"
    REGION = "us-east-1"
    
    create_model_bucket(BUCKET_NAME, REGION)
