import boto3
import pickle
import numpy as np
import os
from datetime import datetime, timedelta
import random
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder
import json


def generate_training_data(n_samples=10000):
    """
    Generate synthetic CloudTrail-like training data for normal behavior.
    
    Returns:
        list: List of event dictionaries
    """
    print(f"Generating {n_samples} synthetic training events...")
    
    # Normal patterns
    normal_apis = [
        'DescribeInstances', 'ListBuckets', 'GetObject', 'PutObject',
        'DescribeSecurityGroups', 'DescribeVpcs', 'ListUsers', 'GetUser',
        'DescribeRegions', 'ListRoles', 'AssumeRole', 'GetCallerIdentity'
    ]
    
    normal_services = ['ec2', 's3', 'iam', 'sts', 'lambda', 'cloudwatch']
    
    # Simulate normal working hours (9 AM - 6 PM)
    normal_hours = list(range(9, 18))
    
    # Normal source IPs (internal)
    normal_ips = [f"10.0.{random.randint(1, 255)}.{random.randint(1, 255)}" for _ in range(20)]
    
    events = []
    base_time = datetime.now()
    
    for i in range(n_samples):
        hour = random.choice(normal_hours)
        event = {
            'eventTime': (base_time - timedelta(days=random.randint(0, 30), hours=random.randint(0, 23))).isoformat(),
            'eventSource': random.choice(normal_services) + '.amazonaws.com',
            'eventName': random.choice(normal_apis),
            'sourceIPAddress': random.choice(normal_ips),
            'userAgent': 'aws-sdk-python/1.0',
            'userIdentity': {
                'type': 'IAMUser',
                'userName': f'user{random.randint(1, 5)}'
            },
            'errorCode': None,
            'hour': hour,
            'is_root': 0,
            'is_error': 0
        }
        events.append(event)
    
    print(f"[OK] Generated {len(events)} training events")
    return events


def extract_features(events):
    """
    Extract numerical features from CloudTrail events.
    
    Args:
        events: List of event dictionaries
    
    Returns:
        numpy array of features, fitted encoders
    """
    print("Extracting features from events...")
    
    # Initialize encoders
    api_encoder = LabelEncoder()
    service_encoder = LabelEncoder()
    ip_encoder = LabelEncoder()
    user_encoder = LabelEncoder()
    
    # Collect all unique values
    apis = [e['eventName'] for e in events]
    services = [e['eventSource'].replace('.amazonaws.com', '') for e in events]
    ips = [e['sourceIPAddress'] for e in events]
    users = [e['userIdentity'].get('userName', 'unknown') for e in events]
    
    # Fit encoders
    api_encoder.fit(apis)
    service_encoder.fit(services)
    ip_encoder.fit(ips)
    user_encoder.fit(users)
    
    # Extract features
    features = []
    for e in events:
        hour = int(e.get('hour', datetime.fromisoformat(e['eventTime'].replace('Z', '')).hour))
        
        feature_vector = [
            api_encoder.transform([e['eventName']])[0],
            service_encoder.transform([e['eventSource'].replace('.amazonaws.com', '')])[0],
            ip_encoder.transform([e['sourceIPAddress']])[0],
            user_encoder.transform([e['userIdentity'].get('userName', 'unknown')])[0],
            hour,
            e.get('is_root', 0),
            e.get('is_error', 0)
        ]
        features.append(feature_vector)
    
    encoders = {
        'api': api_encoder,
        'service': service_encoder,
        'ip': ip_encoder,
        'user': user_encoder
    }
    
    print(f"[OK] Extracted {len(features[0])} features per event")
    return np.array(features), encoders


def train_model(features):
    """
    Train an Isolation Forest model for anomaly detection.
    
    Args:
        features: numpy array of features
    
    Returns:
        trained model
    """
    print("Training Isolation Forest model...")
    
    model = IsolationForest(
        n_estimators=100,
        contamination=0.05,  # Expect 5% anomalies
        random_state=42,
        n_jobs=-1
    )
    
    model.fit(features)
    
    print("[OK] Model trained successfully")
    return model


def save_and_upload(model, encoders, bucket_name, region='us-east-1'):
    """
    Save model and encoders, then upload to S3.
    
    Args:
        model: trained model
        encoders: dictionary of label encoders
        bucket_name: S3 bucket name
        region: AWS region
    """
    print("\nSaving model and encoders...")
    
    # Create model package
    model_package = {
        'model': model,
        'encoders': encoders,
        'version': '1.0',
        'trained_at': datetime.now().isoformat(),
        'features': ['api', 'service', 'ip', 'user', 'hour', 'is_root', 'is_error']
    }
    
    # Save locally first
    local_path = 'cloudtrail_anomaly_model.pkl'
    with open(local_path, 'wb') as f:
        pickle.dump(model_package, f)
    
    file_size = os.path.getsize(local_path)
    print(f"[OK] Model saved locally: {local_path} ({file_size / 1024:.2f} KB)")
    
    # Upload to S3
    print(f"Uploading to S3: s3://{bucket_name}/models/cloudtrail_anomaly_model.pkl")
    
    s3_client = boto3.client('s3', region_name=region)
    
    try:
        s3_client.upload_file(
            local_path,
            bucket_name,
            'models/cloudtrail_anomaly_model.pkl',
            ExtraArgs={'ServerSideEncryption': 'AES256'}
        )
        print(f"[OK] Model uploaded to S3 successfully")
        
        # Also upload metadata
        metadata = {
            'version': '1.0',
            'trained_at': datetime.now().isoformat(),
            'features': ['api', 'service', 'ip', 'user', 'hour', 'is_root', 'is_error'],
            'model_type': 'IsolationForest',
            'contamination': 0.05
        }
        
        s3_client.put_object(
            Bucket=bucket_name,
            Key='models/model_metadata.json',
            Body=json.dumps(metadata, indent=2),
            ContentType='application/json',
            ServerSideEncryption='AES256'
        )
        print("[OK] Model metadata uploaded")
        
    except Exception as e:
        print(f"[FAIL] Upload error: {e}")
        raise


def main():
    """Main function to train and upload the model."""
    
    BUCKET_NAME = "akshit-ml-models-4679"
    REGION = "us-east-1"
    
    print("=" * 50)
    print("CloudTrail Anomaly Detection - Model Training")
    print("=" * 50 + "\n")
    
    # Step 1: Generate training data
    events = generate_training_data(n_samples=10000)
    
    # Step 2: Extract features
    features, encoders = extract_features(events)
    
    # Step 3: Train model
    model = train_model(features)
    
    # Step 4: Save and upload
    save_and_upload(model, encoders, BUCKET_NAME, REGION)
    
    print("\n" + "=" * 50)
    print("Model Training & Upload Complete!")
    print("=" * 50)
    print(f"Model: s3://{BUCKET_NAME}/models/cloudtrail_anomaly_model.pkl")
    

if __name__ == "__main__":
    main()
