import argparse
import json
import logging
import os
import pickle
import random
from datetime import datetime, timedelta

import numpy as np
from botocore.exceptions import ClientError, NoCredentialsError, PartialCredentialsError
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder

from config.config_loader import AwsOperationError, aws_client, safe_aws_call


LOGGER = logging.getLogger(__name__)


def generate_training_data(n_samples=10000):
    """Generate synthetic CloudTrail-like training data for normal behavior."""
    if n_samples <= 0:
        raise ValueError('n_samples must be greater than 0')

    print(f"Generating {n_samples} synthetic training events...")

    normal_apis = [
        'DescribeInstances', 'ListBuckets', 'GetObject', 'PutObject',
        'DescribeSecurityGroups', 'DescribeVpcs', 'ListUsers', 'GetUser',
        'DescribeRegions', 'ListRoles', 'AssumeRole', 'GetCallerIdentity'
    ]
    normal_services = ['ec2', 's3', 'iam', 'sts', 'lambda', 'cloudwatch']
    normal_hours = list(range(9, 18))
    normal_ips = [f"10.0.{random.randint(1, 255)}.{random.randint(1, 255)}" for _ in range(20)]

    events = []
    base_time = datetime.now()
    for _ in range(n_samples):
        event = {
            'eventTime': (base_time - timedelta(days=random.randint(0, 30), hours=random.randint(0, 23))).isoformat(),
            'eventSource': random.choice(normal_services) + '.amazonaws.com',
            'eventName': random.choice(normal_apis),
            'sourceIPAddress': random.choice(normal_ips),
            'userAgent': 'aws-sdk-python/1.0',
            'userIdentity': {
                'type': 'IAMUser',
                'userName': f"user{random.randint(1, 5)}"
            },
            'errorCode': None,
            'hour': random.choice(normal_hours),
            'is_root': 0,
            'is_error': 0
        }
        events.append(event)

    print(f"[OK] Generated {len(events)} training events")
    return events


def extract_features(events):
    """Extract numerical features from CloudTrail events."""
    if not events:
        raise ValueError('events must contain at least one event')

    print('Extracting features from events...')

    api_encoder = LabelEncoder()
    service_encoder = LabelEncoder()
    ip_encoder = LabelEncoder()
    user_encoder = LabelEncoder()

    apis = [e.get('eventName', 'Unknown') for e in events]
    services = [e.get('eventSource', 'unknown.amazonaws.com').replace('.amazonaws.com', '') for e in events]
    ips = [e.get('sourceIPAddress', 'unknown') for e in events]
    users = [e.get('userIdentity', {}).get('userName', 'unknown') for e in events]

    api_encoder.fit(apis)
    service_encoder.fit(services)
    ip_encoder.fit(ips)
    user_encoder.fit(users)

    features = []
    for event in events:
        event_time = event.get('eventTime', datetime.utcnow().isoformat())
        hour = int(event.get('hour', datetime.fromisoformat(event_time.replace('Z', '')).hour))
        feature_vector = [
            api_encoder.transform([event.get('eventName', 'Unknown')])[0],
            service_encoder.transform([event.get('eventSource', 'unknown.amazonaws.com').replace('.amazonaws.com', '')])[0],
            ip_encoder.transform([event.get('sourceIPAddress', 'unknown')])[0],
            user_encoder.transform([event.get('userIdentity', {}).get('userName', 'unknown')])[0],
            hour,
            event.get('is_root', 0),
            event.get('is_error', 0),
        ]
        features.append(feature_vector)

    encoders = {
        'api': api_encoder,
        'service': service_encoder,
        'ip': ip_encoder,
        'user': user_encoder,
    }

    print(f"[OK] Extracted {len(features[0])} features per event")
    return np.array(features), encoders


def train_model(features):
    """Train an Isolation Forest model for anomaly detection."""
    print('Training Isolation Forest model...')
    model = IsolationForest(
        n_estimators=100,
        contamination=0.05,
        random_state=42,
        n_jobs=-1,
    )
    model.fit(features)
    print('[OK] Model trained successfully')
    return model


def _upload_model_artifacts(s3_client, local_path, bucket_name):
    safe_aws_call(
        'upload trained model artifact',
        s3_client.upload_file,
        local_path,
        bucket_name,
        'models/cloudtrail_anomaly_model.pkl',
        ExtraArgs={'ServerSideEncryption': 'AES256'},
    )


def save_and_upload(model, encoders, bucket_name, region='us-east-1'):
    """Save model and encoders locally, then upload to S3."""
    print('\nSaving model and encoders...')

    model_package = {
        'model': model,
        'encoders': encoders,
        'version': '1.0',
        'trained_at': datetime.now().isoformat(),
        'features': ['api', 'service', 'ip', 'user', 'hour', 'is_root', 'is_error'],
    }

    local_path = 'cloudtrail_anomaly_model.pkl'
    with open(local_path, 'wb') as model_file:
        pickle.dump(model_package, model_file)

    file_size = os.path.getsize(local_path)
    print(f"[OK] Model saved locally: {local_path} ({file_size / 1024:.2f} KB)")
    print(f"Uploading to S3: s3://{bucket_name}/models/cloudtrail_anomaly_model.pkl")

    try:
        s3_client = aws_client('s3', region)
        _upload_model_artifacts(s3_client, local_path, bucket_name)
        print('[OK] Model uploaded to S3 successfully')

        metadata = {
            'version': '1.0',
            'trained_at': datetime.now().isoformat(),
            'features': ['api', 'service', 'ip', 'user', 'hour', 'is_root', 'is_error'],
            'model_type': 'IsolationForest',
            'contamination': 0.05,
        }

        safe_aws_call(
            'upload model metadata',
            s3_client.put_object,
            Bucket=bucket_name,
            Key='models/model_metadata.json',
            Body=json.dumps(metadata, indent=2),
            ContentType='application/json',
            ServerSideEncryption='AES256',
        )
        print('[OK] Model metadata uploaded')
    except (ClientError, NoCredentialsError, PartialCredentialsError, AwsOperationError) as exc:
        LOGGER.error('Model upload failed: %s', exc)
        print(f"[FAIL] Upload error: {exc}")
        raise
    except OSError as exc:
        LOGGER.error('Local model file operation failed: %s', exc)
        print(f"[FAIL] Local file error: {exc}")
        raise


def main():
    parser = argparse.ArgumentParser(description='Train anomaly model and upload to S3')
    parser.add_argument('--model-bucket', required=True, help='Model S3 bucket name')
    parser.add_argument('--region', required=True, help='AWS region')
    parser.add_argument('--samples', type=int, default=10000, help='Synthetic training sample count')
    args = parser.parse_args()

    print('=' * 50)
    print('CloudTrail Anomaly Detection - Model Training')
    print('=' * 50 + '\n')

    events = generate_training_data(n_samples=args.samples)
    features, encoders = extract_features(events)
    model = train_model(features)
    save_and_upload(model, encoders, args.model_bucket, args.region)

    print('\n' + '=' * 50)
    print('Model Training & Upload Complete!')
    print('=' * 50)
    print(f"Model: s3://{args.model_bucket}/models/cloudtrail_anomaly_model.pkl")


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(name)s %(message)s')
    try:
        main()
    except Exception as exc:
        LOGGER.exception('Training pipeline failed: %s', exc)
        raise
