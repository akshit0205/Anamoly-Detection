# Copilot Instructions for This Repository

## Project Context
This repository implements an AWS CloudTrail anomaly detection pipeline.

High-level flow:
1. Configure CloudTrail and an S3 log bucket.
2. Create a separate S3 bucket for ML model artifacts.
3. Train an Isolation Forest model locally on synthetic CloudTrail-like events.
4. Upload model artifacts to S3.
5. Deploy a Lambda function that is triggered by new CloudTrail log objects in S3.
6. Parse events, run rule-based and optional ML-based anomaly detection, and store anomaly output in S3.

Core scripts:
- cloudtrail_setup.py: Creates and configures CloudTrail log storage and trail.
- create_model_bucket.py: Creates and configures model artifact bucket.
- train_and_upload.py: Generates training data, trains model, uploads model and metadata.
- lambda_function.py: Runtime detector for CloudTrail records.
- deploy_lambda.py: Creates IAM role, deploys Lambda package, configures S3 trigger.

## Tech Stack
- Language: Python 3.11 (Lambda runtime in deployment script)
- AWS SDK: boto3
- ML/Data: scikit-learn, numpy (pandas is optional for local analysis)
- AWS services: S3, CloudTrail, Lambda, IAM, CloudWatch Logs, STS
- Serialization/storage: pickle for model package, JSON for metadata and anomaly outputs

Dependencies are defined in requirements.txt:
- boto3>=1.26.0
- scikit-learn>=1.0.0
- numpy>=1.21.0
- pandas>=1.3.0 (optional)

## Build and Run Steps
Prerequisites:
- Python 3.11+
- AWS account and credentials configured (for example via AWS CLI profile or environment variables)
- Permission to manage S3, CloudTrail, IAM, Lambda, and CloudWatch resources

Local setup:
1. Create and activate virtual environment.
2. Install dependencies with pip install -r requirements.txt.

Suggested execution order:
1. python cloudtrail_setup.py
2. python create_model_bucket.py
3. python train_and_upload.py
4. python deploy_lambda.py

Validation checks:
- Confirm CloudTrail is delivering logs into the configured S3 bucket.
- Confirm Lambda is deployed and has an S3 object-created trigger for AWSLogs/*.json.gz.
- Confirm anomaly outputs appear under anomalies/ in the CloudTrail bucket.
- Use CloudWatch Logs to inspect processing and anomaly detection behavior.

## Coding Style and Conventions
Follow existing repository conventions unless a task explicitly requires refactoring.

General style:
- Use small, task-focused functions with clear names.
- Keep module-level configuration constants in uppercase.
- Use docstrings for public functions describing purpose, args, and return values.
- Keep script entry points behind if __name__ == "__main__": main().

Operational behavior:
- Prefer explicit status logging via print statements.
- Use consistent status markers like [OK], [WARN], and [FAIL].
- Wrap AWS API calls in try/except and handle idempotency cases (resource already exists).
- Return simple success/failure values for setup utilities where practical.

AWS and security patterns:
- Default to server-side encryption for S3 objects/buckets.
- Block public access on created buckets.
- Keep least-privilege IAM permissions in deploy scripts where possible.
- Avoid hardcoding account-specific names for reusable code; prefer environment variables or parameters.

ML pipeline patterns:
- Keep feature extraction deterministic and aligned between training and inference.
- Store model and encoder metadata together.
- Handle unknown categorical values safely during inference.

## Guidance for Future Changes
- Preserve current script-first workflow (setup scripts + deployed Lambda runtime).
- Prefer incremental changes over large redesigns.
- If changing bucket names, regions, or resource names, update all dependent scripts consistently.
- If changing feature engineering or model schema, update both train_and_upload.py and lambda_function.py together.
- Keep outputs JSON-serializable and easy to inspect in CloudWatch and S3.
