# CloudTrail Anomaly Detection SaaS

## Architecture Overview
This project provides a multi-tenant CloudTrail anomaly detection pipeline for AWS accounts.

High-level architecture:
- User account configurations are stored in DynamoDB (`users` table).
- A FastAPI service registers and manages users and can trigger detection manually.
- Detection assumes each user role, reads CloudTrail logs from the user bucket, and finds anomalies.
- Anomalies are saved to user output buckets and alerts are sent via SES.
- Lambda handler supports event-driven execution when CloudTrail objects land in S3.

## Project Structure
- `config/`:
  Runtime config loading and AWS client helpers.
- `storage/`:
  DynamoDB table creation and CRUD operations for users.
- `auth/`:
  STS role assumption utilities.
- `detection/`:
  CloudTrail anomaly detection pipeline.
- `alerts/`:
  SES alert sender and alert dispatch flow (S3 + email).
- `api/`:
  FastAPI service endpoints.
- `lambda/`:
  Lambda entrypoint (`handler`) for S3-triggered processing.

## Setup
- Install dependencies:
```bash
pip install -r requirements.txt
```

- Environment variables required:
  - `SENDER_EMAIL`: SES-verified sender email address used for anomaly alerts.

- Create DynamoDB table:
```bash
python storage/create_table.py --region <aws-region>
```

- Run API locally:
```bash
uvicorn api.main:app --host 0.0.0.0 --port 8000 --reload
```

## API Endpoints
- `POST /register`
  Registers a user configuration.
- `GET /users`
  Lists all registered users.
- `GET /health`
  Health check endpoint.
- `POST /run/{account_id}`
  Runs detection and alert dispatch for a specific account.

## How It Works
1. Register user config through API (`/register`).
2. CloudTrail writes logs to the user bucket.
3. Lambda handler is triggered by S3 object create event.
4. System fetches user config, runs anomaly detection, and generates anomaly records.
5. Alerts are dispatched: anomalies saved to S3 and emails sent via SES.
