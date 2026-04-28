# Codebase Context

## System Overview
CloudTrail Guard — CloudTrail anomaly detection SaaS backend + frontend dashboard.
Detects sensitive AWS API calls across CloudTrail logs stored in S3, scores them 
by severity, and alerts via SES email.

## Infrastructure
- S3 Bucket: cloudtrail-logs-akshit-2202
- Log path: AWSLogs/836471808982/CloudTrail/{region}/{year}/{month}/{day}/*.json.gz
- Anomaly output path: anomalies/836471808982/
- IAM Role: CloudTrailRole (session: CloudTrailAnomalySession)
- SES sender: akshitsharma02003@gmail.com (env var: SENDER_EMAIL)
- SES limit: 200/day, resets 5:30 AM IST

## Tenants
- 836471808982 — akshitsharma02003@gmail.com — ap-south-1 — FULLY WORKING ✅
- 485849269108 — sbisht2703@gmail.com — ap-south-1 — S3 permission pending ⏳
  (partner needs to add CloudTrailGuardAccess inline policy to CloudTrailRole)

## Completed Features
- STS role assumption via CloudTrailRole ✅
- S3 read (GetObject, ListBucket) ✅
- S3 write to anomalies/* (PutObject) ✅
- CloudTrail log ingestion with date-scoped prefix (today + yesterday) ✅
- Anomaly detection across 57 sensitive events ✅
- Severity scoring: critical / high / medium / low ✅
- Deduplication via seen_events set ✅
- File cap: MAX_FILES=50 ✅
- SES email alerting ✅
- Full anomalies array in API response ✅
- Debug prints removed ✅
- Whitelist for own detector role + AWSService (no false positives) ✅
- API key authentication via X-API-Key header (default: dev-secret-key) ✅
- Anomaly persistence to S3 under anomalies/{account_id}/{timestamp}.json ✅
- Multi-tenant support via config/tenants.py ✅
- Frontend dashboard (React, localhost:3000) ✅
- Run Detection button per tenant with live results ✅
- Register Tenant form ✅
- Live detection rules count from backend (/rules/count) ✅ — shows 57
- API health check on dashboard ✅

## Detection Coverage
Categories: IAM, EC2, S3, CloudTrail, Auth, Network, KMS
Total events monitored: 57
Severity logic:
- critical: root user activity
- high: DeleteTrail, StopLogging, DeleteUser, DeleteRole, DeleteBucket,
         AuthorizeSecurityGroupIngress, UpdateTrail, DeletePolicy
- medium: CreateUser, CreateRole, AttachRolePolicy, DetachRolePolicy,
          PutRolePolicy, AddUserToGroup, RemoveUserFromGroup,
          AssumeRole, ConsoleLogin
- low: AccessDenied errors, everything else

## API
- Framework: FastAPI + uvicorn
- Auth: X-API-Key header (API_KEY env var, default: dev-secret-key)
- Endpoints:
  - POST /run/{account_id} → runs detection, returns account_id, anomalies_found, anomalies[]
  - GET /health → system health check
  - GET /users → list registered tenants
  - POST /register → register new tenant
  - GET /rules/count → returns live count of detection rules
- Docs: http://127.0.0.1:8000/docs

## Anomaly Object Schema
{
  "account_id": "string",
  "event_name": "string",
  "username": "string",
  "reason": "string",
  "timestamp": "ISO8601",
  "severity": "critical | high | medium | low"
}

## Frontend
- Stack: React, localhost:3000
- API helper: cloudtrail-frontend/src/api.js
  - All requests include X-API-Key header
  - BASE = http://localhost:8000
- Pages: Dashboard, Register Tenant, Tenants, How It Works
- Dashboard stats: System Online, Registered Tenants (live), Detection Rules (live from /rules/count)

## Tomorrow Before Panel
- Partner adds CloudTrailGuardAccess inline policy to his CloudTrailRole (5 min)
- Trigger demo events via AWS CLI to show real anomalies:
  aws iam create-user --user-name demo-user-1
  aws iam create-access-key --user-name demo-user-1
  aws iam delete-access-key --user-name demo-user-1 --access-key-id <key-id>
  aws iam delete-user --user-name demo-user-1
- Wait 15 min for CloudTrail delivery, then run detection
- SES quota resets 5:30 AM IST — email alerts resume

## Not Started / Future
- Scheduler (APScheduler) for auto-runs every 15 min
- Remove .env dependency → full env var / Secrets Manager
- Slack / PagerDuty webhook alerts
- Per-tenant whitelist tuning
- Severity burst escalation
- Structured JSON logging
- Anomaly history page on frontend

## Key Variable Names in pipeline.py (for safe patching)
- s3_client: boto3 S3 client
- bucket_name: the S3 bucket string
- account_id: passed into run_detection
- anomalies: list of anomaly dicts
- seen_events: dedup set
