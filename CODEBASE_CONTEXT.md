# Codebase Context

This document gives a concise file-by-file overview of the CloudTrail Anomaly Detection SaaS repository to help onboarding, review, and handoff.

## Top-level overview
- **Purpose**: multi-tenant CloudTrail anomaly detection with per-tenant config, role-assume, S3/Lambda ingestion, and SES alerts.
- **Runtime**: Python 3.11, boto3, FastAPI for control-plane.

## Key components

- **Configuration & AWS helpers**
  - config/config_loader.py — runtime config validation, `aws_client()` helper and `safe_aws_call()` wrapper.

- **Authentication / STS**
  - auth/sts_helper.py — `assume_role()` and `get_client_for_role()` which return temporary-credentials clients.

- **Storage (tenant configs)**
  - storage/create_table.py — script to create the DynamoDB `users` table.
  - storage/dynamodb_store.py — CRUD: `save_user()`, `get_user()`, `list_users()`, `delete_user()`.

- **Detection pipeline**
  - detection/pipeline.py — primary log-scanning code used by API and Lambda. (parses CloudTrail JSON, prefix-scoped S3 listing, rule-based checks, optional ML model inference, deduplication and file caps).

- **Alerts / dispatch**
  - alerts/ses_alerter.py — sends email alerts using SES.
  - alerts/alert_dispatcher.py — orchestrates writing anomaly JSON to S3 and invoking SES.

- **API (control-plane)**
  - api/main.py — FastAPI app exposing `/register`, `/users`, `/health`, and `/run/{account_id}` endpoints. Uses DynamoDB for tenant lookup and runs `run_detection()` + `dispatch_alerts()`.

- **Lambda / runtime**
  - lambda/handler.py — lightweight S3 event Lambda handler that extracts bucket/key, resolves tenant via DynamoDB, calls `run_detection()` and `dispatch_alerts()`.
  - lambda_function.py — an alternative (monolithic) Lambda implementation that includes model loading, parsing, and per-object anomaly output. Useful as a reference for Lambda runtime logic.

- **Deployment & utilities**
  - deploy_lambda.py — creates IAM role, zips and deploys Lambda, and configures S3 bucket notifications.
  - create_model_bucket.py — helper to create and configure an S3 model bucket.
  - train_and_upload.py — synthetic training data, model training with IsolationForest, and upload to S3.

- **Misc / docs**
  - README.md — high-level project and setup notes.
  - BEGINNERS_GUIDE.md / Beginner guide.txt — onboarding instructions and quickstart notes.
  - improvement.md — roadmap and recommended improvements.
  - requirements.txt — Python dependencies.

## Runtime interactions (high level)

1. Tenant registration: store tenant config in DynamoDB via `api/main.py:/register`.
2. Event ingestion: CloudTrail -> S3. S3 notifications call `lambda.handler` or manual `POST /run/{account_id}` triggers API run.
3. Detection: `detection.pipeline.run_detection()` (or `lambda_function._handle_event()` for monolithic lambda) assumes role, lists S3 objects (prefix-scoped), fetches objects, parses CloudTrail JSON, applies rule list and optional ML model, deduplicates findings.
4. Dispatch: `alerts.alert_dispatcher.dispatch_alerts()` writes anomaly JSON to tenant output bucket and calls SES to send email.

## Operational notes / known constraints

- STS / assume-role: Many flows use `auth/sts_helper.assume_role()`; if local credentials are root or improperly configured, assume-role may fail and result in zero scanned objects. Ensure non-root programmatic IAM user is configured for diagnostics.
- Scoping & limits: detection code contains prefix scoping, `PaginationConfig`, and `MAX_FILES` to limit S3 scanning. These are intentional for performance.
- Deduplication: detection uses a dedup key (eventName:user:errorCode) to avoid duplicate alerts for the same event.
- Environment vars required for API/Lambda: `SENDER_EMAIL` (SES verified sender) and AWS credentials or role attached to runtime.

## Current system status

- Severity field in output ✅
- Debug prints cleanup ✅
- Expanded detection rules (50+ events) ✅

## Next recommended tasks (handoff checklist)

- Verify DynamoDB `users` table exists (run `storage/create_table.py`).
- Create a programmatic IAM user for running local diagnostics (do not use root credentials).
- Verify `SENDER_EMAIL` is a verified SES sender for the target region before sending emails.
- Run `POST /run/{account_id}` with a tenant that has CloudTrail logs in the configured `cloudtrail_bucket` to validate end-to-end behaviour.
- Produce an integration test (pytest fixture) that runs detection on sample CloudTrail files in `realistic_indian_cloudtrail_logs.jsonl`.

## Where to look for behavior while debugging

- STS logs: `auth/sts_helper.py` emits ASSUME_ROLE_START / SUCCESS / FAILED log lines.
- Detection debug prints and structured logs in `detection/pipeline.py` (scan prefix, total_objects, per-event debug).
- Lambda logs (CloudWatch) for `lambda/handler.py` or `lambda_function.py` when invoked by S3.

## Anomaly output format example

Example anomaly object saved to S3 / returned by `/run`:

{
  "account_id": "123456789012",
  "event_name": "DeleteBucket",
  "username": "alice",
  "reason": "Sensitive API call detected: DeleteBucket",
  "timestamp": "2026-04-29T12:34:56Z",
  "severity": "high|medium|low|critical"
}

---

If you want, I can (pick one):

- generate a more exhaustive line-by-line CODEBASE_CONTEXT.md (longer, includes function signatures), or
- add a pytest that runs the detection pipeline against the sample logs, or
- run a diagnostics `POST /run/{account_id}` locally (you must confirm AWS credentials & SENDER_EMAIL are configured).
