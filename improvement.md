# Project Improvements Roadmap

This plan is tailored to the current repository and your active AWS-connected setup.

## Current Strengths
- Clear end-to-end pipeline: CloudTrail -> S3 -> Lambda -> anomaly outputs.
- Good baseline security controls in setup scripts (S3 encryption, public access block).
- Hybrid detection strategy (rule-based + ML) is a practical starting point.
- Script-first workflow is beginner-friendly and easy to run.

## Highest-Impact Improvements (Do First)

## 1) Remove hardcoded AWS resource names
Why:
- Current scripts hardcode bucket names, trail names, and region. This blocks reuse and is risky across accounts/environments.

What to change:
- Read config from environment variables and optional .env file.
- Keep safe defaults for local testing, but fail early if required values are missing in production mode.

Suggested config keys:
- AWS_REGION
- CLOUDTRAIL_BUCKET
- MODEL_BUCKET
- TRAIL_NAME
- LAMBDA_FUNCTION_NAME

Impact:
- Better portability, safer deployments, easier multi-environment setup.

## 2) Unify deployment and runtime code path
Why:
- deploy_lambda.py currently generates an inline rule-based lambda package, while lambda_function.py in repo contains ML + rule logic. This can cause behavior drift.

What to change:
- Deploy the actual lambda_function.py file from repo.
- Build package from source directory, not embedded string.
- Add an explicit switch: RULE_ONLY_MODE=true/false if you want fallback behavior.

Impact:
- Prevents mismatch between what you test locally and what runs in AWS.

## 3) Fix anomaly output write strategy
Why:
- The current Lambda loop keeps appending to all_anomalies and saves per file using cumulative list, which can duplicate anomalies across records.

What to change:
- Reset anomaly list per input object key.
- Save one output object per input log file.
- Include source bucket/key and event count in output metadata.

Impact:
- Correctness improvement and cleaner downstream analysis.

## 4) Add robust error handling with retry boundaries
Why:
- AWS operations can fail transiently. Current scripts rely heavily on broad try/except and print.

What to change:
- Use boto3 client config retries (standard/adaptive).
- Add targeted exception handling for S3, IAM, Lambda operations.
- Return explicit status codes/results from key functions.

Impact:
- More reliable automation and fewer intermittent failures.

## Security Improvements

## 5) Replace broad inline IAM policy with minimum required actions
Why:
- Least privilege reduces blast radius if credentials or function are misused.

What to change:
- Scope Lambda role access to exact buckets and exact prefixes where possible.
- Add explicit deny for non-required write paths if needed.
- Consider using managed policy + narrow inline statements.

## 6) Encrypt everything with KMS (optional but recommended)
Why:
- AES256 SSE-S3 is decent; KMS gives stronger key governance and auditability.

What to change:
- Use SSE-KMS for model and anomaly outputs.
- Add KMS key policy for Lambda and deployment principal.

## 7) Add secrets/config management discipline
Why:
- Prevent accidental leakage and configuration drift.

What to change:
- Move runtime config to Lambda environment variables.
- Keep sensitive values out of source code.
- Add .gitignore entries for local artifacts and temporary zips.

## Detection and ML Improvements

## 8) Improve feature engineering and model quality checks
Why:
- Isolation Forest quality depends strongly on features and drift handling.

What to change:
- Add features like event frequency per user/IP, API rarity, geo or ASN signal (if available), and service-specific patterns.
- Keep train/inference feature contract versioned.
- Store model metrics and training summary with each model version.

## 9) Add threshold calibration and severity scoring
Why:
- Binary anomaly labels are hard to operationalize.

What to change:
- Convert anomaly score to severity bands: low, medium, high, critical.
- Weight rule-based detections higher than weak ML outliers.
- Add suppression logic for known safe repetitive noise.

## 10) Add model lifecycle controls
Why:
- Models degrade with environment changes.

What to change:
- Version models in S3 with semantic tags.
- Add scheduled retraining job (for example monthly).
- Keep rollback pointer to previous known-good model.

## Observability and Operations

## 11) Move from print logs to structured JSON logs
Why:
- Easier querying and alerting in CloudWatch Logs Insights.

What to change:
- Use a consistent log schema: timestamp, level, request_id, source_key, event_id, detection_reason, score.
- Emit summary metrics at end of each invocation.

## 12) Publish CloudWatch custom metrics + alarms
Why:
- You need operational visibility and actionable alerting.

What to change:
- Metrics: events_processed, anomalies_detected, parse_failures, model_load_failures, invocation_duration.
- Alarms: high anomaly spike, repeated model load failures, Lambda error rate, throttles.

## 13) Add dead-letter or failure destination
Why:
- Failed events should not disappear silently.

What to change:
- Configure Lambda DLQ (SQS/SNS) or failure destination.
- Add runbook for replaying failed records.

## Cost and Performance Improvements

## 14) Optimize Lambda package and runtime behavior
Why:
- Faster cold starts and lower cost.

What to change:
- Use Lambda layers for heavy dependencies when needed.
- Cache model (already partially done) and avoid repeated S3 model downloads.
- Tune memory/timeouts using observed duration metrics.

## 15) Use S3 lifecycle and partitioning for anomaly outputs
Why:
- Keeps storage cost manageable over time.

What to change:
- Partition outputs by year/month/day/hour (already mostly present) and add lifecycle retention/transition.
- Keep a shorter retention window for high-volume raw outputs if compliance permits.

## Engineering Quality Improvements

## 16) Introduce IaC (Terraform or AWS CDK)
Why:
- Scripted resource creation is useful initially but harder to maintain and audit at scale.

What to change:
- Move S3, CloudTrail, Lambda, IAM, triggers, alarms to Infrastructure as Code.
- Keep scripts for one-off utilities only.

## 17) Add tests and local validation
Why:
- Prevent regressions in feature extraction and event parsing.

What to change:
- Unit tests for parse_cloudtrail_log, extract_features_for_event, analyze_event.
- Add fixtures for realistic CloudTrail samples.
- Add smoke test that runs Lambda handler with sample S3 event payload.

## 18) Add CI checks
Why:
- Catch quality issues before deployment.

What to change:
- Lint (ruff or flake8), format (black), tests (pytest).
- Optional: mypy for typed boundaries in critical functions.

## Recommended Execution Plan

Phase 1 (1-2 days):
- Remove hardcoded config.
- Unify deployment/runtime Lambda code path.
- Fix anomaly write strategy.
- Add structured logging basics.

Phase 2 (3-5 days):
- IAM least-privilege tightening.
- CloudWatch metrics + alarms.
- DLQ/failure destination.
- Tests + CI baseline.

Phase 3 (1-2 weeks):
- Feature and model quality improvements.
- Scheduled retraining and model versioning policy.
- Move infrastructure to Terraform/CDK.

## Optional Next Enhancements
- Add EventBridge notifications for critical anomalies.
- Send high-severity findings to Slack/Email/SIEM.
- Add analyst feedback loop for true positive/false positive labeling.

## Success Criteria
- Deployment is environment-driven and reproducible.
- Lambda output is deterministic and non-duplicated.
- Alerts are actionable with low operational noise.
- Model updates are versioned, measurable, and rollback-safe.
- Security posture follows least privilege and encrypted data-at-rest standards.
