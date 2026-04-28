You are an expert AWS + Python backend engineer. Modify this existing CloudTrail anomaly detection project into a multi-tenant SaaS system with email alerting.

Follow instructions step-by-step. Do NOT skip steps. Keep code modular and production-ready.

---

## CONTEXT

Current system:

* Python + boto3
* Lambda triggered by S3 (CloudTrail logs)
* Uses .env for config (single account only)
* Detects anomalies using:

  * Rule-based checks
  * Optional Isolation Forest ML
* Outputs anomalies to S3 + logs to CloudWatch

---

## TASK 1: REMOVE .env DEPENDENCY

* Remove all usage of dotenv or static config
* Replace with dynamic config loaded per user
* Create a config loader that accepts:

  * account_id
  * role_arn
  * region
  * cloudtrail_bucket
  * output_bucket
  * email

---

## TASK 2: ADD DYNAMODB STORAGE

* Create DynamoDB table: "users"
* Schema:

  * account_id (PK)
  * role_arn
  * region
  * cloudtrail_bucket
  * output_bucket
  * email
* Write helper functions:

  * save_user()
  * get_user(account_id)
  * list_users()

---

## TASK 3: IMPLEMENT STS ROLE ASSUMPTION

* Create module: auth/sts.py
* Function:
  assume_role(role_arn)
* Use boto3 STS to return temporary credentials
* Ensure all AWS clients use assumed credentials

---

## TASK 4: REFRACTOR DETECTION PIPELINE

* Modify detection logic to:

  * Accept user config dynamically
  * Work per account (no shared globals)
* Ensure:

  * S3 reads use assumed role
  * Output stored in correct user bucket/prefix

---

## TASK 5: ADD EMAIL ALERTING (AWS SES)

* Create module: alerts/email.py
* Function:
  send_anomaly_email(to_email, anomaly_data)
* Use AWS SES (boto3)
* Email must include:

  * Event name
  * User identity
  * Reason
  * Timestamp
* Add error handling (email failure should not crash system)

---

## TASK 6: INTEGRATE ALERT INTO PIPELINE

* When anomaly detected:

  * Save to S3
  * Send email alert

---

## TASK 7: CREATE FASTAPI SERVICE

* Create api/main.py
* Endpoints:

POST /register

* Input:
  account_id, role_arn, region, buckets, email
* Save to DynamoDB

GET /users

* Return all users

GET /health

* Return status

---

## TASK 8: PROJECT STRUCTURE

Refactor into:

* auth/
* detection/
* alerts/
* api/
* storage/
* lambda/

---

## TASK 9: SECURITY

* Use least privilege policies
* Validate all inputs
* Restrict role assumption to specific account IDs

---

## TASK 10: OUTPUT FORMAT

Each anomaly must be JSON:

{
"account_id": "...",
"event": "...",
"user": "...",
"reason": "...",
"timestamp": "...",
"severity": "high|medium|low"
}

---

## CONSTRAINTS

* Use Python + boto3 only
* Keep Lambda compatible
* Keep functions small and testable
* Do NOT break existing detection logic

---

## FINAL OUTPUT

* Updated code files
* New modules added
* Instructions to deploy
* Example IAM role trust policy
* SES setup instructions

---

Work step-by-step. Generate code incrementally for each task.
