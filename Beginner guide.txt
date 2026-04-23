# 🛡️ CloudTrail Anomaly Detection System - Beginner's Guide

Welcome! This guide explains everything happening in this project in simple terms. By the end, you'll understand how we detect suspicious activity in AWS cloud environments using Machine Learning.

---

## 📋 Table of Contents

1. [What is This Project?](#what-is-this-project)
2. [Why Do We Need This?](#why-do-we-need-this)
3. [Key Concepts Explained](#key-concepts-explained)
4. [Project Architecture](#project-architecture)
5. [The Scripts Explained](#the-scripts-explained)
6. [How It All Works Together](#how-it-all-works-together)
7. [AWS Services Used](#aws-services-used)
8. [Running the Project](#running-the-project)
9. [What Happens Next?](#what-happens-next)

---

## 🎯 What is This Project?

This project is an **AI-powered security monitoring system** for AWS cloud. It automatically:

1. **Collects** all activity logs from your AWS account (who did what, when, from where)
2. **Analyzes** each action using Machine Learning to find suspicious behavior
3. **Alerts** you when something unusual happens

Think of it like a **security camera + AI brain** that watches your cloud 24/7 and knows what "normal" looks like.

---

## 🤔 Why Do We Need This?

### The Problem
Every action in AWS is logged - creating servers, accessing files, changing permissions, etc. A busy account generates **thousands of events per day**. Manually reviewing these is impossible!

### Real Threats We Detect

| Threat | Example | Why It's Dangerous |
|--------|---------|-------------------|
| **Stolen Credentials** | Someone logs in from a new country at 3 AM | Hackers often use stolen passwords |
| **Privilege Escalation** | A regular user suddenly creates admin accounts | Attacker trying to get more access |
| **Data Exfiltration** | Unusual download patterns from S3 buckets | Someone stealing your data |
| **Security Tampering** | CloudTrail logging is disabled | Attacker covering their tracks |
| **Crypto Mining** | New EC2 instances running unusual workloads | Hackers using your resources |

### Our Solution
Use **Isolation Forest** (a Machine Learning algorithm) to learn what "normal" looks like, then automatically flag anything unusual.

---

## 📚 Key Concepts Explained

### What is AWS CloudTrail?

CloudTrail is like a **CCTV recording** for your AWS account. It records EVERY action:

```
Who: user-akshit
What: Started a new EC2 server
When: 2026-02-03 10:30:45
Where (IP): 192.168.1.100
Result: Success
```

Every API call, every login, every change - it all gets recorded and saved to S3.

### What is S3?

**Simple Storage Service (S3)** is AWS's file storage. Think of it like Google Drive or Dropbox, but for your AWS account. We use it to store:
- CloudTrail logs (activity records)
- Our trained ML model
- Detection results

### What is Lambda?

**AWS Lambda** is "serverless computing." Instead of running a server 24/7, you give AWS your code, and it runs it only when needed. Benefits:
- 💰 **Pay only when it runs** (not idle time)
- ⚡ **Automatic scaling** (handles 1 or 1000 requests)
- 🔧 **No server management**

Our Lambda function wakes up whenever CloudTrail delivers new logs, analyzes them, and goes back to sleep.

### What is Isolation Forest?

It's a Machine Learning algorithm designed to find **outliers** (unusual data points).

**How it works (simplified):**
1. Imagine your normal events as a crowd of people standing together
2. An anomaly/attacker is someone standing far away from the crowd
3. Isolation Forest finds those "lonely" data points

```
Normal events:  ● ● ● ● ● ● ●
                  ● ● ● ● ●

Anomaly:                        ◆ ← This one is far away = suspicious!
```

---

## 🏗️ Project Architecture

```
                    ┌─────────────────────────────────────────────────┐
                    │                   YOUR AWS ACCOUNT               │
                    │                                                  │
   You do stuff →   │  ┌──────────┐    Records     ┌──────────────┐   │
   (create EC2,     │  │   AWS    │ ─────────────► │  CloudTrail  │   │
   access S3,       │  │ Services │    everything  │    Logs      │   │
   etc.)            │  └──────────┘                └──────┬───────┘   │
                    │                                     │           │
                    │                                     ▼           │
                    │                              ┌──────────────┐   │
                    │                              │  S3 Bucket   │   │
                    │                              │  (CloudTrail │   │
                    │  ┌──────────────┐            │    Logs)     │   │
                    │  │  S3 Bucket   │            └──────┬───────┘   │
                    │  │   (Models)   │                   │           │
                    │  │              │                   │ Triggers  │
                    │  │  📦 .pkl     │                   ▼           │
                    │  └──────┬───────┘            ┌──────────────┐   │
                    │         │                    │    Lambda    │   │
                    │         │ Loads model        │   Function   │   │
                    │         └───────────────────►│  (Detector)  │   │
                    │                              └──────┬───────┘   │
                    │                                     │           │
                    │              ┌──────────────────────┼───────┐   │
                    │              ▼                      ▼       │   │
                    │       ┌──────────────┐      ┌────────────┐  │   │
                    │       │  CloudWatch  │      │  S3 Bucket │  │   │
                    │       │    Logs      │      │ (Anomalies)│  │   │
                    │       └──────────────┘      └────────────┘  │   │
                    │                                             │   │
                    └─────────────────────────────────────────────────┘
```

---

## 📂 The Scripts Explained

### 1️⃣ cloudtrail_setup.py

**Purpose:** Set up the logging system

**What it does:**
1. Creates an S3 bucket to store CloudTrail logs
2. Enables encryption (so logs are secure)
3. Sets up lifecycle policy (old logs move to cheaper storage after 90 days)
4. Creates a CloudTrail "trail" that captures all AWS activity
5. Starts logging!

**Key code:**
```python
# Create encrypted bucket
s3_client.put_bucket_encryption(...)

# Move old logs to Glacier (cheaper storage) after 90 days
lifecycle_config = {
    'Rules': [{
        'Transitions': [{'Days': 90, 'StorageClass': 'GLACIER'}]
    }]
}

# Create and start CloudTrail
cloudtrail_client.create_trail(Name='my-trail', S3BucketName='my-bucket')
cloudtrail_client.start_logging(Name='my-trail')
```

---

### 2️⃣ create_model_bucket.py

**Purpose:** Create storage for our ML model

**What it does:**
1. Creates a separate S3 bucket just for models
2. Enables versioning (keeps history of model updates)
3. Enables encryption

**Why separate bucket?** 
- Models are updated frequently
- Different access permissions than logs
- Easier to manage

---

### 3️⃣ train_and_upload.py

**Purpose:** Train the AI brain and upload it to AWS

**What it does:**
1. **Generate training data** - Creates 10,000 fake "normal" CloudTrail events
2. **Extract features** - Converts events into numbers the AI can understand
3. **Train model** - Teaches Isolation Forest what "normal" looks like
4. **Upload to S3** - Saves the trained model to AWS

**Features we extract from each event:**

| Feature | What it means | Example |
|---------|---------------|---------|
| `api_name` | What action was performed | DescribeInstances, DeleteBucket |
| `service` | Which AWS service | EC2, S3, IAM |
| `source_ip` | Where the request came from | 10.0.1.15 |
| `user` | Who did it | user-akshit |
| `hour` | What time (0-23) | 14 (2 PM) |
| `is_root` | Was it the root account? | 0 or 1 |
| `is_error` | Did it fail? | 0 or 1 |

**Key code:**
```python
# Create the ML model
model = IsolationForest(
    n_estimators=100,      # Use 100 decision trees
    contamination=0.05,    # Expect ~5% anomalies
    random_state=42        # For reproducibility
)

# Train it on normal data
model.fit(features)

# Save and upload
pickle.dump(model_package, file)
s3_client.upload_file('model.pkl', 'bucket', 'models/model.pkl')
```

---

### 4️⃣ lambda_function.py

**Purpose:** The actual anomaly detector that runs in AWS

**What it does (when triggered):**
1. Downloads the CloudTrail log file from S3
2. Decompresses it (logs are gzipped)
3. For each event in the log:
   - Checks rule-based patterns (known bad things)
   - Runs ML prediction (unknown bad things)
   - Flags anomalies
4. Saves all anomalies to S3
5. Logs everything to CloudWatch

**Rule-based detection (things we ALWAYS flag):**

```python
SUSPICIOUS_APIS = [
    'DeleteTrail',      # Someone disabling logging? Very sus!
    'StopLogging',      # Same as above
    'CreateUser',       # New users = possible backdoor
    'CreateAccessKey',  # New credentials = possible persistence
    'DeleteBucket',     # Destroying evidence?
    'RunInstances',     # Spinning up servers = crypto mining?
]
```

**ML-based detection:**
```python
# Get model's opinion (-1 = anomaly, 1 = normal)
prediction = model.predict([features])

if prediction == -1:
    flag_as_anomaly("ML detected unusual pattern")
```

---

### 5️⃣ deploy_lambda.py

**Purpose:** Deploy everything to AWS automatically

**What it does:**
1. Creates an IAM role (permissions for Lambda)
2. Packages the Lambda code into a ZIP file
3. Creates/updates the Lambda function
4. Sets up the S3 trigger (so Lambda runs when logs arrive)

**The trigger setup:**
```python
notification_config = {
    'LambdaFunctionConfigurations': [{
        'LambdaFunctionArn': function_arn,
        'Events': ['s3:ObjectCreated:*'],  # When any new file is created
        'Filter': {
            'Key': {
                'FilterRules': [
                    {'Name': 'prefix', 'Value': 'AWSLogs/'},  # In this folder
                    {'Name': 'suffix', 'Value': '.json.gz'}   # With this extension
                ]
            }
        }
    }]
}
```

---

## 🔄 How It All Works Together

### The Complete Flow

```
1. YOU DO SOMETHING IN AWS
   └── Example: aws ec2 run-instances (start a server)
            │
            ▼
2. CloudTrail RECORDS IT
   └── Writes: {who, what, when, where, result} to S3
            │
            ▼
3. S3 RECEIVES THE LOG FILE
   └── File: AWSLogs/123456789/CloudTrail/.../log.json.gz
            │
            ▼
4. S3 TRIGGERS LAMBDA
   └── "Hey Lambda, new file arrived!"
            │
            ▼
5. LAMBDA WAKES UP
   └── Downloads the log file
   └── Loads the ML model from S3
            │
            ▼
6. LAMBDA ANALYZES EACH EVENT
   └── Rule check: Is this a known dangerous API?
   └── ML check: Does this look unusual compared to training data?
            │
            ▼
7. ANOMALIES ARE SAVED
   └── Written to: s3://bucket/anomalies/2026/02/03/results.json
   └── Logged to: CloudWatch logs
            │
            ▼
8. YOU CAN SEE THE RESULTS
   └── Check S3 for anomaly files
   └── Check CloudWatch for Lambda logs
```

---

## ☁️ AWS Services Used

| Service | What We Use It For | Cost |
|---------|-------------------|------|
| **CloudTrail** | Record all AWS activity | Free (first trail) |
| **S3** | Store logs, models, results | ~$0.023/GB/month |
| **Lambda** | Run anomaly detection | Free tier: 1M requests/month |
| **IAM** | Permissions and roles | Free |
| **CloudWatch** | Logs and monitoring | Free tier available |

### Monthly Cost Estimate (Small Account)
- CloudTrail: **Free** (first trail)
- S3 (10GB logs): **~$0.25**
- Lambda (1000 invocations): **Free**
- **Total: Less than $1/month!**

---

## 🚀 Running the Project

### Prerequisites

```bash
# 1. Install Python dependencies
pip install boto3 scikit-learn numpy

# 2. Configure AWS credentials
aws configure
# Enter your AWS Access Key, Secret Key, Region (us-east-1)
```

### Step-by-Step Execution

```bash
# Step 1: Set up CloudTrail (already done!)
python cloudtrail_setup.py

# Step 2: Create model bucket
python create_model_bucket.py

# Step 3: Train and upload model
python train_and_upload.py

# Step 4: Deploy Lambda
python deploy_lambda.py

# Step 5: Wait for logs (15-30 minutes)
# CloudTrail delivers logs periodically, not instantly

# Step 6: Check results
aws s3 ls s3://akshit-cloudtrail-logs-4679/anomalies/ --recursive
```

---

## 🔮 What Happens Next?

### After Deployment

1. **CloudTrail delivers logs** every 15-30 minutes
2. **Lambda automatically runs** and analyzes them
3. **Anomalies appear** in S3 and CloudWatch

### Checking Results

**View Lambda invocations:**
```bash
aws logs filter-log-events \
  --log-group-name /aws/lambda/cloudtrail-anomaly-detector \
  --region us-east-1
```

**View anomaly files:**
```bash
aws s3 ls s3://akshit-cloudtrail-logs-4679/anomalies/ --recursive
```

**Download an anomaly report:**
```bash
aws s3 cp s3://akshit-cloudtrail-logs-4679/anomalies/2026/02/03/12/file.json ./
```

### Sample Anomaly Output

```json
{
  "source_log": "AWSLogs/467968377795/CloudTrail/us-east-1/2026/02/03/log.json.gz",
  "analyzed_at": "2026-02-03T12:30:45.123Z",
  "total_anomalies": 3,
  "anomalies": [
    {
      "eventId": "abc-123",
      "eventTime": "2026-02-03T12:15:30Z",
      "eventName": "DeleteTrail",
      "sourceIPAddress": "45.33.32.156",
      "is_anomaly": true,
      "anomaly_reasons": ["Suspicious API: DeleteTrail"]
    }
  ]
}
```

---

## 📖 Glossary

| Term | Definition |
|------|------------|
| **API** | Application Programming Interface - how programs talk to each other |
| **Anomaly** | Something unusual or unexpected |
| **Boto3** | Python library for interacting with AWS |
| **CloudTrail** | AWS service that logs all account activity |
| **Contamination** | ML term: expected percentage of anomalies in data |
| **IAM** | Identity and Access Management - AWS permissions system |
| **Isolation Forest** | ML algorithm for anomaly detection |
| **Lambda** | AWS serverless computing service |
| **S3** | Simple Storage Service - AWS file storage |
| **Trigger** | Event that causes something else to happen |

---

## 🎉 Congratulations!

You now understand how to build an AI-powered cloud security system! This project demonstrates:

- ✅ Cloud infrastructure setup with Boto3
- ✅ Machine Learning for anomaly detection
- ✅ Serverless architecture with Lambda
- ✅ Event-driven processing with S3 triggers
- ✅ Real-world security monitoring

**Questions?** Check the AWS documentation or the individual script files for more details!
