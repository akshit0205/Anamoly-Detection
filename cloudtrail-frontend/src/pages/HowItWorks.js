import React from 'react';

const steps = [
  { title: 'Tenant Registration',       desc: 'Tenant registers their AWS account with role ARN, S3 buckets, and alert email via the FastAPI backend.' },
  { title: 'CloudTrail Logging',         desc: 'AWS CloudTrail continuously logs all API activity and delivers log files to the tenant\'s S3 bucket.' },
  { title: 'S3 Event Trigger',           desc: 'New log files in S3 automatically trigger an AWS Lambda function for real-time processing.' },
  { title: 'Config Lookup',              desc: 'Lambda fetches tenant configuration (role ARN, buckets, email) from DynamoDB.' },
  { title: 'Cross-Account Access',       desc: 'Lambda assumes the tenant\'s IAM role via AWS STS to securely access their resources.' },
  { title: 'Anomaly Detection',          desc: 'Detection rules analyze CloudTrail events for suspicious patterns like root usage, sensitive API calls, and access denied errors.' },
  { title: 'Alert & Report',             desc: 'Detected anomalies are saved to the output S3 bucket and an email alert is dispatched via AWS SES.' },
];

const rules = [
  {
    title: '🔴 Root Account Usage',
    desc: 'Flags any API call made using the AWS root account, which should rarely be used in production environments.',
    severity: 'Critical',
  },
  {
    title: '🟡 Sensitive API Calls',
    desc: 'Detects destructive operations like Delete*, Stop*, and Terminate* that could indicate malicious activity or misconfigurations.',
    severity: 'High',
  },
  {
    title: '🟠 AccessDenied Errors',
    desc: 'Monitors for AccessDenied error codes which may indicate unauthorized access attempts or privilege escalation.',
    severity: 'Medium',
  },
];

const techStack = [
  'AWS CloudTrail', 'Amazon S3', 'AWS Lambda', 'Amazon DynamoDB',
  'AWS STS', 'Amazon SES', 'FastAPI', 'Python', 'boto3', 'React',
];

export default function HowItWorks() {
  return (
    <div>
      <div className="page-header">
        <h2>How It Works</h2>
        <p>End-to-end pipeline for automated CloudTrail anomaly detection</p>
      </div>

      {/* ── Pipeline ────────────────────────────── */}
      <div className="card mb-24">
        <h3 className="section-title">Detection Pipeline</h3>
        <div className="pipeline">
          {steps.map((s, i) => (
            <div className="pipeline-step" key={i}>
              <div className="step-dot">{i + 1}</div>
              <div className="step-content">
                <h4>{s.title}</h4>
                <p>{s.desc}</p>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* ── Detection Rules ─────────────────────── */}
      <h3 className="section-title">Detection Rules</h3>
      <div className="rule-cards mb-24">
        {rules.map((r, i) => (
          <div className="rule-card" key={i}>
            <h4>{r.title}</h4>
            <p>{r.desc}</p>
            <div style={{ marginTop: 12 }}>
              <span className="tech-tag" style={{
                color: r.severity === 'Critical' ? '#ef4444' : r.severity === 'High' ? '#f59e0b' : '#3b82f6',
                borderColor: r.severity === 'Critical' ? 'rgba(239,68,68,.3)' : r.severity === 'High' ? 'rgba(245,158,11,.3)' : 'rgba(59,130,246,.3)',
                background: r.severity === 'Critical' ? 'rgba(239,68,68,.1)' : r.severity === 'High' ? 'rgba(245,158,11,.1)' : 'rgba(59,130,246,.1)',
              }}>
                {r.severity} Severity
              </span>
            </div>
          </div>
        ))}
      </div>

      {/* ── Tech Stack ──────────────────────────── */}
      <div className="card">
        <h3 className="section-title">Technology Stack</h3>
        <div className="tech-grid">
          {techStack.map(t => (
            <span className="tech-tag" key={t}>{t}</span>
          ))}
        </div>
      </div>
    </div>
  );
}
