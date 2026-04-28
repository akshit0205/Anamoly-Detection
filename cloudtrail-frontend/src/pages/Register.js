import React, { useState } from 'react';
import { registerTenant } from '../api';
import { useToast } from '../Toast';

const REGIONS = ['ap-south-1', 'us-east-1', 'us-west-2', 'eu-west-1', 'ap-southeast-1'];

const initial = {
  account_id: '',
  role_arn: '',
  region: 'ap-south-1',
  cloudtrail_bucket: '',
  output_bucket: '',
  email: '',
};

export default function Register() {
  const toast = useToast();
  const [form, setForm] = useState(initial);
  const [errors, setErrors] = useState({});
  const [submitting, setSubmitting] = useState(false);

  const set = (key, val) => {
    setForm(prev => ({ ...prev, [key]: val }));
    setErrors(prev => ({ ...prev, [key]: '' }));
  };

  const validate = () => {
    const e = {};
    if (!/^\d{12}$/.test(form.account_id)) e.account_id = 'Must be exactly 12 digits';
    if (!/^arn:aws:iam::\d{12}:role\/.+/.test(form.role_arn)) e.role_arn = 'Must match arn:aws:iam::<12-digits>:role/<name>';
    if (!form.region) e.region = 'Select a region';
    if (!form.cloudtrail_bucket.trim()) e.cloudtrail_bucket = 'Required';
    if (!form.output_bucket.trim()) e.output_bucket = 'Required';
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(form.email)) e.email = 'Invalid email address';
    setErrors(e);
    return Object.keys(e).length === 0;
  };

  const handleSubmit = async (ev) => {
    ev.preventDefault();
    if (!validate()) return;
    setSubmitting(true);
    try {
      const res = await registerTenant(form);
      toast(`Tenant registered successfully — Account ID: ${res.account_id}`, 'success');
      setForm(initial);
    } catch (err) {
      toast(`Registration failed: ${err.message}`, 'error');
    }
    setSubmitting(false);
  };

  return (
    <div>
      <div className="page-header">
        <h2>Register Tenant</h2>
        <p>Onboard a new AWS account for CloudTrail anomaly detection</p>
      </div>

      <div className="card" style={{ maxWidth: 720 }}>
        <form onSubmit={handleSubmit}>
          <div className="form-grid">
            {/* Account ID */}
            <div className="form-group">
              <label htmlFor="account_id">AWS Account ID</label>
              <input
                id="account_id"
                className={`form-input ${errors.account_id ? 'error' : ''}`}
                placeholder="123456789012"
                maxLength={12}
                value={form.account_id}
                onChange={e => set('account_id', e.target.value.replace(/\D/g, ''))}
              />
              {errors.account_id && <span className="form-error">{errors.account_id}</span>}
            </div>

            {/* Role ARN */}
            <div className="form-group">
              <label htmlFor="role_arn">IAM Role ARN</label>
              <input
                id="role_arn"
                className={`form-input ${errors.role_arn ? 'error' : ''}`}
                placeholder="arn:aws:iam::123456789012:role/MyRole"
                value={form.role_arn}
                onChange={e => set('role_arn', e.target.value)}
              />
              {errors.role_arn && <span className="form-error">{errors.role_arn}</span>}
            </div>

            {/* Region */}
            <div className="form-group">
              <label htmlFor="region">AWS Region</label>
              <select
                id="region"
                className="form-select"
                value={form.region}
                onChange={e => set('region', e.target.value)}
              >
                {REGIONS.map(r => <option key={r} value={r}>{r}</option>)}
              </select>
              {errors.region && <span className="form-error">{errors.region}</span>}
            </div>

            {/* Email */}
            <div className="form-group">
              <label htmlFor="email">Alert Email</label>
              <input
                id="email"
                type="email"
                className={`form-input ${errors.email ? 'error' : ''}`}
                placeholder="security@company.com"
                value={form.email}
                onChange={e => set('email', e.target.value)}
              />
              {errors.email && <span className="form-error">{errors.email}</span>}
            </div>

            {/* CloudTrail Bucket */}
            <div className="form-group">
              <label htmlFor="ct_bucket">CloudTrail S3 Bucket</label>
              <input
                id="ct_bucket"
                className={`form-input ${errors.cloudtrail_bucket ? 'error' : ''}`}
                placeholder="my-cloudtrail-logs"
                value={form.cloudtrail_bucket}
                onChange={e => set('cloudtrail_bucket', e.target.value)}
              />
              {errors.cloudtrail_bucket && <span className="form-error">{errors.cloudtrail_bucket}</span>}
            </div>

            {/* Output Bucket */}
            <div className="form-group">
              <label htmlFor="out_bucket">Output S3 Bucket</label>
              <input
                id="out_bucket"
                className={`form-input ${errors.output_bucket ? 'error' : ''}`}
                placeholder="my-anomaly-output"
                value={form.output_bucket}
                onChange={e => set('output_bucket', e.target.value)}
              />
              {errors.output_bucket && <span className="form-error">{errors.output_bucket}</span>}
            </div>

            {/* Submit */}
            <div className="form-group full" style={{ marginTop: 8 }}>
              <button className="btn btn-primary" type="submit" disabled={submitting}>
                {submitting ? <><span className="spinner" /> Registering…</> : 'Register Tenant'}
              </button>
            </div>
          </div>
        </form>
      </div>
    </div>
  );
}
