import React, { useState, useEffect, useCallback } from 'react';
import { getUsers, runDetection } from '../api';
import { useToast } from '../Toast';

export default function Tenants() {
  const toast = useToast();
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [runningId, setRunningId] = useState(null);
  const [modal, setModal] = useState(null); // { accountId, type, msg } | null

  const fetchUsers = useCallback(async () => {
    setLoading(true);
    try {
      const res = await getUsers();
      setUsers(res.users || []);
    } catch (err) {
      toast('Failed to load tenants: ' + err.message, 'error');
    }
    setLoading(false);
  }, [toast]);

  useEffect(() => { fetchUsers(); }, [fetchUsers]);

  const handleRun = async (accountId) => {
    setRunningId(accountId);
    try {
      const res = await runDetection(accountId);
      const count = res.anomalies_found;
      setModal({
        accountId,
        type: count > 0 ? 'warn' : 'success',
        msg: `Detection complete: ${count} anomal${count === 1 ? 'y' : 'ies'} found`,
      });
      toast(
        count > 0
          ? `${count} anomalies found for ${accountId}`
          : `No anomalies for ${accountId}`,
        count > 0 ? 'info' : 'success'
      );
    } catch (err) {
      setModal({ accountId, type: 'error', msg: err.message });
      toast('Detection failed: ' + err.message, 'error');
    }
    setRunningId(null);
  };

  const copyArn = (arn) => {
    navigator.clipboard.writeText(arn).then(() => toast('ARN copied to clipboard', 'success'));
  };

  const truncateArn = (arn) => {
    if (!arn) return '–';
    if (arn.length <= 35) return arn;
    return arn.slice(0, 20) + '…' + arn.slice(-12);
  };

  return (
    <div>
      <div className="page-header">
        <div className="flex-between">
          <div>
            <h2>Tenants</h2>
            <p>Manage all registered AWS accounts</p>
          </div>
          <button className="btn btn-outline" onClick={fetchUsers} disabled={loading}>
            {loading ? <span className="spinner spinner-blue" /> : '↻'} Refresh
          </button>
        </div>
      </div>

      {loading ? (
        <div className="empty-state">
          <div className="spinner spinner-lg spinner-blue" />
          <p style={{ marginTop: 16 }}>Loading tenants…</p>
        </div>
      ) : users.length === 0 ? (
        <div className="card">
          <div className="empty-state">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" style={{ width: 48, height: 48, opacity: .4 }}>
              <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2" /><circle cx="9" cy="7" r="4" />
            </svg>
            <h3>No tenants registered yet</h3>
            <p>Go to "Register Tenant" to onboard your first AWS account.</p>
          </div>
        </div>
      ) : (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Account ID</th>
                <th>Region</th>
                <th>CloudTrail Bucket</th>
                <th>Output Bucket</th>
                <th>Email</th>
                <th>Role ARN</th>
                <th style={{ textAlign: 'right' }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {users.map(u => (
                <tr key={u.account_id}>
                  <td style={{ fontWeight: 600 }}>{u.account_id}</td>
                  <td>{u.region}</td>
                  <td>{u.cloudtrail_bucket}</td>
                  <td>{u.output_bucket}</td>
                  <td>{u.email}</td>
                  <td>
                    <span className="arn-text">{truncateArn(u.role_arn)}</span>
                    <button className="copy-btn" onClick={() => copyArn(u.role_arn)} title="Copy full ARN">
                      📋 Copy
                    </button>
                  </td>
                  <td style={{ textAlign: 'right' }}>
                    <button
                      className="btn btn-primary btn-sm"
                      disabled={runningId === u.account_id}
                      onClick={() => handleRun(u.account_id)}
                    >
                      {runningId === u.account_id ? (
                        <><span className="spinner" /> Running…</>
                      ) : (
                        '▶ Run Detection'
                      )}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* ── Result Modal ──────────────────────── */}
      {modal && (
        <div className="modal-overlay" onClick={() => setModal(null)}>
          <div className="modal" onClick={e => e.stopPropagation()}>
            <div style={{ fontSize: 40, marginBottom: 12 }}>
              {modal.type === 'success' ? '✅' : modal.type === 'warn' ? '⚠️' : '❌'}
            </div>
            <h3>Detection Result</h3>
            <p>
              <strong>Account:</strong> {modal.accountId}<br />
              {modal.msg}
            </p>
            <button className="btn btn-primary" onClick={() => setModal(null)}>Close</button>
          </div>
        </div>
      )}
    </div>
  );
}
