import React, { useState, useEffect, useCallback } from 'react';
import { checkHealth, getUsers, runDetection, getRulesCount } from '../api';
import { useToast } from '../Toast';

export default function Dashboard() {
  const toast = useToast();
  const [health, setHealth] = useState(null);       // null = loading
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [runningId, setRunningId] = useState(null);
  const [results, setResults] = useState({});        // accountId → { type, msg }
  const [rulesCount, setRulesCount] = useState(50);

  const fetchData = useCallback(async () => {
    setLoading(true);
    try {
      const h = await checkHealth();
      setHealth(h.status === 'ok');
    } catch {
      setHealth(false);
    }
    try {
      const u = await getUsers();
      setUsers(u.users || []);
    } catch {
      setUsers([]);
    }
    try {
      const r = await getRulesCount();
      setRulesCount(r.count);
    } catch {
      setRulesCount(50);
    }
    setLoading(false);
  }, []);

  useEffect(() => { fetchData(); }, [fetchData]);

  const handleRun = async (accountId) => {
    setRunningId(accountId);
    setResults(prev => ({ ...prev, [accountId]: null }));
    try {
      const res = await runDetection(accountId);
      const count = res.anomalies_found;
      setResults(prev => ({
        ...prev,
        [accountId]: {
          type: count > 0 ? 'found' : 'clean',
          msg: count > 0 ? `${count} anomalies found` : 'No anomalies — all clear',
        },
      }));
      toast(
        count > 0
          ? `Detection complete: ${count} anomalies found for ${accountId}`
          : `No anomalies detected for ${accountId}`,
        count > 0 ? 'info' : 'success'
      );
    } catch (err) {
      setResults(prev => ({
        ...prev,
        [accountId]: { type: 'err', msg: err.message },
      }));
      toast(`Detection failed for ${accountId}: ${err.message}`, 'error');
    }
    setRunningId(null);
  };

  return (
    <div>
      <div className="page-header">
        <h2>Dashboard</h2>
        <p>Monitor your CloudTrail anomaly detection system</p>
      </div>

      {/* ── Status & Stats ──────────────────────── */}
      <div className="card-grid">
        <div className="card stat-card">
          <div className={`stat-icon ${health === true ? 'green' : health === false ? 'red' : 'blue'}`}>
            {health === null ? '⏳' : health ? '⚡' : '⚠'}
          </div>
          <div className="stat-info">
            {health === null ? (
              <p>Checking system…</p>
            ) : (
              <>
                <div className={`status-badge ${health ? 'online' : 'offline'}`}>
                  <span className={`status-dot ${health ? 'green' : 'red'}`} />
                  {health ? 'System Online' : 'System Offline'}
                </div>
                <p style={{ marginTop: 4 }}>API Health Check</p>
              </>
            )}
          </div>
        </div>

        <div className="card stat-card">
          <div className="stat-icon blue">👥</div>
          <div className="stat-info">
            <h3>{loading ? '–' : users.length}</h3>
            <p>Registered Tenants</p>
          </div>
        </div>

        <div className="card stat-card">
          <div className="stat-icon amber">🔍</div>
          <div className="stat-info">
            <h3>{rulesCount}</h3>
            <p>Detection Rules Active</p>
          </div>
        </div>
      </div>

      {/* ── Recent Activity / Run Detection ─────── */}
      <div className="flex-between mb-16">
        <h3 className="section-title" style={{ marginBottom: 0 }}>Tenant Activity</h3>
        <button className="btn btn-outline btn-sm" onClick={fetchData} disabled={loading}>
          {loading ? <span className="spinner" /> : '↻'} Refresh
        </button>
      </div>

      {loading ? (
        <div className="empty-state">
          <div className="spinner spinner-lg spinner-blue" />
          <p style={{ marginTop: 16 }}>Loading tenants…</p>
        </div>
      ) : users.length === 0 ? (
        <div className="empty-state">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
            <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/>
            <circle cx="9" cy="7" r="4"/>
          </svg>
          <h3>No tenants registered</h3>
          <p>Register a tenant to get started with anomaly detection.</p>
        </div>
      ) : (
        <div className="activity-list">
          {users.map(u => (
            <div className="activity-row" key={u.account_id}>
              <div className="activity-info">
                <span className="acct">{u.account_id}</span>
                <span className="meta">{u.region} · {u.email}</span>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                {results[u.account_id] && (
                  <span className={`activity-result ${results[u.account_id].type}`}>
                    {results[u.account_id].msg}
                  </span>
                )}
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
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
