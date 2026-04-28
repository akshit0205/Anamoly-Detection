const BASE = 'http://localhost:8000';
const API_KEY = 'dev-secret-key';

async function request(path, options = {}) {
  const res = await fetch(`${BASE}${path}`, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      'X-API-Key': API_KEY,
      ...(options.headers || {}),
    },
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.detail || data.error || `HTTP ${res.status}`);
  return data;
}

export const checkHealth    = ()          => request('/health');
export const getUsers       = ()          => request('/users');
export const registerTenant = (body)      => request('/register', { method: 'POST', body: JSON.stringify(body) });
export const runDetection   = (accountId) => request(`/run/${accountId}`, { method: 'POST' });
export const getRulesCount  = ()          => request('/rules/count');
