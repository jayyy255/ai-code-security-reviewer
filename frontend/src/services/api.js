// Real scan results only; transport failures remain visible to the user.
const BACKEND_URL = import.meta.env?.VITE_BACKEND_URL || '/api';

const transientReports = new Map();
export function setLoggedInStatus(status) { if (!status) transientReports.clear(); }

async function request(path, options = {}) {
  let response;
  try {
    response = await fetch(`${BACKEND_URL}${path}`, { credentials: 'include', ...options });
  } catch (err) {
    if (err.name === 'AbortError') throw err;
    throw new Error('Cannot reach the security service. Check that the API and analysis engine are running.', { cause: err });
  }
  const data = await response.json().catch(() => null);
  if (!response.ok) {
    if (response.status === 401) { setLoggedInStatus(false); window.dispatchEvent(new Event('reviewer:unauthorized')); }
    const detail = data?.detail;
    const message = Array.isArray(detail) ? detail.map(item => item.msg).join('; ') : detail;
    throw new Error(data?.error || message || `Request failed (${response.status}).`);
  }
  if (data === null) throw new Error('The service returned an invalid response.');
  return data;
}
const jsonOptions = (body) => ({ method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
const HISTORY_KEY = 'reviewer_scan_history';
function readLocalHistory() {
  try {
    const data = JSON.parse(localStorage.getItem(HISTORY_KEY) || '[]');
    return Array.isArray(data) ? data : [];
  } catch { return []; }
}
function historyRecord(result) {
  const record = { ...result };
  delete record.code;
  return {
    ...record,
    timestamp: result.timestamp || new Date().toISOString(),
    score: result.summary?.security_score ?? result.score,
    critical: result.summary?.critical ?? result.critical ?? 0,
    high: result.summary?.high ?? result.high ?? 0,
    medium: result.summary?.medium ?? result.medium ?? 0,
    low: result.summary?.low ?? result.low ?? 0,
  };
}

export async function getCurrentUser() {
  const data = await request('/auth/me');
  return data.user;
}
export async function login(username, password) {
  const data = await request('/auth/login', jsonOptions({ username, password }));
  transientReports.clear();
  return data.user;
}
export async function signup(username, email, password) {
  const data = await request('/auth/signup', jsonOptions({ username, email, password }));
  transientReports.clear();
  return data.user;
}
export async function logout() {
  await request('/auth/logout', { method: 'POST' });
  setLoggedInStatus(false);
}
export async function getHistory() {
  const history = await request('/history');
  return history.map(historyRecord);
}
export async function saveToHistory(result) {
  transientReports.set(result.analysis_id, result);
  if (transientReports.size > 20) transientReports.delete(transientReports.keys().next().value);
}

export async function deleteFromHistory(id) {
  await request(`/api/v1/scans/${encodeURIComponent(id)}`, { method: 'DELETE' });
  transientReports.delete(id);
  localStorage.setItem(HISTORY_KEY, JSON.stringify(readLocalHistory().filter(item => item.analysis_id !== id)));
}
export async function clearHistory() {
  await request('/history', { method: 'DELETE' });
  localStorage.removeItem(HISTORY_KEY);
  transientReports.clear();
}
export async function getAnalysisResult(id) {
  if (transientReports.has(id)) return transientReports.get(id);
  return request(`/api/v1/scans/${encodeURIComponent(id)}`);
}
export async function analyzeCode(code, language, fileName = 'snippet', ephemeral = false) {
  const result = await request('/api/v1/files/scan', jsonOptions({ code, language, file_name: fileName, ephemeral }));
  await saveToHistory(result);
  return result;
}
export function detectCodeLanguage(code, signal) {
  return request('/api/v1/language/detect', { ...jsonOptions({ code, file_name: 'snippet' }), signal });
}
export async function scanUploadedFiles(filesArray, ephemeral = false) {
  const body = new FormData();
  filesArray.forEach(file => body.append('files', file, file.name));
  body.append('ephemeral', String(ephemeral));
  const result = await request('/api/v1/files/scan-batch', { method: 'POST', body });
  await saveToHistory(result);
  return result;
}
// Mode 3: GitHub Repo / Commit Analysis
export async function analyzeCommit(repoUrl, commitSha = null, branch = null, strategy = 'auto', baselineFindings = [], ephemeral = false) {
  const result = await request('/api/v1/commits/analyze', jsonOptions({ repository_url: repoUrl, commit_sha: commitSha, branch, strategy, baseline_findings: baselineFindings, ephemeral }));
  await saveToHistory(result);
  return result;
}
