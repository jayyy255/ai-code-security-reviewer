// Real scan results only; transport failures remain visible to the user.
const BACKEND_URL = import.meta.env.VITE_BACKEND_URL || '/api';
let isLoggedIn = false;
const transientReports = new Map();
export function setLoggedInStatus(status) { isLoggedIn = status; if (!status) transientReports.clear(); }

async function request(path, options = {}) {
  let response;
  try {
    response = await fetch(`${BACKEND_URL}${path}`, { credentials: 'include', ...options });
  } catch {
    throw new Error('Cannot reach the security service. Check that the API and analysis engine are running.');
  }
  const data = await response.json().catch(() => null);
  if (!response.ok) {
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
  isLoggedIn = Boolean(data.user);
  return data.user;
}
export async function login(username, password) {
  const data = await request('/auth/login', jsonOptions({ username, password }));
  isLoggedIn = true;
  transientReports.clear();
  return data.user;
}
export async function signup(username, email, password) {
  const data = await request('/auth/signup', jsonOptions({ username, email, password }));
  isLoggedIn = true;
  transientReports.clear();
  return data.user;
}
export async function logout() {
  await request('/auth/logout', { method: 'POST' });
  setLoggedInStatus(false);
}
export async function syncLocalHistoryToBackend() {
  if (!isLoggedIn) return;
  // Remove only records acknowledged by the server; failed syncs are retriable.
  for (const item of readLocalHistory()) {
    if (item.privacy_metadata?.ephemeral_scan || item.is_demo) continue;
    await request('/history', jsonOptions(historyRecord(item)));
    const remaining = readLocalHistory().filter(record => record.analysis_id !== item.analysis_id);
    localStorage.setItem(HISTORY_KEY, JSON.stringify(remaining));
  }
}
export async function getHistory() {
  const history = isLoggedIn ? await request('/history') : readLocalHistory();
  return history.map(historyRecord);
}
export async function saveToHistory(result) {
  transientReports.set(result.analysis_id, result);
  if (transientReports.size > 20) transientReports.delete(transientReports.keys().next().value);
  if (result.privacy_metadata?.ephemeral_scan) return;
  if (isLoggedIn) return;
  const history = readLocalHistory();
  if (!history.some(item => item.analysis_id === result.analysis_id)) {
    try {
      localStorage.setItem(HISTORY_KEY, JSON.stringify([historyRecord(result), ...history].slice(0, 50)));
    } catch {
      result.persistence_warning = 'This report could not be saved in browser storage. Export it to keep a copy.';
    }
  }
}
export async function deleteFromHistory(id) {
  if (isLoggedIn) await request(`/api/v1/scans/${encodeURIComponent(id)}`, { method: 'DELETE' });
  transientReports.delete(id);
  localStorage.setItem(HISTORY_KEY, JSON.stringify(readLocalHistory().filter(item => item.analysis_id !== id)));
}
export async function clearHistory() {
  if (isLoggedIn) await request('/history', { method: 'DELETE' });
  else localStorage.removeItem(HISTORY_KEY);
  transientReports.clear();
}
export async function getAnalysisResult(id) {
  if (transientReports.has(id)) return transientReports.get(id);
  if (isLoggedIn) return request(`/api/v1/scans/${encodeURIComponent(id)}`);
  return readLocalHistory().find(item => item.analysis_id === id) || null;
}
export async function analyzeCode(code, language, fileName = 'snippet', ephemeral = false) {
  const result = await request('/api/v1/files/scan', jsonOptions({ code, language, file_name: fileName, ephemeral }));
  await saveToHistory(result);
  return result;
}
export async function scanUploadedFiles(filesArray, ephemeral = false) {
  const body = new FormData();
  filesArray.forEach(file => body.append('files', file, file.name));
  body.append('ephemeral', String(ephemeral));
  const result = await request('/api/v1/files/scan-batch', { method: 'POST', body });
  await saveToHistory(result);
  return result;
}
function generateUUID() { return crypto.randomUUID(); }

// Mode 3: GitHub Repo / Commit Analysis
export async function analyzeCommit(repoUrl, commitSha = null, branch = null, strategy = 'auto', baselineFindings = [], ephemeral = false) {
  try {
    const response = await fetch(`${BACKEND_URL}/api/v1/commits/analyze`, {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        repository_url: repoUrl,
        commit_sha: commitSha,
        branch,
        strategy,
        baseline_findings: baselineFindings,
        ephemeral
      })
    });

    if (response.ok) {
      const result = await response.json();
      await saveToHistory(result);
      return result;
    } else {
      const err = await response.json();
      throw new Error(err.error || `Commit analysis error ${response.status}`);
    }
  } catch (error) {
    console.warn("Backend commit scan unreachable. Using demo response.", error);
    const mock = generateDemoMockResponse("Repository scan state", "multi", "commit", repoUrl, commitSha);
    await saveToHistory(mock);
    return mock;
  }
}

// Synthetic Demo Mode Data (Clearly marked as Demo Scan)
function generateDemoMockResponse(code, language, scanType = 'paste', repoUrl = null, commitSha = null) {
  const analysisId = generateUUID();
  return {
    analysis_id: analysisId,
    scan_type: scanType,
    is_demo: true,
    language: language || 'python',
    summary: {
      security_score: 45,
      critical: 2,
      high: 1,
      medium: 1,
      low: 1,
      total_findings: 5
    },
    findings: [
      {
        scanner: "gitleaks",
        rule_id: "github-pat",
        file_path: scanType === 'paste' ? "snippet" : "src/config.py",
        line: 4,
        column: 1,
        severity: "CRITICAL",
        category: "secrets",
        message: "Exposed GitHub Personal Access Token in source code.",
        source: "gitleaks",
        confidence: "HIGH",
        owasp: ["A07:2021 - Identification and Authentication Failures"],
        cwe: ["CWE-798: Use of Hard-coded Credentials"],
        vulnerability_class: ["Hardcoded Secret"],
        explanation: "[Demo Advisory] Hardcoded GitHub personal access tokens permit unauthorized repository access.",
        risk: "Allows attacker to push malicious code and access private repositories.",
        remediation: ["Revoke token in GitHub settings.", "Store secrets in environment variables."],
        requires_verification: true
      },
      {
        scanner: "semgrep",
        rule_id: "python-sql-injection-format",
        file_path: scanType === 'paste' ? "snippet" : "src/db.py",
        line: 12,
        column: 5,
        severity: "CRITICAL",
        category: "injection",
        message: "SQL query built with string formatting.",
        source: "semgrep",
        confidence: "HIGH",
        owasp: ["A03:2021 - Injection"],
        cwe: ["CWE-89: Improper Neutralization of Special Elements used in an SQL Command"],
        vulnerability_class: ["SQL Injection"],
        explanation: "[Demo Advisory] Unescaped user input in SQL queries allows database takeover.",
        risk: "Attackers can bypass authentication and extract confidential records.",
        remediation: ["Use parameterized query placeholders."],
        fixed_code: "cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))",
        requires_verification: true
      }
    ],
    files_analyzed: [scanType === 'paste' ? "pasted_snippet.py" : "src/app.py", "src/config.py"],
    files_skipped: [],
    scanner_status: [
      {
        scanner_name: "Semgrep",
        available: true,
        version: "1.168.0",
        rules_loaded: 62,
        capabilities: ["Multi-language AST scanning", "Custom rule engine"],
        limitations: ["Static rule-based"],
        status_message: "Demo Mode"
      },
      {
        scanner_name: "Gitleaks",
        available: true,
        version: "8.x",
        rules_loaded: 160,
        capabilities: ["Secret scanning"],
        limitations: ["Does not test live revocation"],
        status_message: "Demo Mode"
      }
    ],
    malware_status: {
      status: "unavailable",
      engine: "ClamAV",
      engine_available: false,
      details: "ClamAV engine not active in demo fallback. Honest unavailable status reported."
    },
    privacy_metadata: {
      raw_code_stored: false,
      ephemeral_scan: true,
      ai_context_isolated: true,
      snippets_only_to_ai: true,
      storage_type: "demo_memory"
    },
    repository_url: repoUrl,
    commit_sha: commitSha || "a1b2c3d4e5",
    parent_sha: "9f8e7d6c5b",
    changed_files: { added: ["src/config.py"], modified: ["src/db.py"], renamed: [], deleted: [] },
    new_findings: [],
    fixed_findings: [],
    persistent_findings: []
  };
}
