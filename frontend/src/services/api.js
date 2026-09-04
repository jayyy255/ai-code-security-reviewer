// API Service for AI Code Security Reviewer (Multi-Mode & Privacy-Conscious)

const BACKEND_URL = '/api';

let isLoggedIn = false;

export function setLoggedInStatus(status) {
  isLoggedIn = status;
}

function generateUUID() {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
    const r = Math.random() * 16 | 0, v = c === 'x' ? r : (r & 0x3 | 0x8);
    return v.toString(16);
  });
}

// --- AUTH SERVICES ---
export async function getCurrentUser() {
  try {
    const response = await fetch(`${BACKEND_URL}/auth/me`, {
      credentials: 'include'
    });
    if (response.ok) {
      const data = await response.json();
      if (data.user) {
        isLoggedIn = true;
        return data.user;
      }
    }
    isLoggedIn = false;
    return null;
  } catch (error) {
    console.error("Error getting session user:", error);
    isLoggedIn = false;
    return null;
  }
}

export async function login(username, password) {
  const response = await fetch(`${BACKEND_URL}/auth/login`, {
    method: 'POST',
    credentials: 'include',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password })
  });
  if (!response.ok) {
    const errData = await response.json();
    throw new Error(errData.error || 'Login failed');
  }
  const data = await response.json();
  isLoggedIn = true;
  return data.user;
}

export async function signup(username, email, password) {
  const response = await fetch(`${BACKEND_URL}/auth/signup`, {
    method: 'POST',
    credentials: 'include',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, email, password })
  });
  if (!response.ok) {
    const errData = await response.json();
    throw new Error(errData.error || 'Signup failed');
  }
  const data = await response.json();
  isLoggedIn = true;
  return data.user;
}

export async function logout() {
  const response = await fetch(`${BACKEND_URL}/auth/logout`, {
    method: 'POST',
    credentials: 'include'
  });
  if (!response.ok) throw new Error('Logout failed');
  isLoggedIn = false;
}

export async function syncLocalHistoryToBackend() {
  if (!isLoggedIn) return;
  const localHistoryStr = localStorage.getItem('reviewer_scan_history');
  if (!localHistoryStr) return;

  try {
    const localHistory = JSON.parse(localHistoryStr);
    if (localHistory && localHistory.length > 0) {
      for (const item of localHistory) {
        await fetch(`${BACKEND_URL}/history`, {
          method: 'POST',
          credentials: 'include',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(item)
        });
      }
      localStorage.removeItem('reviewer_scan_history');
    }
  } catch (error) {
    console.error('Failed to sync guest history to backend:', error);
  }
}

// --- HISTORY SERVICES ---
export async function getHistory() {
  if (isLoggedIn) {
    try {
      const response = await fetch(`${BACKEND_URL}/history`, { credentials: 'include' });
      if (response.ok) return await response.json();
    } catch (error) {
      console.warn("Failed to fetch from DB vault, checking local storage.", error);
    }
  }
  const history = localStorage.getItem('reviewer_scan_history');
  return history ? JSON.parse(history) : [];
}

export async function saveToHistory(scanResult) {
  if (scanResult.privacy_metadata?.ephemeral_scan) return;

  if (!isLoggedIn) {
    const history = await getHistory();
    if (!history.some(item => item.analysis_id === scanResult.analysis_id)) {
      const updated = [scanResult, ...history];
      localStorage.setItem('reviewer_scan_history', JSON.stringify(updated.slice(0, 50)));
    }
  }
}

export async function deleteFromHistory(analysisId) {
  if (isLoggedIn) {
    try {
      await fetch(`${BACKEND_URL}/api/v1/scans/${analysisId}`, {
        method: 'DELETE',
        credentials: 'include'
      });
    } catch (e) {
      console.error("Failed to delete record:", e);
    }
  }
  const history = await getHistory();
  const filtered = history.filter(item => item.analysis_id !== analysisId);
  localStorage.setItem('reviewer_scan_history', JSON.stringify(filtered));
}

export async function clearHistory() {
  if (isLoggedIn) {
    try {
      await fetch(`${BACKEND_URL}/history`, { method: 'DELETE', credentials: 'include' });
    } catch (e) {
      console.error("Failed to clear DB vault:", e);
    }
  }
  localStorage.removeItem('reviewer_scan_history');
}

export async function getAnalysisResult(analysisId) {
  try {
    const response = await fetch(`${BACKEND_URL}/api/v1/scans/${analysisId}`, { credentials: 'include' });
    if (response.ok) return await response.json();
  } catch (e) {
    // fallback to local history
  }
  const history = await getHistory();
  return history.find(item => item.analysis_id === analysisId) || null;
}

// -------------------------------------------------------------
// 3 SCAN MODES
// -------------------------------------------------------------

// Mode 1: Paste Code / Single File
export async function analyzeCode(code, language, fileName = 'snippet', ephemeral = false) {
  try {
    const response = await fetch(`${BACKEND_URL}/api/v1/files/scan`, {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ code, language, file_name: fileName, ephemeral })
    });

    if (response.ok) {
      const result = await response.json();
      result.code = code;
      await saveToHistory(result);
      return result;
    } else {
      const err = await response.json();
      throw new Error(err.error || `Server error ${response.status}`);
    }
  } catch (error) {
    console.warn("Backend API unreachable. Falling back to Demo Mode.", error);
    const mock = generateDemoMockResponse(code, language, 'paste');
    await saveToHistory(mock);
    return mock;
  }
}

// Mode 2: File / Batch Upload
export async function scanUploadedFiles(filesArray, ephemeral = false) {
  try {
    const response = await fetch(`${BACKEND_URL}/api/v1/files/scan-batch`, {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ files: filesArray, ephemeral })
    });

    if (response.ok) {
      const result = await response.json();
      await saveToHistory(result);
      return result;
    } else {
      const err = await response.json();
      throw new Error(err.error || `Batch scan error ${response.status}`);
    }
  } catch (error) {
    console.warn("Backend batch scan unreachable. Using demo response.", error);
    const mock = generateDemoMockResponse("Uploaded project files", "multi", "upload");
    await saveToHistory(mock);
    return mock;
  }
}

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
