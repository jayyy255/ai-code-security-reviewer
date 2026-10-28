import { useState, useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import Editor from '@monaco-editor/react';
import '../services/editor';
import { useTheme } from '../services/theme';
import { 
  Play, 
  Code, 
  ShieldAlert, 
  UploadCloud,
  GitBranch,
  FileText,
  Lock,
  EyeOff,
  AlertTriangle,
  RefreshCw,
  X
} from 'lucide-react';
import { analyzeCode, scanUploadedFiles, analyzeCommit, detectCodeLanguage } from '../services/api';
import './AnalyzePage.css';

const ALL_LANGUAGES = [
  { id: 'python', name: 'Python (.py)' },
  { id: 'javascript', name: 'JavaScript (.js, .jsx)' },
  { id: 'typescript', name: 'TypeScript (.ts, .tsx)' },
  { id: 'java', name: 'Java (.java)' },
  { id: 'go', name: 'Go (.go)' },
  { id: 'c', name: 'C (.c, .h)' },
  { id: 'cpp', name: 'C++ (.cpp, .hpp)' },
  { id: 'csharp', name: 'C# (.cs)' },
  { id: 'ruby', name: 'Ruby (.rb)' },
  { id: 'php', name: 'PHP (.php)' },
  { id: 'rust', name: 'Rust (.rs)' },
  { id: 'scala', name: 'Scala (.scala)' },
  { id: 'kotlin', name: 'Kotlin (.kt)' },
  { id: 'dockerfile', name: 'Dockerfile' },
  { id: 'terraform', name: 'Terraform (.tf)' },
  { id: 'yaml', name: 'YAML (.yml, .yaml)' },
  { id: 'json', name: 'JSON (.json)' },
  { id: 'bash', name: 'Shell / Bash (.sh)' }
];

const PRESETS = {
  python: `import os
import sqlite3

# EXPOSED AWS SECRET
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

def check_user(user_id):
    # SQL INJECTION
    db = sqlite3.connect("app.db")
    cursor = db.cursor()
    query = f"SELECT * FROM users WHERE id = '{user_id}'"
    cursor.execute(query)
    
    # OS COMMAND INJECTION
    os.system("ping -c 1 " + user_id)
`,
  javascript: `const jwt = require('jsonwebtoken');

// HARDCODED JWT SECRET
const JWT_SECRET = "super_insecure_jwt_secret_key_12345";

function verifyUser(token, userInput) {
  // INSECURE JWT DECODE WITHOUT VERIFICATION
  const payload = jwt.decode(token);
  
  // DANGEROUS EVAL INJECTION
  eval("console.log('Action: ' + " + userInput + ")");
}
`,
  java: `import java.sql.*;

public class AuthManager {
    // HARDCODED DB CREDENTIALS
    private static final String DB_PASS = "admin_super_secret_998";

    public void queryProducts(String category) throws SQLException {
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/app", "dbuser", DB_PASS);
        // SQL INJECTION VIA STRING CONCATENATION
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery("SELECT * FROM items WHERE cat = '" + category + "'");
    }
}
`,
  go: `package main

import (
	"fmt"
	"net/http"
	"os/exec"
)

// EXPOSED SLACK BOT TOKEN
const slackToken = "xoxb-982372938472-928374928374-j82kf92k01"

func handlePing(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("target")
	// COMMAND INJECTION VIA SHELL CONCATENATION
	cmd := exec.Command("sh", "-c", "nslookup "+target)
	out, _ := cmd.CombinedOutput()
	fmt.Fprintf(w, "%s", out)
}
`,
  dockerfile: `FROM node:18-alpine

# RUNNING AS ROOT USER INSECURELY
USER root

# EXPOSING EMBEDDED SECRET
ENV API_SECRET="ghp_v4l5K0s9B3aJ9823M5lK283s71f02p"

COPY . /app
WORKDIR /app
CMD ["node", "server.js"]
`,
  terraform: `resource "aws_security_group" "web_insecure" {
  name = "web-open-all"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    # OPEN SECURITY GROUP WORLD-ACCESSIBLE
    cidr_blocks = ["0.0.0.0/0"]
  }
}
`
};

export default function AnalyzePage() {
  const { theme } = useTheme();
  const navigate = useNavigate();
  const [activeMode, setActiveMode] = useState('paste'); // 'paste' | 'upload' | 'github'
  const [ephemeral, setEphemeral] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  // Mode 1: Paste Code State
  const [language, setLanguage] = useState('auto');
  const [detection, setDetection] = useState(null);
  const [code, setCode] = useState(PRESETS.python);
  const activeDetection = detection?.code === code ? detection : null;
  const editorLanguage = language === 'auto' ? activeDetection?.language || 'plaintext' : language;

  useEffect(() => {
    if (language !== 'auto' || activeMode !== 'paste' || !code.trim()) return;
    const controller = new AbortController();
    const timer = setTimeout(async () => {
      try {
        const detected = await detectCodeLanguage(code.slice(0, 20000), controller.signal);
        if (!controller.signal.aborted) setDetection({ ...detected, code });
      } catch (err) {
        if (!controller.signal.aborted) setDetection({ code, language: null, error: err.message });
      }
    }, 400);
    return () => { clearTimeout(timer); controller.abort(); };
  }, [code, language, activeMode]);

  // Mode 2: Upload Files State
  const [uploadedFiles, setUploadedFiles] = useState([]);
  const [dragActive, setDragActive] = useState(false);
  const fileInputRef = useRef(null);

  // Mode 3: GitHub Repo State
  const [repoUrl, setRepoUrl] = useState('');
  const [branch, setBranch] = useState('');
  const [commitSha, setCommitSha] = useState('');
  const strategy = 'full';

  // Handle File Upload Drop
  const handleDrop = async (e) => {
    e.preventDefault();
    setDragActive(false);
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      await processUploadedFiles(e.dataTransfer.files);
    }
  };

  const handleFileInput = async (e) => {
    if (e.target.files && e.target.files.length > 0) {
      await processUploadedFiles(e.target.files);
    }
    e.target.value = '';
  };

  const processUploadedFiles = async (fileList) => {
    const files = Array.from(fileList);
    if (uploadedFiles.length + files.length > 50 || files.some(file => file.size > 50 * 1024 * 1024)) {
      setError('Select up to 50 files, each no larger than 50 MB.');
      return;
    }
    if ([...uploadedFiles, ...files].reduce((sum, file) => sum + file.size, 0) > 50 * 1024 * 1024) {
      setError('The combined upload must be no larger than 50 MB.');
      return;
    }
    setError(null);
    setUploadedFiles(prev => [...prev, ...files]);
  };

  // Submit handler based on active mode
  const handleRunScan = async () => {
    setError(null);
    setLoading(true);

    try {
      let result = null;

      if (activeMode === 'paste') {
        if (!code.trim()) {
          throw new Error('Please enter or paste code before scanning.');
        }
        result = await analyzeCode(code, language === 'auto' ? null : language, 'snippet', ephemeral);
      } else if (activeMode === 'upload') {
        if (uploadedFiles.length === 0) {
          throw new Error('Please select or drag at least one file to scan.');
        }
        result = await scanUploadedFiles(uploadedFiles, ephemeral);
      } else if (activeMode === 'github') {
        if (!repoUrl.trim()) {
          throw new Error('Please enter a valid GitHub repository URL.');
        }
        result = await analyzeCommit(repoUrl.trim(), commitSha.trim() || null, branch.trim() || null, strategy, [], ephemeral);
      }

      if (result) {
        navigate(`/results/${result.analysis_id}`);
      }
    } catch (err) {
      console.error("Scan error:", err);
      setError(err.message || 'An error occurred during security review.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="container analyze-container animate-fade-in">
      {/* Top Header */}
      <div className="analyze-header">
        <div className="header-titles">
          <h1>Review your code</h1>
          <p className="subtitle">
            Paste code or upload files to find security issues and review suggested fixes.
          </p>
        </div>

        {/* Global Privacy & Ephemeral Bar */}
        <div className="privacy-bar">
          <div className="privacy-left">
            <Lock size={16} className="text-safe" />
            <span>Complete source is not stored in your history.</span>
          </div>
          <label className="ephemeral-toggle">
            <input 
              type="checkbox" 
              checked={ephemeral} 
              onChange={(e) => setEphemeral(e.target.checked)} 
            />
            <span className="ephemeral-label">
              <EyeOff size={14} /> Do not save this report
            </span>
          </label>
        </div>
      </div>

      {/* Mode Selector Navigation */}
      <div className="mode-tabs-container">
        <button 
          className={`mode-tab-btn ${activeMode === 'paste' ? 'active' : ''}`}
          aria-pressed={activeMode === 'paste'}
          onClick={() => setActiveMode('paste')}
        >
          <span className="mode-tab-icon"><Code size={19} /></span>
          <div>
            <div className="mode-tab-title">Paste code</div>
            <div className="mode-tab-desc">Review a snippet</div>
          </div>
        </button>

        <button 
          className={`mode-tab-btn ${activeMode === 'upload' ? 'active' : ''}`}
          aria-pressed={activeMode === 'upload'}
          onClick={() => setActiveMode('upload')}
        >
          <span className="mode-tab-icon"><UploadCloud size={19} /></span>
          <div>
            <div className="mode-tab-title">Upload files</div>
            <div className="mode-tab-desc">Files &amp; archives</div>
          </div>
        </button>

        <button 
          className={`mode-tab-btn ${activeMode === 'github' ? 'active' : ''}`}
          aria-pressed={activeMode === 'github'}
          onClick={() => setActiveMode('github')}
        >
          <span className="mode-tab-icon"><GitBranch size={19} /></span>
          <div>
            <div className="mode-tab-title">Repository</div>
            <div className="mode-tab-desc">Branch or commit</div>
          </div>
        </button>
      </div>

      {error && (
        <div className="scan-error-alert animate-fade-in">
          <AlertTriangle size={18} />
          <span>{error}</span>
        </div>
      )}

      {/* Main Workspace Area */}
      <div className="scan-workspace-card">
        {/* MODE 1: PASTE CODE */}
        {activeMode === 'paste' && (
          <div className="paste-mode-section animate-fade-in">
            <div className="editor-controls-bar">
              <div className="control-group">
                <label htmlFor="language-select">Language:</label>
                <select 
                  id="language-select" 
                  value={language} 
                  onChange={(e) => setLanguage(e.target.value)}
                  className="select-input"
                >
                  <option value="auto">Auto-detect (recommended)</option>
                  {ALL_LANGUAGES.map(lang => (
                    <option key={lang.id} value={lang.id}>{lang.name}</option>
                  ))}
                </select>
              </div>

              {language === 'auto' && <span className="language-detection-status" role="status">{!code.trim() ? 'Paste code to detect its language.' : !activeDetection ? 'Detecting language…' : activeDetection.error || (activeDetection.language ? `Detected: ${ALL_LANGUAGES.find(item => item.id === activeDetection.language)?.name || activeDetection.language}${activeDetection.confidence === 'medium' ? ' (check the language or override it)' : ''}` : 'Language unclear. Select it manually before scanning.')}</span>}
              <div className="preset-links">
                <span className="preset-label">Security Presets:</span>
                {['python', 'javascript', 'java', 'go', 'dockerfile', 'terraform'].map(p => (
                  <button 
                    key={p} 
                    type="button" 
                    className={`preset-btn ${language === p ? 'active' : ''}`}
                    onClick={() => { setLanguage(p); setCode(PRESETS[p]); }}
                  >
                    {p}
                  </button>
                ))}
              </div>
            </div>

            <div className="monaco-wrapper">
              <Editor
                height="clamp(300px, 52svh, 520px)"
                language={editorLanguage === 'terraform' ? 'hcl' : editorLanguage === 'bash' ? 'shell' : editorLanguage}
                value={code}
                onChange={(value) => setCode(value || '')}
                theme={theme === 'light' ? 'frosted-light' : 'frosted-carbon'}
                options={{
                  minimap: { enabled: false },
                  fontSize: 14,
                  lineNumbers: 'on',
                  scrollBeyondLastLine: false,
                  automaticLayout: true,
                  tabSize: 2,
                  fontFamily: 'Fira Code, monospace',
                  padding: { top: 12, bottom: 12 }
                }}
              />
            </div>
          </div>
        )}

        {/* MODE 2: UPLOAD FILE / ARCHIVE */}
        {activeMode === 'upload' && (
          <div className="upload-mode-section animate-fade-in">
            <div 
              className={`dropzone-box ${dragActive ? 'active' : ''}`}
              onDragOver={(e) => { e.preventDefault(); setDragActive(true); }}
              onDragLeave={() => setDragActive(false)}
              onDrop={loading ? e => e.preventDefault() : handleDrop}
            >
              <UploadCloud size={48} className="dropzone-icon" />
              <h3>Drag & Drop Source Files or Archives</h3>
              <p>Supports .zip, .tar, source files (.py, .js, .java, .go, .c, .rs), config files (.yml, .json, .tf), and documents (.pdf, .docx)</p>
              
              <input ref={fileInputRef} id="upload-files" type="file" multiple onChange={handleFileInput} className="visually-hidden-file-input" aria-label="Choose files to analyze" disabled={loading} />
              <button type="button" className="btn btn-secondary file-picker-label" onClick={() => fileInputRef.current?.click()} disabled={loading}>Choose files</button>
              <p className="upload-limits">Up to 50 files, 50 MB total. Archives are extracted safely; uploaded files are never executed.</p>

            </div>

            {uploadedFiles.length > 0 && (
              <div className="uploaded-file-list">
                <div className="file-list-header">
                  <h4>Selected Files ({uploadedFiles.length})</h4>
                  <button className="btn-text" onClick={() => setUploadedFiles([])}>Clear All</button>
                </div>
                <div className="file-items-grid">
                  {uploadedFiles.map((file, idx) => (
                    <div key={idx} className="file-item-card">
                      <FileText size={16} className="text-accent" />
                      <div className="file-item-info">
                        <span className="file-item-name">{file.name}</span>
                        <span className="file-item-size">{(file.size / 1024).toFixed(1)} KB</span>
                      </div>
                      <button type="button" className="btn-remove-file" aria-label={`Remove ${file.name}`} onClick={() => setUploadedFiles(previous => previous.filter((_, index) => index !== idx))} disabled={loading}><X size={16} /></button>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {/* MODE 3: GITHUB REPO / COMMIT */}
        {activeMode === 'github' && (
          <div className="github-mode-section animate-fade-in">
            <div className="git-inputs-grid">
              <div className="git-input-field full-width">
                <label htmlFor="repository-url">GitHub Repository URL *</label>
                <input 
                  type="text" 
                  id="repository-url" placeholder="https://github.com/owner/repository"
                  value={repoUrl}
                  onChange={(e) => setRepoUrl(e.target.value)}
                  className="text-input"
                />
              </div>

              <div className="git-input-field">
                <label htmlFor="repository-branch">Branch (optional)</label>
                <input 
                  type="text" 
                  id="repository-branch" placeholder="Default branch if omitted"
                  value={branch}
                  onChange={(e) => setBranch(e.target.value)}
                  className="text-input"
                />
              </div>

              <div className="git-input-field">
                <label htmlFor="repository-commit">Commit SHA (optional)</label>
                <input 
                  type="text" 
                  id="repository-commit" placeholder="Full SHA for an older commit"
                  value={commitSha}
                  onChange={(e) => setCommitSha(e.target.value)}
                  className="text-input"
                />
              </div>

            </div>

            <div className="git-strategy-notice">
              <AlertTriangle size={16} className="text-warning" />
              <div>
                <strong>Full repository review.</strong> Scans the latest commit on the default or selected branch, including existing issues. Checks source, secrets, infrastructure rules, workflow hazards and supported locked dependencies. Only package names and versions are sent to OSV for advisory lookup. No repository code is run. Private repositories are not supported.
              </div>
            </div>
          </div>
        )}

        {/* Action Button & Loader */}
        <div className="scan-action-footer">
          <div className="action-hint">
            <ShieldAlert size={16} className="text-accent" />
            <span>Findings come from scanners. Suggested fixes should be verified.</span>
          </div>

          <button 
            className="btn btn-primary run-scan-btn" 
            onClick={handleRunScan}
            disabled={loading || (activeMode === 'upload' && uploadedFiles.length === 0)}
          >
            {loading ? (
              <>
                <RefreshCw size={18} className="spinning-icon" />
                Scanning Workspace...
              </>
            ) : (
              <>
                <Play size={18} fill="currentColor" />
                {activeMode === 'upload' ? `Analyze ${uploadedFiles.length || ''} ${uploadedFiles.length === 1 ? 'file' : 'files'}` : activeMode === 'github' ? 'Review repository' : 'Analyze code'}
              </>
            )}
          </button>
        </div>

        {loading && (
          <div className="scan-progress-overlay animate-fade-in">
            <div className="progress-content">
              <div className="progress-spinner"></div>
              <h3>{activeMode === 'upload' ? 'Scanning your files…' : activeMode === 'github' ? 'Reviewing the repository snapshot…' : 'Analyzing your code…'}</h3>
              <p role="status">Running security scanners and preparing findings. Repositories and large archives can take a few minutes.</p>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
