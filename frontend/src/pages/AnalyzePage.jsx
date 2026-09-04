import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import Editor from '@monaco-editor/react';
import { 
  Play, 
  Terminal, 
  Code, 
  Sparkles, 
  ShieldAlert, 
  CheckCircle,
  HelpCircle,
  UploadCloud,
  GitBranch,
  FileText,
  FileCode,
  ShieldCheck,
  Lock,
  EyeOff,
  AlertTriangle,
  FolderArchive,
  RefreshCw
} from 'lucide-react';
import { analyzeCode, scanUploadedFiles, analyzeCommit } from '../services/api';
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
  const navigate = useNavigate();
  const [activeMode, setActiveMode] = useState('paste'); // 'paste' | 'upload' | 'github'
  const [ephemeral, setEphemeral] = useState(false);
  const [loading, setLoading] = useState(false);
  const [scanStep, setScanStep] = useState(1);
  const [error, setError] = useState(null);

  // Mode 1: Paste Code State
  const [language, setLanguage] = useState('python');
  const [code, setCode] = useState(PRESETS.python);

  // Mode 2: Upload Files State
  const [uploadedFiles, setUploadedFiles] = useState([]);
  const [dragActive, setDragActive] = useState(false);

  // Mode 3: GitHub Repo State
  const [repoUrl, setRepoUrl] = useState('');
  const [branch, setBranch] = useState('');
  const [commitSha, setCommitSha] = useState('');
  const [strategy, setStrategy] = useState('auto'); // 'auto' | 'full' | 'incremental'

  useEffect(() => {
    if (PRESETS[language] && activeMode === 'paste') {
      setCode(PRESETS[language]);
    }
  }, [language, activeMode]);

  // Loading animation simulation
  useEffect(() => {
    let interval;
    if (loading) {
      interval = setInterval(() => {
        setScanStep(prev => (prev < 4 ? prev + 1 : 1));
      }, 1200);
    }
    return () => clearInterval(interval);
  }, [loading]);

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
  };

  const processUploadedFiles = async (fileList) => {
    const fileObjs = [];
    for (let i = 0; i < fileList.length; i++) {
      const file = fileList[i];
      try {
        const text = await file.text();
        fileObjs.push({
          filename: file.name,
          size: file.size,
          content: text
        });
      } catch (err) {
        fileObjs.push({
          filename: file.name,
          size: file.size,
          content: `[Binary or non-text content - ${file.type || 'unknown'}]`
        });
      }
    }
    setUploadedFiles(prev => [...prev, ...fileObjs]);
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
        result = await analyzeCode(code, language, `snippet.${language}`, ephemeral);
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
        navigate(`/results/${result.analysis_id}`, { state: { data: result } });
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
          <div className="badge-wrapper">
            <span className="badge badge-primary">
              <Sparkles size={14} className="sparkle-icon" /> Next-Gen Security Engine
            </span>
          </div>
          <h1>Multi-Mode Code Security Scanner</h1>
          <p className="subtitle">
            Static AST analysis, 60+ security rulesets, secret scanning, honest malware engine reporting, and prompt-injection-hardened AI advisories.
          </p>
        </div>

        {/* Global Privacy & Ephemeral Bar */}
        <div className="privacy-bar">
          <div className="privacy-left">
            <Lock size={16} className="text-safe" />
            <span><strong>Privacy By Design:</strong> Isolated AI context • No full repository transfer • Minimal snippet footprint</span>
          </div>
          <label className="ephemeral-toggle">
            <input 
              type="checkbox" 
              checked={ephemeral} 
              onChange={(e) => setEphemeral(e.target.checked)} 
            />
            <span className="ephemeral-label">
              <EyeOff size={14} /> Ephemeral Scan (Zero Vault Persistence)
            </span>
          </label>
        </div>
      </div>

      {/* Mode Selector Navigation */}
      <div className="mode-tabs-container">
        <button 
          className={`mode-tab-btn ${activeMode === 'paste' ? 'active' : ''}`}
          onClick={() => setActiveMode('paste')}
        >
          <Code size={18} />
          <div>
            <div className="mode-tab-title">1. Paste Code</div>
            <div className="mode-tab-desc">Multi-language code snippets & prompts</div>
          </div>
        </button>

        <button 
          className={`mode-tab-btn ${activeMode === 'upload' ? 'active' : ''}`}
          onClick={() => setActiveMode('upload')}
        >
          <UploadCloud size={18} />
          <div>
            <div className="mode-tab-title">2. Upload File / Archive</div>
            <div className="mode-tab-desc">Source, Zip, Config, PDF & Docx</div>
          </div>
        </button>

        <button 
          className={`mode-tab-btn ${activeMode === 'github' ? 'active' : ''}`}
          onClick={() => setActiveMode('github')}
        >
          <GitBranch size={18} />
          <div>
            <div className="mode-tab-title">3. GitHub Repo / Commit</div>
            <div className="mode-tab-desc">Full snapshot or Smart Incremental diff</div>
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
                <label htmlFor="language-select">Language Support:</label>
                <select 
                  id="language-select" 
                  value={language} 
                  onChange={(e) => setLanguage(e.target.value)}
                  className="select-input"
                >
                  {ALL_LANGUAGES.map(lang => (
                    <option key={lang.id} value={lang.id}>{lang.name}</option>
                  ))}
                </select>
              </div>

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
                height="440px"
                language={language === 'dockerfile' ? 'dockerfile' : language === 'terraform' ? 'hcl' : language}
                value={code}
                onChange={(value) => setCode(value || '')}
                theme="vs-dark"
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
              onDrop={handleDrop}
            >
              <UploadCloud size={48} className="dropzone-icon" />
              <h3>Drag & Drop Source Files or Archives</h3>
              <p>Supports .zip, .tar, source files (.py, .js, .java, .go, .c, .rs), config files (.yml, .json, .tf), and documents (.pdf, .docx)</p>
              
              <label className="btn btn-secondary file-picker-label">
                Browse Local Files
                <input 
                  type="file" 
                  multiple 
                  onChange={handleFileInput} 
                  style={{ display: 'none' }} 
                />
              </label>

              <div className="security-badges-row">
                <span className="badge badge-info"><ShieldCheck size={12} /> Zip Bomb Limit (100:1 / 100MB)</span>
                <span className="badge badge-info"><Lock size={12} /> Path Traversal Sanitized</span>
                <span className="badge badge-info"><FileCode size={12} /> Non-executable Isolation</span>
              </div>
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
                        <span className="file-item-name">{file.filename}</span>
                        <span className="file-item-size">{(file.size / 1024).toFixed(1)} KB</span>
                      </div>
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
                <label>GitHub Repository URL *</label>
                <input 
                  type="text" 
                  placeholder="https://github.com/owner/repository" 
                  value={repoUrl}
                  onChange={(e) => setRepoUrl(e.target.value)}
                  className="text-input"
                />
              </div>

              <div className="git-input-field">
                <label>Branch (Optional)</label>
                <input 
                  type="text" 
                  placeholder="e.g. main or feature/login" 
                  value={branch}
                  onChange={(e) => setBranch(e.target.value)}
                  className="text-input"
                />
              </div>

              <div className="git-input-field">
                <label>Target Commit SHA (Optional)</label>
                <input 
                  type="text" 
                  placeholder="e.g. 7a3f89e" 
                  value={commitSha}
                  onChange={(e) => setCommitSha(e.target.value)}
                  className="text-input"
                />
              </div>

              <div className="git-input-field full-width">
                <label>Scanning Strategy</label>
                <select 
                  value={strategy} 
                  onChange={(e) => setStrategy(e.target.value)}
                  className="select-input"
                >
                  <option value="auto">Auto: Smart Incremental with Automatic Full Fallback (Recommended)</option>
                  <option value="full">Full Snapshot: Complete Repository Scan</option>
                  <option value="incremental">Incremental: Changed Files in Commit Only</option>
                </select>
              </div>
            </div>

            <div className="git-strategy-notice">
              <AlertTriangle size={16} className="text-warning" />
              <div>
                <strong>Auto-Fallback Triggers:</strong> Full scans are automatically triggered if no previous baseline exists, if the commit is a merge commit, or if dependency lockfiles (e.g. <code>package-lock.json</code>, <code>requirements.txt</code>) or scanner security configs are modified.
              </div>
            </div>
          </div>
        )}

        {/* Action Button & Loader */}
        <div className="scan-action-footer">
          <div className="action-hint">
            <ShieldAlert size={16} className="text-accent" />
            <span>Deterministic Semgrep & Gitleaks findings are strictly separated from AI advisory insights.</span>
          </div>

          <button 
            className="btn btn-primary run-scan-btn" 
            onClick={handleRunScan}
            disabled={loading}
          >
            {loading ? (
              <>
                <RefreshCw size={18} className="spinning-icon" />
                Scanning Workspace...
              </>
            ) : (
              <>
                <Play size={18} fill="currentColor" />
                Execute Security Review
              </>
            )}
          </button>
        </div>

        {loading && (
          <div className="scan-progress-overlay animate-fade-in">
            <div className="progress-content">
              <div className="progress-spinner"></div>
              <h3>Analyzing Security Posture...</h3>
              <div className="progress-steps-row">
                <div className={`step-item ${scanStep >= 1 ? 'active' : ''}`}>
                  <CheckCircle size={14} /> Ingestion & Prompt Defense
                </div>
                <div className={`step-item ${scanStep >= 2 ? 'active' : ''}`}>
                  <CheckCircle size={14} /> Semgrep & Secret Rules
                </div>
                <div className={`step-item ${scanStep >= 3 ? 'active' : ''}`}>
                  <CheckCircle size={14} /> Malware Status Engine
                </div>
                <div className={`step-item ${scanStep >= 4 ? 'active' : ''}`}>
                  <CheckCircle size={14} /> AI Advisory Synthesis
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
