import React, { useState, useEffect } from 'react';
import { useParams, useLocation, useNavigate, Link } from 'react-router-dom';
import { 
  PieChart, 
  Pie, 
  Cell, 
  ResponsiveContainer 
} from 'recharts';
import { 
  ShieldAlert, 
  ArrowLeft, 
  Copy, 
  Check, 
  ListFilter,
  ExternalLink,
  ShieldCheck,
  CheckCircle2,
  AlertTriangle,
  FileCode,
  FolderTree,
  Bug,
  Lock,
  Download,
  Info,
  Layers,
  GitCommit,
  Sparkles,
  ShieldX
} from 'lucide-react';
import { getAnalysisResult } from '../services/api';
import './ResultsPage.css';

export default function ResultsPage() {
  const { analysisId } = useParams();
  const location = useLocation();
  const navigate = useNavigate();
  
  const [result, setResult] = useState(null);
  const [selectedFinding, setSelectedFinding] = useState(null);
  const [filterSeverity, setFilterSeverity] = useState('ALL');
  const [filterSource, setFilterSource] = useState('ALL');
  const [selectedFile, setSelectedFile] = useState('ALL');
  const [commitTab, setCommitTab] = useState('ALL'); // 'ALL' | 'NEW' | 'FIXED' | 'PERSISTENT'
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    async function loadResult() {
      if (location.state && location.state.data) {
        const data = location.state.data;
        setResult(data);
        if (data.findings && data.findings.length > 0) {
          setSelectedFinding(data.findings[0]);
        }
      } else {
        try {
          const data = await getAnalysisResult(analysisId);
          if (data) {
            setResult(data);
            if (data.findings && data.findings.length > 0) {
              setSelectedFinding(data.findings[0]);
            }
          } else {
            navigate('/analyze');
          }
        } catch (err) {
          console.error("Error loading scan result:", err);
          navigate('/analyze');
        }
      }
    }
    loadResult();
  }, [analysisId, location.state, navigate]);

  if (!result) {
    return (
      <div className="container" style={{ padding: '80px 24px', textAlign: 'center' }}>
        <p>Loading security audit report...</p>
      </div>
    );
  }

  const { summary, findings = [], malware_status, scanner_status = [], privacy_metadata = {} } = result;
  const score = Math.round(summary.security_score ?? 100);

  // Group findings by file
  const filesList = Array.from(new Set(findings.map(f => f.file_path || 'snippet')));

  // Filter commit findings if applicable
  let candidateFindings = findings;
  if (result.scan_type === 'commit' || result.scan_type === 'incremental') {
    if (commitTab === 'NEW' && result.new_findings) candidateFindings = result.new_findings;
    else if (commitTab === 'FIXED' && result.fixed_findings) candidateFindings = result.fixed_findings;
    else if (commitTab === 'PERSISTENT' && result.persistent_findings) candidateFindings = result.persistent_findings;
  }

  // Filter findings
  const filteredFindings = candidateFindings.filter(f => {
    const matchSev = filterSeverity === 'ALL' || (f.severity && f.severity.toUpperCase() === filterSeverity.toUpperCase());
    const matchSource = filterSource === 'ALL' || (f.source && f.source.toLowerCase() === filterSource.toLowerCase());
    const matchFile = selectedFile === 'ALL' || f.file_path === selectedFile;
    return matchSev && matchSource && matchFile;
  });

  const handleCopyCode = (text) => {
    if (!text) return;
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleExportReport = (format = 'json') => {
    let blob, filename;
    if (format === 'json') {
      blob = new Blob([JSON.stringify(result, null, 2)], { type: 'application/json' });
      filename = `security-report-${result.analysis_id}.json`;
    } else {
      const markdown = `# Security Scan Audit Report
Analysis ID: ${result.analysis_id}
Date: ${new Date().toISOString()}
Scan Mode: ${result.scan_type}
Security Score: ${score}/100

## Summary Metrics
- Critical: ${summary.critical}
- High: ${summary.high}
- Medium: ${summary.medium}
- Low: ${summary.low}

## Findings (${findings.length})
${findings.map((f, i) => `
### ${i+1}. [${f.severity}] ${f.message}
- **Rule ID**: \`${f.rule_id}\`
- **File**: \`${f.file_path}\` (Line: ${f.line || 'N/A'})
- **Source**: ${f.source}
- **Explanation**: ${f.explanation || 'N/A'}
- **Risk**: ${f.risk || 'N/A'}
- **Remediation**:
${(f.remediation || []).map(r => `  - ${r}`).join('\n')}
`).join('\n')}
`;
      blob = new Blob([markdown], { type: 'text/markdown' });
      filename = `security-report-${result.analysis_id}.md`;
    }
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  };

  const getMalwareBadge = (status) => {
    const s = (status || 'unavailable').toLowerCase();
    if (s === 'clean') return { label: 'CLEAN', color: 'badge-safe', icon: <ShieldCheck size={14} /> };
    if (s === 'infected') return { label: 'INFECTED', color: 'badge-danger', icon: <ShieldX size={14} /> };
    if (s === 'suspicious') return { label: 'SUSPICIOUS', color: 'badge-warning', icon: <AlertTriangle size={14} /> };
    return { label: 'UNAVAILABLE', color: 'badge-neutral', icon: <Info size={14} /> };
  };

  const malwareBadge = getMalwareBadge(malware_status?.status);

  return (
    <div className="container results-container animate-fade-in">
      {/* Top Header & Breadcrumbs */}
      <div className="results-top-bar">
        <Link to="/analyze" className="btn-back">
          <ArrowLeft size={16} /> New Security Review
        </Link>
        <div className="export-actions">
          <button className="btn btn-secondary btn-sm" onClick={() => handleExportReport('json')}>
            <Download size={14} /> Export JSON
          </button>
          <button className="btn btn-secondary btn-sm" onClick={() => handleExportReport('md')}>
            <Download size={14} /> Export Markdown
          </button>
        </div>
      </div>

      {result.is_demo && (
        <div className="demo-mode-alert">
          <Info size={16} />
          <span><strong>Offline Demo Mode:</strong> Displaying synthetic evaluation results. Backend scanners were simulated.</span>
        </div>
      )}

      {/* Summary Score Dashboard */}
      <div className="results-summary-grid">
        <div className="summary-card score-card">
          <div className="score-value-circle" style={{ borderColor: score >= 80 ? '#22c55e' : score >= 60 ? '#eab308' : '#ef4444' }}>
            <span className="score-number">{score}</span>
            <span className="score-label">/ 100</span>
          </div>
          <div className="score-text">
            <h3>Overall Security Score</h3>
            <p>{score >= 80 ? 'Strong Security Posture' : score >= 60 ? 'Moderate Risks Detected' : 'Action Required: High Exposure'}</p>
          </div>
        </div>

        <div className="summary-card metrics-card">
          <div className="metric-pill critical">
            <span className="metric-count">{summary.critical}</span>
            <span className="metric-name">Critical</span>
          </div>
          <div className="metric-pill high">
            <span className="metric-count">{summary.high}</span>
            <span className="metric-name">High</span>
          </div>
          <div className="metric-pill medium">
            <span className="metric-count">{summary.medium}</span>
            <span className="metric-name">Medium</span>
          </div>
          <div className="metric-pill low">
            <span className="metric-count">{summary.low}</span>
            <span className="metric-name">Low</span>
          </div>
        </div>

        {/* Malware Engine Status Card */}
        <div className="summary-card malware-card">
          <div className="card-header-row">
            <span className="card-title">Malware Engine</span>
            <span className={`badge ${malwareBadge.color}`}>{malwareBadge.icon} {malwareBadge.label}</span>
          </div>
          <div className="engine-details-text">
            {malware_status?.details || 'Malware engine was not invoked on this plain text stream.'}
          </div>
          <div className="engine-disclaimer">
            * We never claim clean when the antivirus daemon is offline or uninstalled.
          </div>
        </div>
      </div>

      {/* Commit Diff Navigation (If Commit Scan) */}
      {(result.scan_type === 'commit' || result.scan_type === 'incremental' || result.commit_sha) && (
        <div className="commit-diff-banner">
          <div className="commit-meta">
            <GitCommit size={18} className="text-accent" />
            <span>Target Commit: <code>{result.commit_sha?.substring(0, 8) || 'Head'}</code></span>
            {result.parent_sha && <span>Parent: <code>{result.parent_sha.substring(0, 8)}</code></span>}
            <span className="badge badge-info">{result.scan_type.toUpperCase()} SCAN</span>
          </div>

          <div className="commit-tabs">
            <button className={`tab-btn ${commitTab === 'ALL' ? 'active' : ''}`} onClick={() => setCommitTab('ALL')}>
              All Findings ({findings.length})
            </button>
            <button className={`tab-btn ${commitTab === 'NEW' ? 'active' : ''}`} onClick={() => setCommitTab('NEW')}>
              New (+{result.new_findings?.length || 0})
            </button>
            <button className={`tab-btn ${commitTab === 'FIXED' ? 'active' : ''}`} onClick={() => setCommitTab('FIXED')}>
              Fixed (-{result.fixed_findings?.length || 0})
            </button>
            <button className={`tab-btn ${commitTab === 'PERSISTENT' ? 'active' : ''}`} onClick={() => setCommitTab('PERSISTENT')}>
              Persistent (={result.persistent_findings?.length || 0})
            </button>
          </div>
        </div>
      )}

      {/* Filter Toolbar */}
      <div className="filter-toolbar">
        <div className="filter-group">
          <ListFilter size={16} className="text-muted" />
          <span className="filter-title">Filter by:</span>

          <select value={filterSeverity} onChange={(e) => setFilterSeverity(e.target.value)} className="filter-select">
            <option value="ALL">All Severities</option>
            <option value="CRITICAL">Critical Only</option>
            <option value="HIGH">High Only</option>
            <option value="MEDIUM">Medium Only</option>
            <option value="LOW">Low Only</option>
          </select>

          <select value={filterSource} onChange={(e) => setFilterSource(e.target.value)} className="filter-select">
            <option value="ALL">All Sources</option>
            <option value="semgrep">Semgrep AST Rules</option>
            <option value="gitleaks">Gitleaks Secret Scanner</option>
            <option value="prompt_injection_guard">Prompt Injection Guard</option>
            <option value="ai">AI Advisory</option>
          </select>

          {filesList.length > 1 && (
            <select value={selectedFile} onChange={(e) => setSelectedFile(e.target.value)} className="filter-select">
              <option value="ALL">All Files ({filesList.length})</option>
              {filesList.map(f => (
                <option key={f} value={f}>{f}</option>
              ))}
            </select>
          )}
        </div>

        <div className="findings-count-label">
          Showing <strong>{filteredFindings.length}</strong> of {findings.length} findings
        </div>
      </div>

      {/* Main Two-Column Layout */}
      <div className="findings-explorer-layout">
        {/* Left Column: Finding List */}
        <div className="findings-list-column">
          {filteredFindings.length === 0 ? (
            <div className="no-findings-box">
              <CheckCircle2 size={40} className="text-safe" />
              <h4>No matching findings</h4>
              <p>No vulnerabilities identified matching the selected filter criteria.</p>
            </div>
          ) : (
            filteredFindings.map((finding, idx) => {
              const isSelected = selectedFinding?.rule_id === finding.rule_id && selectedFinding?.line === finding.line;
              const sevClass = (finding.severity || 'low').toLowerCase();

              return (
                <div 
                  key={idx} 
                  className={`finding-card ${sevClass} ${isSelected ? 'selected' : ''}`}
                  onClick={() => setSelectedFinding(finding)}
                >
                  <div className="finding-card-top">
                    <span className={`sev-tag ${sevClass}`}>{finding.severity}</span>
                    <span className="source-tag">{finding.source || 'scanner'}</span>
                  </div>
                  <h4 className="finding-title">{finding.message}</h4>
                  <div className="finding-card-meta">
                    <span className="file-meta"><FileCode size={13} /> {finding.file_path}:{finding.line || '1'}</span>
                    <span className="rule-meta"><code>{finding.rule_id}</code></span>
                  </div>
                </div>
              );
            })
          )}
        </div>

        {/* Right Column: Finding Inspector */}
        <div className="finding-inspector-column">
          {selectedFinding ? (
            <div className="inspector-card animate-fade-in">
              <div className="inspector-header">
                <div className="inspector-title-row">
                  <span className={`sev-tag ${(selectedFinding.severity || 'low').toLowerCase()}`}>
                    {selectedFinding.severity}
                  </span>
                  <span className="category-tag">{selectedFinding.category || 'Security'}</span>
                  {selectedFinding.requires_verification && (
                    <span className="badge badge-warning">
                      <Sparkles size={12} /> AI Advisory - Verify
                    </span>
                  )}
                </div>
                <h2>{selectedFinding.message}</h2>
                <div className="inspector-location">
                  <strong>Location:</strong> <code>{selectedFinding.file_path}</code> (Line {selectedFinding.line || 'N/A'})
                </div>
              </div>

              {/* OWASP & CWE Badges */}
              {(selectedFinding.owasp?.length > 0 || selectedFinding.cwe?.length > 0) && (
                <div className="tags-row">
                  {selectedFinding.owasp?.map((o, i) => (
                    <span key={i} className="tag-pill owasp-pill">{o}</span>
                  ))}
                  {selectedFinding.cwe?.map((c, i) => (
                    <span key={i} className="tag-pill cwe-pill">{c}</span>
                  ))}
                </div>
              )}

              {/* Explanation & Impact */}
              <div className="inspector-section">
                <h3>Vulnerability Explanation</h3>
                <p className="inspector-text">{selectedFinding.explanation || selectedFinding.message}</p>
              </div>

              {selectedFinding.risk && (
                <div className="inspector-section">
                  <h3>Security Risk & Impact</h3>
                  <p className="inspector-text">{selectedFinding.risk}</p>
                </div>
              )}

              {/* Remediation Points */}
              {selectedFinding.remediation?.length > 0 && (
                <div className="inspector-section">
                  <h3>Recommended Remediation</h3>
                  <ul className="remediation-list">
                    {selectedFinding.remediation.map((rem, i) => (
                      <li key={i}>{rem}</li>
                    ))}
                  </ul>
                </div>
              )}

              {/* Suggested Code Fix */}
              {selectedFinding.fixed_code && (
                <div className="inspector-section">
                  <div className="section-header-row">
                    <h3>Suggested Code Fix</h3>
                    <button className="btn-copy" onClick={() => handleCopyCode(selectedFinding.fixed_code)}>
                      {copied ? <Check size={14} /> : <Copy size={14} />} {copied ? 'Copied' : 'Copy'}
                    </button>
                  </div>
                  <pre className="code-fix-block">
                    <code>{selectedFinding.fixed_code}</code>
                  </pre>
                </div>
              )}
            </div>
          ) : (
            <div className="inspector-empty-state">
              <ShieldAlert size={48} className="text-muted" />
              <p>Select a security finding on the left to view detailed explanation and remediation steps.</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
