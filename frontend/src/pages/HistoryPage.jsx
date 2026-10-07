import { useState, useEffect } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { 
  History, 
  Trash2, 
  Eye, 
  Code,
  ShieldAlert,
  ArrowRight,
} from 'lucide-react';
import { useAuth } from '../components/UserContext';
import { getHistory, deleteFromHistory, clearHistory } from '../services/api';
import './HistoryPage.css';

export default function HistoryPage() {
  const navigate = useNavigate();
  const { loading: sessionLoading, currentUser } = useAuth();
  const [history, setHistory] = useState([]);
  const [error, setError] = useState('');

  useEffect(() => {
    if (sessionLoading) return;
    async function loadHistory() {
      try {
        const data = await getHistory();
        setHistory(data);
      } catch (err) { setError(err.message); }
    }
    loadHistory();
  }, [sessionLoading, currentUser]);

  const handleDeleteItem = async (id, e) => {
    e.stopPropagation(); // Avoid triggering row navigate click
    if (window.confirm("Are you sure you want to delete this scan record?")) {
      try {
        await deleteFromHistory(id);
        setHistory(await getHistory());
        setError('');
      } catch (err) { setError(err.message); }
    }
  };

  const handleClearAll = async () => {
    if (window.confirm("WARNING: Are you sure you want to clear your entire scan history? This action is permanent.")) {
      try {
        await clearHistory();
        setHistory([]);
        setError('');
      } catch (err) { setError(err.message); }
    }
  };

  const navigateToResult = (item) => {
    navigate(`/results/${item.analysis_id}`);
  };

  // Color selection for scores
  const getScoreBadgeClass = (score) => {
    if (score >= 90) return 'safe';
    if (score >= 70) return 'warning';
    return 'critical';
  };

  return (
    <div className="container history-container animate-fade-in">
      <div className="history-header">
        <div className="flex items-center gap-4">
          <History size={24} className="purple-text" />
          <h1>Analysis History Vault</h1>
        </div>
        
        {history.length > 0 && (
          <button onClick={handleClearAll} className="btn btn-secondary flex items-center gap-4" style={{ color: 'var(--severity-critical)', borderColor: 'var(--severity-critical-border)' }}>
            <Trash2 size={16} />
            Purge History
          </button>
        )}
      </div>

      {error && <p role="alert" className="scan-error-alert">{error}</p>}
      {history.length > 0 ? (
        <div className="card history-table-card animate-fade-in">
          <div className="history-table-wrapper">
            <table className="history-table">
              <thead>
                <tr>
                  <th>Date & Time</th>
                  <th>Language</th>
                  <th>Security Health</th>
                  <th>Critical Issues</th>
                  <th>Findings Count</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {history.map((item) => (
                  <tr key={item.analysis_id} onClick={() => navigateToResult(item)} style={{ cursor: 'pointer' }}>
                    <td>
                      {new Date(item.timestamp).toLocaleString(undefined, { 
                        month: 'short', 
                        day: 'numeric', 
                        hour: '2-digit', 
                        minute: '2-digit' 
                      })}
                    </td>
                    <td style={{ textTransform: 'capitalize' }}>
                      <span className="flex items-center gap-4">
                        <Code size={14} className="purple-text" />
                        {item.language}
                      </span>
                    </td>
                    <td>
                      <span className={`score-cell-badge ${getScoreBadgeClass(item.score)}`}>
                        {Math.round(item.score)}
                      </span>
                    </td>
                    <td>
                      <div className={`critical-count-indicator ${item.critical > 0 ? 'active' : 'zero'}`}>
                        <ShieldAlert size={14} />
                        <span>{item.critical}</span>
                      </div>
                    </td>
                    <td>
                      <span className="meta-value">{item.findings ? item.findings.length : 0} found</span>
                    </td>
                    <td>
                      <div className="action-buttons-cell">
                        <button 
                          onClick={(e) => { e.stopPropagation(); navigateToResult(item); }} 
                          className="action-icon-btn view"
                          title="Open report"
                        >
                          <Eye size={14} />
                        </button>
                        <button 
                          onClick={(e) => handleDeleteItem(item.analysis_id, e)} 
                          className="action-icon-btn delete"
                          title="Delete report"
                        >
                          <Trash2 size={14} />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      ) : (
        <div className="card empty-vault-card animate-fade-in">
          <div className="empty-vault-icon-box">
            <History size={32} />
          </div>
          <h2>Your Security Vault is Empty</h2>
          <p style={{ maxWidth: '420px', margin: '0 auto' }}>
            You haven't run any code scans yet. Run a security scan in the workspace to view records, scores, and AI recommendations here.
          </p>
          <Link to="/analyze" className="btn btn-primary" style={{ marginTop: '10px' }}>
            Go to Workspace
            <ArrowRight size={16} />
          </Link>
        </div>
      )}
    </div>
  );
}
