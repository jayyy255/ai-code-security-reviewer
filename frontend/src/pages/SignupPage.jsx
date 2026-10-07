import { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { useAuth } from '../components/UserContext';
import { ShieldAlert, Sparkles, User, Mail, Lock, ArrowRight, AlertCircle } from 'lucide-react';
import './LoginPage.css';

export default function SignupPage() {
  const navigate = useNavigate();
  const { signup } = useAuth();
  
  const [username, setUsername] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [error, setError] = useState('');
  const [submitting, setSubmitting] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!username || !email || !password || !confirmPassword) {
      setError('Please fill in all fields.');
      return;
    }

    if (username.length < 3) {
      setError('Username must be at least 3 characters long.');
      return;
    }

    if (password.length < 6) {
      setError('Password must be at least 6 characters long.');
      return;
    }

    if (password !== confirmPassword) {
      setError('Passwords do not match.');
      return;
    }

    setSubmitting(true);
    setError('');

    try {
      await signup(username, email, password);
      navigate('/analyze');
    } catch (err) {
      setError(err.message || 'Registration failed. Try a different username or email.');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="auth-page-container animate-fade-in">
      <div className="auth-glow-bg"></div>
      
      <div className="card auth-card">
        <div className="auth-header">
          <div className="logo-icon-wrapper auth-logo-shield">
            <ShieldAlert size={28} className="logo-shield purple-text" />
            <Sparkles size={14} className="logo-sparkle" />
          </div>
          <h2>Join AI Code <span className="purple-text">Security Reviewer</span></h2>
          <p>Create a secure account to sync your scan findings</p>
        </div>

        {error && (
          <div className="auth-error-box animate-fade-in">
            <AlertCircle size={16} />
            <span>{error}</span>
          </div>
        )}

        <form onSubmit={handleSubmit} className="auth-form">
          <div className="auth-input-group">
            <label htmlFor="username">Username</label>
            <div className="auth-input-wrapper">
              <User size={16} className="auth-input-icon" />
              <input
                id="username"
                type="text"
                className="text-input auth-text-input"
                placeholder="Choose username"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                disabled={submitting}
                required
              />
            </div>
          </div>

          <div className="auth-input-group">
            <label htmlFor="email">Email Address</label>
            <div className="auth-input-wrapper">
              <Mail size={16} className="auth-input-icon" />
              <input
                id="email"
                type="email"
                className="text-input auth-text-input"
                placeholder="you@example.com"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                disabled={submitting}
                required
              />
            </div>
          </div>

          <div className="auth-input-group">
            <label htmlFor="password">Password</label>
            <div className="auth-input-wrapper">
              <Lock size={16} className="auth-input-icon" />
              <input
                id="password"
                type="password"
                className="text-input auth-text-input"
                placeholder="Min. 6 characters"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                disabled={submitting}
                required
              />
            </div>
          </div>

          <div className="auth-input-group">
            <label htmlFor="confirmPassword">Confirm Password</label>
            <div className="auth-input-wrapper">
              <Lock size={16} className="auth-input-icon" />
              <input
                id="confirmPassword"
                type="password"
                className="text-input auth-text-input"
                placeholder="Repeat password"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                disabled={submitting}
                required
              />
            </div>
          </div>

          <button type="submit" className="btn btn-primary auth-submit-btn" disabled={submitting}>
            {submitting ? 'Creating account...' : 'Create Account'}
            <ArrowRight size={18} />
          </button>
        </form>

        <div className="auth-footer">
          <span>Already secure? <Link to="/login" className="purple-text font-medium">Sign in here</Link></span>
        </div>
      </div>
    </div>
  );
}
