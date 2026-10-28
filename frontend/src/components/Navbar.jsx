import { useRef, useState } from 'react';
import { NavLink, Link } from 'react-router-dom';
import { ShieldAlert, Sparkles, Code, History, User, LogOut, Menu, X, Sun, Moon } from 'lucide-react';
import { useAuth } from '../components/UserContext';
import { useTheme } from '../services/theme';

export default function Navbar() {
  const { currentUser, isAuthenticated, logout, error } = useAuth();
  const { theme, toggleTheme } = useTheme();
  const [menuOpen, setMenuOpen] = useState(false);
  const menuToggleRef = useRef(null);

  const handleLogout = async () => {
    try {
      await logout();
      setMenuOpen(false);
    } catch (err) {
      console.error('Logout failed:', err);
    }
  };

  return (
    <nav className="navbar" aria-label="Main navigation" onKeyDown={event => { if (event.key === 'Escape' && menuOpen) { setMenuOpen(false); menuToggleRef.current?.focus(); } }}>
      <div className="container nav-container">
        <Link to="/" className="logo-link" onClick={() => setMenuOpen(false)}>
          <div className="logo-icon-wrapper">
            <ShieldAlert size={22} className="logo-shield" />
            <Sparkles size={12} className="logo-sparkle" />
          </div>
          <span className="logo-text">AI Code <span className="purple-text">Security Reviewer</span></span>
        </Link>
        
        <div className="nav-appearance-controls">
          <button type="button" className="theme-toggle" onClick={toggleTheme} aria-label={`Switch to ${theme === 'dark' ? 'light' : 'dark'} mode`} title={`Switch to ${theme === 'dark' ? 'light' : 'dark'} mode`}>
            {theme === 'dark' ? <Sun size={20} /> : <Moon size={20} />}
          </button>
        <button ref={menuToggleRef} type="button" className="nav-menu-toggle" aria-expanded={menuOpen} aria-controls="main-navigation-links" aria-label={menuOpen ? 'Close navigation menu' : 'Open navigation menu'} onClick={() => setMenuOpen(open => !open)}>
          {menuOpen ? <X size={22} /> : <Menu size={22} />}
        </button>
        </div>
        <div id="main-navigation-links" className={`nav-links ${menuOpen ? 'is-open' : ''}`} onClick={event => { if (event.target.closest('a')) setMenuOpen(false); }}>
          <NavLink 
            to="/" 
            className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}
            end
          >
            Home
          </NavLink>
          <NavLink 
            to="/analyze" 
            className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}
          >
            <Code size={16} />
            Analyze
          </NavLink>
          <NavLink 
            to="/history" 
            className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}
          >
            <History size={16} />
            History
          </NavLink>

          <div className="nav-separator" style={{ width: '1px', backgroundColor: 'var(--border-color)', margin: '0 8px' }}></div>

          {isAuthenticated ? (
            <div className="flex items-center gap-4">
              <div className="user-profile-badge" style={{ display: 'flex', alignItems: 'center', gap: '8px', padding: '4px 10px', background: 'var(--bg-input)', border: '1px solid var(--border-color)', borderRadius: '20px', fontSize: '0.88rem', fontWeight: 500, color: 'var(--text-primary)' }}>
                <User size={14} className="purple-text" />
                <span>{currentUser.username}</span>
              </div>
              <button 
                onClick={handleLogout} 
                className="nav-item btn-logout" 
                style={{ background: 'transparent', border: 'none', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '6px', color: 'var(--text-secondary)' }}
                title="Sign Out"
              >
                <LogOut size={16} />
                <span className="logout-text">Logout</span>
              </button>
            </div>
          ) : (
            <div className="flex items-center gap-4">
              <NavLink 
                to="/login" 
                className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}
              >
                Login
              </NavLink>
              <NavLink 
                to="/signup" 
                className="btn btn-primary"
                style={{ padding: '6px 14px', fontSize: '0.85rem', height: '32px', boxShadow: 'none' }}
              >
                Sign Up
              </NavLink>
            </div>
          )}
        </div>
      </div>
      {error && isAuthenticated && <p role="alert" className="container">{error}</p>}
    </nav>
  );
}
