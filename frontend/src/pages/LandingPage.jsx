import { Link } from 'react-router-dom';
import { 
  ShieldAlert, 
  Key, 
  PieChart, 
  Sparkles, 
  ArrowRight, 
  Terminal,
} from 'lucide-react';
import './LandingPage.css';

export default function LandingPage() {
  return (
    <div className="container landing-container animate-fade-in">
      <section className="hero-section">
        <div className="hero-glow"></div>
        
        <div className="hero-badge">
          <Sparkles size={14} className="hero-sparkle-icon" />
          <span>Powered by Gemini AI, Semgrep & Gitleaks</span>
        </div>
        
        <h1 className="hero-title">
          Secure Your Codebase<br />With AI-Powered Analysis
        </h1>
        
        <p className="hero-subtitle">
          Detect vulnerabilities, identify exposed credentials, and get instant, 
          intelligent code recommendations explained in plain English.
        </p>
        
        <div className="hero-ctas">
          <Link to="/analyze" className="btn btn-primary">
            Start Analysis
            <ArrowRight size={16} />
          </Link>
          <a href="#features" className="btn btn-secondary">
            Learn More
          </a>
        </div>
      </section>

      {/* Interactive Mockup Teaser */}
      <section className="demo-section">
        <div className="demo-header">
          <div className="demo-dots">
            <span className="demo-dot red"></span>
            <span className="demo-dot yellow"></span>
            <span className="demo-dot green"></span>
          </div>
          <div className="demo-tab flex items-center gap-4">
            <Terminal size={12} />
            <span>analysis_job_demo.py</span>
          </div>
          <div style={{ width: '40px' }}></div>
        </div>
        
        <div className="demo-body">
          <div className="demo-code-pane">
            <div className="demo-code-glow"></div>
            <code>
              <span className="demo-code-keyword">import</span> os<br />
              <span className="demo-code-keyword">import</span> sys<br /><br />
              <span className="demo-code-comment"># EXPOSED CREDENTIALS</span><br />
              token = <span className="demo-code-string">"ghp_13A8F2Kj9s9823M..."</span><br /><br />
              <span className="demo-code-comment"># REMOTE CODE EXECUTION</span><br />
              <span className="demo-code-keyword">def</span> <span className="demo-code-func">run_ping</span>(ip):<br />
              &nbsp;&nbsp;os.system(<span className="demo-code-string">"ping "</span> + ip)<br />
            </code>
          </div>
          
          <div className="demo-result-pane">
            <div className="demo-alert-card">
              <div className="demo-alert-title">
                <ShieldAlert size={16} />
                <span>CRITICAL VULNERABILITY FOUND</span>
              </div>
              <div className="demo-alert-desc">
                <strong>Command Injection:</strong> Passing unvalidated user input <code>ip</code> directly to a system command is highly unsafe.
              </div>
              <div className="demo-fix-header">Gemini Recommended Fix</div>
              <div className="demo-fix-code">
                subprocess.run(["ping", "-c", "1", ip], check=True)
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Features Section */}
      <section id="features" className="features-section">
        <div className="section-header">
          <h2 className="section-title">Comprehensive Security Scanning</h2>
          <p className="section-subtitle">
            Combines battle-tested static analysis with Gemini AI to understand, score, and remediate security issues.
          </p>
        </div>
        
        <div className="features-grid">
          <div className="card feature-card card-hover">
            <div className="feature-icon-box">
              <ShieldAlert size={22} />
            </div>
            <h3>Vulnerability Detection</h3>
            <p>
              Checks source code for injections (SQL, command), unsafe desig patterns, and library security flaws using Semgrep.
            </p>
          </div>
          
          <div className="card feature-card card-hover">
            <div className="feature-icon-box">
              <Key size={22} />
            </div>
            <h3>Secret Detection</h3>
            <p>
              Scans files for hardcoded API keys, tokens, SSH keys, passwords, and other high-risk credentials using Gitleaks rules.
            </p>
          </div>
          
          <div className="card feature-card card-hover">
            <div className="feature-icon-box">
              <PieChart size={22} />
            </div>
            <h3>Security Scoring</h3>
            <p>
              Generates a normalized security grade (0-100) reflecting the overall health, density, and severity of bugs in your code.
            </p>
          </div>
          
          <div className="card feature-card card-hover">
            <div className="feature-icon-box">
              <Sparkles size={22} />
            </div>
            <h3>AI-Powered Remedies</h3>
            <p>
              Translates confusing warning outputs into simple language. Provides concrete examples and copy-paste secure code overrides.
            </p>
          </div>
        </div>
      </section>
    </div>
  );
}
