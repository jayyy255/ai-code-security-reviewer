import { Lock } from 'lucide-react';

export default function Footer() {
  return (
    <footer className="footer">
      <div className="container footer-container">
        <div className="footer-left">
          <Lock size={14} className="muted-icon" />
          <span>&copy; {new Date().getFullYear()} AI Code Security Reviewer. All rights reserved.</span>
        </div>
        <div className="footer-right">
          <span>Powered by <span className="tech-badge">Semgrep</span> + <span className="tech-badge">Gitleaks</span> + <span className="tech-badge">Gemini AI</span></span>
        </div>
      </div>
    </footer>
  );
}
