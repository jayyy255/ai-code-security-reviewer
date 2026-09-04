import tempfile
import os
import shutil
import subprocess
import json
import re
from pathlib import Path
from app.services.scanner_interface import BaseScanner, ScannerStatusModel

FALLBACK_SECRET_PATTERNS = [
    (r"(?i)(AKIA|ASIA)[0-9A-Z]{16}", "aws-access-key", "CRITICAL", "Exposed AWS Access Key ID"),
    (r"gh[pousr]_[A-Za-z0-9_]{20,255}", "github-pat", "CRITICAL", "Exposed GitHub Personal Access Token"),
    (r"xox[baprs]-[0-9a-zA-Z]{10,48}", "slack-token", "HIGH", "Exposed Slack Bot or User Token"),
    (r"sk_(live|test)_[0-9a-zA-Z]{24,99}", "stripe-api-key", "CRITICAL", "Exposed Stripe API Key"),
    (r"sk-[a-zA-Z0-9]{32,64}", "openai-api-key", "HIGH", "Exposed OpenAI API Key"),
    (r"AIza[0-9A-Za-z\-_]{35}", "google-api-key", "HIGH", "Exposed Google Cloud / Maps API Key"),
    (r"-----BEGIN[ A-Z0-9_-]+PRIVATE KEY-----", "private-key", "CRITICAL", "Exposed RSA/EC Private Key"),
    (r"(postgres|mysql|mongodb|redis|amqp):\/\/[a-zA-Z0-9_\-\.]+:[a-zA-Z0-9_\-\.\@]+@[a-zA-Z0-9_\-\.]+", "database-secret", "HIGH", "Exposed Database Connection URI with password")
]

class GitleaksScanner(BaseScanner):
    def __init__(self):
        self.executable = self._locate_gitleaks()

    def _locate_gitleaks(self) -> str | None:
        cmd = shutil.which("gitleaks")
        if cmd:
            return cmd
        if os.path.exists(r"E:\gitleaks.exe"):
            return r"E:\gitleaks.exe"
        return None

    def get_status(self) -> ScannerStatusModel:
        available = self.executable is not None
        return ScannerStatusModel(
            scanner_name="Gitleaks",
            available=available,
            version="8.x" if available else None,
            rules_loaded=160 if available else len(FALLBACK_SECRET_PATTERNS),
            capabilities=[
                "High-entropy secret detection",
                "API key and credential scanning",
                "Built-in fallback regex engine"
            ],
            limitations=[
                "Does not verify live token revocation status",
                "May flag synthetic or test secrets in documentation"
            ],
            status_message="Operational (Binary)" if available else "Operational (Fallback Regex Engine)"
        )

    def scan_code(self, code: str, language: str | None = None, file_name: str = "snippet") -> list[dict]:
        if not code:
            return []

        cli_findings = []
        if self.executable:
            try:
                with tempfile.TemporaryDirectory() as temp_dir:
                    ext = f".{language}" if language else ".txt"
                    temp_file = Path(temp_dir) / f"scan_target{ext}"
                    temp_file.write_text(code, encoding="utf-8", errors="ignore")
                    cli_findings = self._run_gitleaks_cli(temp_dir, file_name=file_name)
            except Exception:
                pass

        regex_findings = self._run_regex_fallback(code, file_name=file_name)
        combined = { (f.get("line"), f.get("rule_id")): f for f in (cli_findings + regex_findings) }
        return list(combined.values())

    def scan_path(self, target_path: str) -> list[dict]:
        if not os.path.exists(target_path):
            return []

        if self.executable:
            findings = self._run_gitleaks_cli(target_path)
            if findings:
                return findings

        # Run regex fallback over all files in target_path
        all_findings = []
        if os.path.isfile(target_path):
            try:
                content = Path(target_path).read_text(encoding="utf-8", errors="ignore")
                all_findings.extend(self._run_regex_fallback(content, file_name=os.path.basename(target_path)))
            except Exception:
                pass
        else:
            for root, _, files in os.walk(target_path):
                for f in files:
                    fp = os.path.join(root, f)
                    try:
                        content = Path(fp).read_text(encoding="utf-8", errors="ignore")
                        rel_path = os.path.relpath(fp, target_path)
                        all_findings.extend(self._run_regex_fallback(content, file_name=rel_path))
                    except Exception:
                        pass
        return all_findings

    def _run_gitleaks_cli(self, target_dir: str, file_name: str | None = None) -> list[dict]:
        try:
            result = subprocess.run(
                [self.executable, "dir", target_dir, "-f", "json", "-r", "-"],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="ignore",
                timeout=60
            )

            if not result.stdout.strip():
                return []

            raw_findings = json.loads(result.stdout)
            findings = []
            for item in raw_findings:
                rule_id = item.get("RuleID") or "secret"
                file_found = item.get("File", "snippet")
                display_file = file_name or (os.path.relpath(file_found, target_dir) if os.path.isdir(target_dir) else os.path.basename(file_found))

                findings.append({
                    "scanner": "gitleaks",
                    "rule_id": rule_id,
                    "file_path": display_file,
                    "line": item.get("StartLine", 1),
                    "column": item.get("StartColumn", 1),
                    "severity": "CRITICAL" if any(k in rule_id.lower() for k in ["pat", "key", "token", "secret", "private"]) else "HIGH",
                    "category": "secrets",
                    "message": item.get("Description") or "Hardcoded secret or credential detected.",
                    "source": "gitleaks",
                    "confidence": "HIGH",
                    "owasp": ["A07:2021 - Identification and Authentication Failures"],
                    "cwe": ["CWE-798: Use of Hard-coded Credentials"],
                    "vulnerability_class": ["Hardcoded Secret", "Credential Exposure"],
                    "likelihood": "HIGH",
                    "impact": "HIGH",
                    "explanation": None,
                    "risk": None,
                    "remediation": [
                        "Revoke the exposed credential immediately.",
                        "Move secrets to environment variables or secret vaults (e.g. AWS Secrets Manager, HashiCorp Vault).",
                        "Rotate existing access keys."
                    ],
                    "fixed_code": None,
                    "requires_verification": False
                })
            return findings
        except Exception as e:
            print(f"Gitleaks CLI scan failed: {e}")
            return []

    def _run_regex_fallback(self, content: str, file_name: str = "snippet") -> list[dict]:
        findings = []
        lines = content.splitlines()

        for regex_pattern, rule_id, severity, description in FALLBACK_SECRET_PATTERNS:
            compiled = re.compile(regex_pattern)
            for idx, line in enumerate(lines, start=1):
                if compiled.search(line):
                    findings.append({
                        "scanner": "gitleaks_pattern_engine",
                        "rule_id": rule_id,
                        "file_path": file_name,
                        "line": idx,
                        "column": 1,
                        "severity": severity,
                        "category": "secrets",
                        "message": description,
                        "source": "gitleaks",
                        "confidence": "HIGH",
                        "owasp": ["A07:2021 - Identification and Authentication Failures"],
                        "cwe": ["CWE-798: Use of Hard-coded Credentials"],
                        "vulnerability_class": ["Hardcoded Secret", "Credential Exposure"],
                        "likelihood": "HIGH",
                        "impact": "HIGH",
                        "explanation": None,
                        "risk": None,
                        "remediation": [
                            "Revoke the exposed key/token immediately.",
                            "Store secrets in environment variables or key management services.",
                            "Ensure secrets are never committed into version control."
                        ],
                        "fixed_code": None,
                        "requires_verification": False
                    })
        return findings

# Singleton instance
gitleaks_scanner = GitleaksScanner()

def run_secret_scan(code: str, language: str | None = None, file_name: str = "snippet") -> list[dict]:
    return gitleaks_scanner.scan_code(code, language, file_name)

def run_path_secret_scan(target_path: str) -> list[dict]:
    return gitleaks_scanner.scan_path(target_path)