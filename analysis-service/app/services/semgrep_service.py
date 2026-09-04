import json
import subprocess
import tempfile
import os
from pathlib import Path
from app.services.scanner_interface import BaseScanner, ScannerStatusModel

LANGUAGE_EXTENSION_MAP = {
    "python": ".py",
    "py": ".py",
    "javascript": ".js",
    "js": ".js",
    "jsx": ".jsx",
    "typescript": ".ts",
    "ts": ".ts",
    "tsx": ".tsx",
    "java": ".java",
    "go": ".go",
    "golang": ".go",
    "c": ".c",
    "cpp": ".cpp",
    "c++": ".cpp",
    "cc": ".cpp",
    "csharp": ".cs",
    "c#": ".cs",
    "cs": ".cs",
    "ruby": ".rb",
    "rb": ".rb",
    "php": ".php",
    "rust": ".rs",
    "rs": ".rs",
    "scala": ".scala",
    "kotlin": ".kt",
    "kt": ".kt",
    "dockerfile": "Dockerfile",
    "docker": "Dockerfile",
    "terraform": ".tf",
    "tf": ".tf",
    "yaml": ".yml",
    "yml": ".yml",
    "json": ".json",
    "html": ".html",
    "sh": ".sh",
    "bash": ".sh"
}

SEVERITY_MAP = {
    "ERROR": "HIGH",
    "WARNING": "MEDIUM",
    "INFO": "LOW",
    "CRITICAL": "CRITICAL"
}

# Resolve rules directory relative to analysis-service
RULES_DIR = Path(__file__).resolve().parent.parent.parent / "rules"

class SemgrepScanner(BaseScanner):
    def __init__(self, rules_path: Path | None = None):
        self.rules_path = rules_path or RULES_DIR
        self._version = self._detect_version()

    def _detect_version(self) -> str | None:
        try:
            res = subprocess.run(["semgrep", "--version"], capture_output=True, text=True, timeout=5)
            if res.returncode == 0:
                return res.stdout.strip().splitlines()[0]
        except Exception:
            pass
        return None

    def get_status(self) -> ScannerStatusModel:
        available = self._version is not None
        rule_files = list(self.rules_path.glob("*.yml")) if self.rules_path.exists() else []
        return ScannerStatusModel(
            scanner_name="Semgrep",
            available=available,
            version=self._version,
            rules_loaded=len(rule_files),
            capabilities=[
                "Multi-language AST pattern matching",
                "Custom security rulesets (14 categories)",
                "OWASP Top 10 & CWE classification",
                "Zero-runtime execution safety"
            ],
            limitations=[
                "Static rule-based analysis (does not simulate dynamic runtime state)",
                "Cross-repository inter-procedural taint analysis requires Semgrep Pro/Enterprise engine",
                "Does not perform live binary disassembly or malware payload execution"
            ],
            status_message="Operational" if available else "Semgrep executable not found in PATH"
        )

    def scan_code(self, code: str, language: str | None = None, file_name: str = "snippet") -> list[dict]:
        clean_lang = (language or "").lower().strip()
        ext = LANGUAGE_EXTENSION_MAP.get(clean_lang, ".txt")

        # Handle Dockerfile naming
        suffix = ext if ext.startswith(".") else f".{clean_lang or 'txt'}"

        temp_file = tempfile.NamedTemporaryFile(mode="w", suffix=suffix, delete=False, encoding="utf-8")
        try:
            temp_file.write(code)
            temp_file.close()
            temp_path = temp_file.name
            findings = self._run_semgrep_on_target(temp_path, original_file_name=file_name)
            return findings
        finally:
            if os.path.exists(temp_file.name):
                os.unlink(temp_file.name)

    def scan_path(self, target_path: str) -> list[dict]:
        if not os.path.exists(target_path):
            return []
        return self._run_semgrep_on_target(target_path)

    def _run_semgrep_on_target(self, target_path: str, original_file_name: str | None = None) -> list[dict]:
        cmd = ["semgrep", "scan", "--json"]

        # If custom rules exist, include them
        if self.rules_path.exists() and any(self.rules_path.glob("*.yml")):
            cmd.extend(["--config", str(self.rules_path)])
        else:
            cmd.extend(["--config", "auto"])

        cmd.append(target_path)

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="ignore",
                timeout=120
            )

            # Semgrep returns 0 for no findings, 1 for findings found
            if result.returncode not in (0, 1):
                # Fallback to auto config if custom rules errored
                fallback = subprocess.run(
                    ["semgrep", "scan", "--config", "auto", target_path, "--json"],
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="ignore",
                    timeout=120
                )
                if fallback.returncode in (0, 1) and fallback.stdout.strip():
                    data = json.loads(fallback.stdout)
                else:
                    return []
            else:
                data = json.loads(result.stdout) if result.stdout.strip() else {"results": []}

            findings = []
            for finding in data.get("results", []):
                extra = finding.get("extra", {})
                metadata = extra.get("metadata", {})
                raw_sev = (extra.get("severity") or metadata.get("severity") or "LOW").upper()

                line_num = finding.get("start", {}).get("line")
                col_num = finding.get("start", {}).get("col")
                path_found = finding.get("path", target_path)

                # If single snippet scan, use original filename
                if original_file_name:
                    display_path = original_file_name
                else:
                    # Clean up temp prefixes in relative paths
                    display_path = os.path.relpath(path_found, target_path) if os.path.isdir(target_path) else os.path.basename(path_found)

                # Determine category
                category = metadata.get("category") or "security"

                findings.append({
                    "scanner": "semgrep",
                    "rule_id": finding.get("check_id") or "semgrep.rule",
                    "file_path": display_path,
                    "line": line_num,
                    "column": col_num,
                    "severity": SEVERITY_MAP.get(raw_sev, "LOW"),
                    "category": category,
                    "message": extra.get("message") or "Security rule triggered.",
                    "source": "semgrep",
                    "confidence": metadata.get("confidence") or "HIGH",
                    "owasp": metadata.get("owasp", []),
                    "cwe": metadata.get("cwe", []),
                    "vulnerability_class": metadata.get("vulnerability_class", []),
                    "likelihood": metadata.get("likelihood") or "MEDIUM",
                    "impact": metadata.get("impact") or "MEDIUM",
                    "explanation": None,
                    "risk": None,
                    "remediation": [],
                    "fixed_code": None,
                    "requires_verification": False
                })

            return findings

        except Exception as e:
            print(f"Semgrep execution error: {e}")
            return []

# Singleton instance
semgrep_scanner = SemgrepScanner()

def run_scan(code: str, language: str | None = None, file_name: str = "snippet") -> list[dict]:
    return semgrep_scanner.scan_code(code, language, file_name)

def run_path_scan(target_path: str) -> list[dict]:
    return semgrep_scanner.scan_path(target_path)