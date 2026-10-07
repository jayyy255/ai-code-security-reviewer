import json
import subprocess
import tempfile
import os
import yaml
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
        rule_count = sum(len((yaml.safe_load(path.read_text(encoding="utf-8")) or {}).get("rules", [])) for path in rule_files)
        return ScannerStatusModel(
            scanner_name="Semgrep",
            available=available,
            version=self._version,
            rules_loaded=rule_count,
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

        if not clean_lang and file_name != "snippet":
            ext = Path(file_name).suffix or ".txt"
        with tempfile.TemporaryDirectory() as directory:
            name = "Dockerfile" if ext == "Dockerfile" or file_name.lower() == "dockerfile" else "scan_target" + ext
            temp_path = Path(directory) / name
            temp_path.write_text(code, encoding="utf-8")
            findings = self._run_semgrep_on_target(str(temp_path), original_file_name=file_name)
            code_lines = code.splitlines()
            for finding in findings:
                line = finding.get("line")
                if isinstance(line, int) and 1 <= line <= len(code_lines):
                    finding["snippet"] = code_lines[line - 1].strip()
            return findings

    def scan_path(self, target_path: str) -> list[dict]:
        if not os.path.exists(target_path):
            return []
        findings = self._run_semgrep_on_target(target_path)
        for f in findings:
            if not f.get("snippet") and f.get("line"):
                resolved = os.path.join(target_path, f.get("file_path", "")) if os.path.isdir(target_path) else target_path
                if os.path.isfile(resolved):
                    try:
                        flines = Path(resolved).read_text(encoding="utf-8", errors="ignore").splitlines()
                        if 1 <= f["line"] <= len(flines):
                            f["snippet"] = flines[f["line"] - 1].strip()
                    except Exception:
                        pass
        return findings

    def _run_semgrep_on_target(self, target_path: str, original_file_name: str | None = None) -> list[dict]:
        cmd = ["semgrep", "scan", "--json", "--metrics=off", "--disable-version-check", "--no-git-ignore"]

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

            if result.returncode not in (0, 1):
                raise RuntimeError("Semgrep scan failed. Check the engine and local rule configuration.")
            data = json.loads(result.stdout)
            if data.get("errors"):
                raise RuntimeError("Semgrep could not fully parse or scan the submitted files. Check the selected language and syntax.")

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
                raw_lines = extra.get("lines")
                snippet = raw_lines.strip() if isinstance(raw_lines, str) and raw_lines.strip() else None

                findings.append({
                    "scanner": "semgrep",
                    "rule_id": finding.get("check_id") or "semgrep.rule",
                    "file_path": display_path,
                    "line": line_num,
                    "column": col_num,
                    "snippet": snippet,
                    "severity": metadata.get("severity", SEVERITY_MAP.get(raw_sev, "LOW")).upper(),
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
            raise RuntimeError("Static analysis did not complete. No security report was produced.") from e

# Singleton instance
semgrep_scanner = SemgrepScanner()

def run_scan(code: str, language: str | None = None, file_name: str = "snippet") -> list[dict]:
    return semgrep_scanner.scan_code(code, language, file_name)

def run_path_scan(target_path: str) -> list[dict]:
    return semgrep_scanner.scan_path(target_path)