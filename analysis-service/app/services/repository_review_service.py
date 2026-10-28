"""Bounded, tracked-file snapshot extraction without executing repository code."""
import re
from pathlib import Path, PurePosixPath

MAX_FILES = 5000
MAX_BYTES = 100 * 1024 * 1024
MAX_FILE_BYTES = 2 * 1024 * 1024
EXCLUDED = {"node_modules", "vendor", ".venv", "venv", "__pycache__", "dist", "build", ".git"}


def materialize_snapshot(repo, commit_sha: str, destination: Path):
    destination.mkdir(parents=True, exist_ok=True)
    files, skipped, texts = [], [], {}
    total_bytes = 0
    for index, item in enumerate(repo.commit(commit_sha).tree.traverse()):
        if index >= 20000:
            skipped.append("Repository tree limit reached (20,000 entries); remaining entries not inspected.")
            break
        if item.type == "tree":
            continue
        rel = PurePosixPath(item.path)
        # Reject Windows-special names too; materialization is portable and collision-safe.
        unsafe = any(part in (".", "..") or ":" in part or "\\" in part or part.endswith((".", " "))
                     or re.fullmatch(r"(?i)(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?", part) for part in rel.parts)
        if rel.is_absolute() or unsafe or any(part.lower() in EXCLUDED for part in rel.parts):
            skipped.append(f"{item.path}: excluded generated/dependency directory or unsafe path")
            continue
        if item.type != "blob" or item.mode not in (0o100644, 0o100755):
            skipped.append(f"{item.path}: symlink or submodule is not followed")
            continue
        if rel.name.lower() in {".semgrepignore", ".gitleaksignore", ".gitleaks.toml"}:
            skipped.append(f"{item.path}: repository scanner overrides are not applied")
            continue
        if len(files) >= MAX_FILES or item.size > MAX_FILE_BYTES or total_bytes + item.size > MAX_BYTES:
            skipped.append(f"{item.path}: scan size limit")
            continue
        target = destination.joinpath(*rel.parts)
        if not target.resolve().is_relative_to(destination.resolve()) or target.exists():
            skipped.append(f"{item.path}: unsafe or colliding path")
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        data = item.data_stream.read(MAX_FILE_BYTES + 1)
        if len(data) > MAX_FILE_BYTES:
            skipped.append(f"{item.path}: scan size limit")
            continue
        target.write_bytes(data)
        total_bytes += len(data)
        files.append(item.path)
        if b"\x00" not in data[:8192]:
            texts[item.path] = data.decode("utf-8", errors="replace")
    return files, skipped, texts


def repository_configuration_findings(texts: dict[str, str]) -> list[dict]:
    """High-signal configuration checks, with evidence and specific remediation."""
    findings = []
    for path, content in texts.items():
        if path.startswith(".github/workflows/") and path.endswith((".yml", ".yaml")):
            for number, line in enumerate(content.splitlines(), 1):
                message = fix = None
                if re.match(r"^\s*permissions:\s*write-all\s*(?:#.*)?$", line):
                    message = "GitHub Actions grants write permissions to every token scope."
                    fix = "Set permissions to contents: read by default; grant only the specific write scope needed by each job."
                elif re.search(r"\buses:\s*[^\s./][^\s]*@(?:main|master|HEAD)\s*(?:#.*)?$", line):
                    message = "GitHub Actions executes an action from a mutable development branch."
                    fix = "Pin the action to a reviewed full commit SHA and use an update tool to maintain the pin."
                elif "${{" in line and re.search(r"github\.event\.(?:issue|pull_request|comment|discussion)\.", line) and re.search(r"\b(?:run:|echo |curl |sh |bash )", line):
                    message = "Untrusted GitHub event text is interpolated directly into a shell command."
                    fix = "Pass event values through an environment variable and quote its expansion in the shell; do not interpolate expressions into run commands."
                if message:
                    findings.append({"scanner": "repository_config", "source": "repository_config", "rule_id": "workflow-" + ("broad-token" if "permissions" in message else "mutable-action" if "mutable" in message else "expression-injection"),
                        "file_path": path, "line": number, "severity": "HIGH" if "Untrusted" in message else "MEDIUM", "category": "ci_security", "message": message,
                        "snippet": line.strip(), "explanation": message, "risk": "A compromised action or attacker-controlled event can abuse the workflow runner and its token permissions.",
                        "remediation": [fix], "confidence": "MEDIUM", "requires_verification": True})
    return findings
