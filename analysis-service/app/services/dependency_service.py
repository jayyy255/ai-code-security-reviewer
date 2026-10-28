"""Query OSV for exact locked versions. Never install or execute dependencies."""
import json
import re
import time
from pathlib import PurePosixPath
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import quote
import requests
try:
    import tomllib
except ImportError:
    import tomli as tomllib

OSV_URL = "https://api.osv.dev/v1/"


def parse_dependencies(texts):
    packages, gaps = [], []
    for path, text in texts.items():
        name = path.rsplit("/", 1)[-1].lower()
        found = []
        try:
            if name == "package-lock.json":
                lock = json.loads(text)
                if "packages" in lock:
                    for location, entry in lock["packages"].items():
                        if location and "node_modules/" in location and entry.get("version"):
                            package = entry.get("name") or location.rsplit("node_modules/", 1)[-1]
                            found.append(("npm", package, entry["version"]))
                else:
                    def walk(dependencies, depth=0):
                        if depth > 30:
                            raise ValueError("Nested dependency limit")
                        for package, entry in dependencies.items():
                            if entry.get("version"):
                                found.append(("npm", package, entry["version"]))
                            walk(entry.get("dependencies", {}), depth + 1)
                    walk(lock.get("dependencies", {}))
            elif name.startswith("requirements") and name.endswith(".txt"):
                for line in text.splitlines():
                    match = re.match(r"^\s*([A-Za-z0-9_.-]+)(?:\[[^]]+\])?==([A-Za-z0-9_.+!-]+)(?:\s|;|$)", line)
                    if match:
                        found.append(("PyPI", re.sub(r"[-_.]+", "-", match[1]).lower(), match[2]))
                    elif line.strip() and not line.lstrip().startswith(("#", "--hash", "\\")):
                        gaps.append(f"{path}: unpinned, included, or unsupported Python requirement")
            elif name in ("poetry.lock", "cargo.lock"):
                data = tomllib.loads(text)
                ecosystem = "PyPI" if name == "poetry.lock" else "crates.io"
                for entry in data.get("package", []):
                    if name == "cargo.lock" and not str(entry.get("source", "")).startswith("registry+"):
                        continue
                    if entry.get("name") and entry.get("version"):
                        found.append((ecosystem, entry["name"], entry["version"]))
            elif name == "go.sum":
                for line in text.splitlines():
                    parts = line.split()
                    if len(parts) >= 2 and not parts[1].endswith("/go.mod"):
                        found.append(("Go", parts[0], parts[1]))
            elif name in {"yarn.lock", "pnpm-lock.yaml", "pom.xml", "gradle.lockfile", "packages.lock.json", "composer.lock", "gemfile.lock"}:
                gaps.append(f"{path}: dependency format not yet supported")
            elif name == "package.json" and str(PurePosixPath(path).with_name("package-lock.json")) not in texts:
                gaps.append(f"{path}: exact npm versions need package-lock.json")
            elif name in {"pyproject.toml", "setup.py", "pipfile", "go.mod", "cargo.toml", "build.gradle", "build.gradle.kts", "gemfile", "composer.json"}:
                parent = PurePosixPath(path).parent
                companions = {"pyproject.toml": ("poetry.lock", "requirements.txt"), "setup.py": ("requirements.txt",), "pipfile": ("requirements.txt",),
                    "go.mod": ("go.sum",), "cargo.toml": ("Cargo.lock",)}.get(name, ())
                if not any(str(parent / companion) in texts for companion in companions):
                    gaps.append(f"{path}: exact supported dependency lockfile is missing")
            for ecosystem, package, version in found:
                if not re.fullmatch(r"[0-9][A-Za-z0-9.+!_-]*|v[0-9][A-Za-z0-9.+_-]*", str(version)):
                    gaps.append(f"{path}: non-registry or unresolved package version")
                    continue
                packages.append({"ecosystem": ecosystem, "name": package, "version": version, "path": path})
        except (ValueError, TypeError, AttributeError, RecursionError):
            gaps.append(f"{path}: dependency manifest could not be parsed")
    # A repeated dependency in separate manifests keeps both locations in reports.
    return list({tuple(p.values()): p for p in packages}.values()), sorted(set(gaps))


def _osv_request(path, payload=None, timeout=8):
    response = requests.post(OSV_URL + path, json=payload, timeout=timeout) if payload is not None else requests.get(OSV_URL + path, timeout=timeout)
    response.raise_for_status()
    return response.json()


def scan_dependencies(texts):
    packages, gaps = parse_dependencies(texts)
    status = {"scanner_name": "Dependency advisories (OSV)", "available": True, "status": "completed", "rules_loaded": 0,
        "capabilities": ["Known advisories for exact npm, Python, Rust and Go versions"],
        "limitations": ["Does not prove exploitability; only exact supported versions are queried. Package names and versions are sent to OSV; source code is not."], "status_message": ""}
    if len(packages) > 500:
        gaps.append("Dependency limit: only the first 500 package locations were checked")
    packages = packages[:500]
    findings, matches, records = [], [], {}
    deadline = time.monotonic() + 45
    try:
        for start in range(0, len(packages), 100):
            batch = packages[start:start + 100]
            result = _osv_request("querybatch", {"queries": [{"package": {"ecosystem": p["ecosystem"], "name": p["name"]}, "version": p["version"]} for p in batch]}, timeout=max(1, min(8, deadline - time.monotonic())))
            if len(result.get("results", [])) != len(batch):
                raise ValueError("Incomplete OSV batch response")
            for package, response in zip(batch, result["results"]):
                if response.get("next_page_token"):
                    gaps.append("OSV returned additional advisory pages; review is partial")
                matches.extend((package, vuln["id"]) for vuln in response.get("vulns", []))
            if time.monotonic() > deadline:
                raise TimeoutError("Dependency advisory time limit")
        identifiers = list(dict.fromkeys(v for _, v in matches))
        if len(identifiers) > 60:
            gaps.append("Advisory detail limit: only the first 60 advisory records were resolved")
        def fetch(identifier):
            if time.monotonic() > deadline:
                return identifier, None
            try:
                return identifier, _osv_request("vulns/" + quote(identifier, safe=""), timeout=max(1, min(8, deadline - time.monotonic())))
            except (requests.RequestException, ValueError):
                return identifier, None
        with ThreadPoolExecutor(max_workers=8) as executor:
            records = dict(executor.map(fetch, identifiers[:60]))
        for package, identifier in matches:
            advisory = records.get(identifier)
            if advisory and advisory.get("withdrawn"):
                continue
            if not advisory:
                gaps.append("Some advisory details were unavailable; severity and fixes need verification")
            advisory = advisory or {}
            severity = str(advisory.get("database_specific", {}).get("severity", "")).upper()
            if not severity:
                severity = next((str(affected.get("ecosystem_specific", {}).get("severity", "")).upper() for affected in advisory.get("affected", []) if affected.get("ecosystem_specific", {}).get("severity")), "")
            if severity == "MODERATE":
                severity = "MEDIUM"
            unclassified = severity not in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
            severity = "MEDIUM" if unclassified else severity
            fixes = sorted({event["fixed"] for affected in advisory.get("affected", []) if affected.get("package", {}).get("name") == package["name"]
                for affected_range in affected.get("ranges", []) for event in affected_range.get("events", []) if event.get("fixed")})
            findings.append({"scanner": "osv", "source": "osv", "rule_id": f'{identifier}/{package["name"]}@{package["version"]}', "file_path": package["path"], "severity": severity,
                "category": "dependency_vulnerability", "message": f'{package["name"]}@{package["version"]}: {advisory.get("summary") or identifier}',
                "explanation": (advisory.get("details") or "OSV lists this exact package version as affected.")[:3000] + (" Severity is unclassified in the advisory; medium is used only as a triage default and must be verified." if unclassified else ""),
                "risk": "A known dependency vulnerability may affect this application. Verify whether the vulnerable functionality is reachable.",
                "remediation": [f'Upgrade {package["name"]} to a compatible fixed release' + (f' (published fix boundaries: {", ".join(fixes)})' if fixes else "; consult the advisory for available fixes") + ". Regenerate the lockfile and run regression tests.", f"Review advisory: https://osv.dev/vulnerability/{identifier}"],
                "confidence": "HIGH", "requires_verification": True})
    except (requests.RequestException, ValueError, TimeoutError, KeyError, TypeError):
        gaps.append("OSV could not complete the dependency lookup; absence of findings does not mean dependencies are safe")
        status["available"] = False
        status["status"] = "failed"
    if gaps and status["status"] != "failed":
        status["status"] = "partial"
    if not packages and not gaps:
        status["status"] = "not_applicable"
    status["status_message"] = f"Checked {len(packages)} exact package locations. " + " ".join(gaps)
    return findings, status
