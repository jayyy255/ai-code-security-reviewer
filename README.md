# AI Code Security Reviewer (v2.0)

A privacy-conscious, multi-mode security review platform that combines **Semgrep AST static analysis**, **Gitleaks secret scanning**, **real malware detection (ClamAV)**, **prompt injection defense**, and **grounded AI advisories (Gemini)**.

---

## Key Features & 3 Scan Modes

### 1. Paste Code Mode
- Multi-language support covering all Semgrep-supported languages (Python, JavaScript, TypeScript, Java, Go, C/C++, C#, Ruby, PHP, Rust, Scala, Kotlin, Dockerfile, Terraform, YAML, JSON, Shell/Bash).
- Input size validation & untrusted data isolation.
- Active Prompt Injection Guard detecting override attempts, system prompt dumps, safety bypasses, and data exfiltration vectors.
- AST vulnerability rules + hardcoded secret detection.
- Honest reporting: plain text streams never claim antivirus protection without a real malware engine.

### 2. Upload File / Archive Mode
- Ingestion security with path traversal sanitization, binary file detection, and isolated sandbox directory cleanup.
- ZIP Bomb & decompression protections (100:1 ratio limit, 100MB uncompressed limit, max 500 entries, recursive archive depth protection).
- Strict execution safety: never executes uploaded scripts, never installs dependencies.
- Classification into 7 categories: `Source code`, `Configuration`, `Text/document`, `Archive`, `Binary/executable`, `Image`, `Unknown`.
- Safe document text extraction for PDF (`pypdf`) and Word (`python-docx`).
- ClamAV malware scanning pipeline reporting: `clean`, `suspicious`, `infected`, `unavailable`, `failed`. Never reports false clean when scanner is unavailable or fails.

### 3. GitHub Repository & Commit Mode
- Supports GitHub URL, optional Branch, and optional Commit SHA.
- Scans current commit state without traversing irrelevant repository history.
- Two scan strategies:
  - **Full Snapshot Scan**: Scans all relevant files in repository snapshot.
  - **Incremental Commit Scan**: Calculates parent diff, identifies added/modified/renamed/deleted files, scans changed files, and compares against previous baseline.
- **Automatic Fallback Triggers**: Forces a full scan when:
  - No baseline exists or parent commit cannot be resolved
  - Merge commit with multiple parents
  - Large percentage of files changed (>30% in repos with 10+ files)
  - Dependency lockfiles modified (`package-lock.json`, `yarn.lock`, `requirements.txt`, `go.sum`, `Cargo.lock`, `pom.xml`, etc.)
  - Security configuration modified (`.semgrep.yml`, `.gitleaks.toml`, etc.)
  - Explicit user choice.
- Commit analysis returns classified findings: `new_findings`, `fixed_findings`, `persistent_findings`.

---

## Privacy & Security Guarantees

1. **No Raw Code Storage by Default**: When storing scan metadata and findings in MongoDB, raw source code is not persisted for full repositories or uploaded archives.
2. **Ephemeral Mode**: Users can toggle Ephemeral Mode to run scans entirely in-memory with zero database persistence.
3. **Snippet-Only AI Context**: The platform never sends entire repositories to the LLM. Only concise finding snippets and surrounding diff context are provided for remediation.
4. **Prompt Injection Hardening**: All scanned code is wrapped in strict untrusted data boundaries with a fixed system prompt forbidding execution of in-code directives.
5. **AI Advisory Transparency**: Every AI-generated remediation is marked with `source: "ai"`, `confidence`, and `requires_verification: true`.

---

## Semgrep Capabilities & Limitations Disclosure

- **Capabilities**: High-speed AST pattern matching across 62+ custom rulesets in 14 categories (SQL/Command/NoSQL injection, Memory safety, Deserialization, XXE, ReDoS, CORS, Hardcoded secrets, Docker & Terraform misconfigurations, Auth bypasses).
- **Limitations**: Static rule-based analysis does not simulate live dynamic runtime state. Cross-repository inter-procedural taint analysis requires proprietary enterprise engines. Does not perform live binary disassembly.

---

## Malware Engine Status Invariant

The malware engine result is strictly one of:
- `clean`: Engine verified zero malicious signatures.
- `suspicious`: Heuristic flags found.
- `infected`: Known malware signature detected (or EICAR test signature).
- `unavailable`: ClamAV engine not installed or unreachable (No false clean reported).
- `failed`: Engine execution errored or timed out.

---

## Architecture

```
                      +------------------------------------------+
                      |         React Frontend (Vite)            |
                      |          http://localhost:5173           |
                      +------------------------------------------+
                                           |
                                           |  Proxies /api requests
                                           v
                      +------------------------------------------+
                      |         Express API Gateway              |
                      |          http://localhost:5000           |
                      +------------------------------------------+
                         /                                    \
                        / Auth, Sessions,                       \ Proxies v1 API Routes
                       /  & Ephemeral / Vault                    \
                      v                                           v
         +--------------------------+               +-------------------------------------+
         |     MongoDB Database     |               |    FastAPI Multi-Mode Engine        |
         |  (Sessions, Users, Vault)|               |    http://localhost:8000            |
         +--------------------------+               +-------------------------------------+
                                                      - Semgrep AST Engine (62 Rules)
                                                      - Gitleaks Secret Scanner
                                                      - ClamAV Malware Pipeline
                                                      - Ingestion & ZIP Bomb Sandbox
                                                      - Git Commit Diff & Baseline Engine
                                                      - Grounded AI Explainer (Gemini)
```

---

## API Documentation (v1 Endpoints)

### 1. `POST /api/v1/files/scan`
Scan single file or pasted code snippet.
- **Request Body**:
  ```json
  {
    "code": "import sqlite3\ncursor.execute(f'SELECT * FROM users WHERE id={uid}')",
    "language": "python",
    "file_name": "app.py",
    "ephemeral": false
  }
  ```
- **Response**:
  ```json
  {
    "analysis_id": "uuid",
    "scan_type": "paste",
    "summary": { "security_score": 50, "critical": 1, "high": 0, "medium": 0, "low": 0 },
    "findings": [ ... ],
    "scanner_status": [ ... ],
    "malware_status": { "status": "unavailable", "engine": "ClamAV", "details": "..." },
    "privacy_metadata": { "raw_code_stored": false, "ephemeral_scan": false }
  }
  ```

### 2. `POST /api/v1/files/scan-batch`
Scan uploaded files, configuration files, documents, or archives.
- **Multipart Form-Data / JSON**:
  - `files`: File objects or array of `{ filename, content }`
  - `ephemeral`: boolean

### 3. `POST /api/v1/commits/analyze`
Analyze GitHub repository commit or full snapshot.
- **Request Body**:
  ```json
  {
    "repository_url": "https://github.com/owner/repo",
    "commit_sha": "7a3f89e",
    "branch": "main",
    "strategy": "auto",
    "baseline_findings": [],
    "ephemeral": false
  }
  ```
- **Response**: Includes `commit_sha`, `parent_sha`, `scan_type` (`full` vs `incremental`), `changed_files`, `new_findings`, `fixed_findings`, `persistent_findings`, `scanner_status`, and `malware_status`.

### 4. `GET /api/v1/scans/:scanId` & `DELETE /api/v1/scans/:scanId`
Retrieve or purge a scan record from the history vault.

---

## Local Setup & Quickstart

### Prerequisites
- Python 3.10+
- Node.js 18+
- Semgrep (`pip install semgrep`)
- Git (`git --version`)
- *(Optional)* ClamAV for live local malware scanning (`clamscan`)

### 1. Start FastAPI Engine
```bash
cd analysis-service
python -m uvicorn app.main:app --port 8000 --reload
```

### 2. Start Express Gateway
```bash
cd express-api
npm install
npm run dev
```

### 3. Start React Frontend
```bash
cd frontend
npm install
npm run dev
```
Open your browser to `http://localhost:5173`.

### 4. Running Automated Tests
```bash
pytest analysis-service/tests/ -v
```
