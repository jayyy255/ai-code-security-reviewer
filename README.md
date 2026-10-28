# AI Code Security Reviewer (v2.0)

A privacy-conscious, multi-mode security review platform that combines **Semgrep AST static analysis**, **Gitleaks secret scanning**, **real malware detection (ClamAV)**, **prompt injection defense**, and **grounded AI advisories (Gemini)**.

---

## Key Features & 3 Scan Modes

### 1. Paste Code Mode
- Language detection is automatic by default. Ambiguous snippets require a manual language choice; the dropdown also lets users override a detection.
- Multi-language support covering all Semgrep-supported languages (Python, JavaScript, TypeScript, Java, Go, C/C++, C#, Ruby, PHP, Rust, Scala, Kotlin, Dockerfile, Terraform, YAML, JSON, Shell/Bash).
- Input size validation & untrusted data isolation.
- Active Prompt Injection Guard detecting override attempts, system prompt dumps, safety bypasses, and data exfiltration vectors.
- AST vulnerability rules + hardcoded secret detection.
- Honest reporting: plain text streams never claim antivirus protection without a real malware engine.

### 2. Upload File / Archive Mode
- Choose or drag multiple files, remove individual selections, and reselect the same file. The browser accepts up to 50 files and 50 MB total per scan.
- Ingestion security with path traversal sanitization, binary file detection, and isolated sandbox directory cleanup.
- ZIP Bomb & decompression protections (100:1 ratio limit, 100MB uncompressed limit, max 500 entries, recursive archive depth protection).
- Strict execution safety: never executes uploaded scripts, never installs dependencies.
- Classification into 7 categories: `Source code`, `Configuration`, `Text/document`, `Archive`, `Binary/executable`, `Image`, `Unknown`.
- Safe document text extraction for PDF (`pypdf`) and Word (`python-docx`).
- ClamAV malware scanning pipeline reporting: `clean`, `suspicious`, `infected`, `unavailable`, `failed`. Never reports false clean when scanner is unavailable or fails.

### 3. GitHub Repository Review
- Reviews the complete tracked snapshot of a public GitHub repository at the current default/selected branch HEAD, or an explicitly selected commit.
- Runs local source/infrastructure security rules, secret detection, workflow configuration checks, supported dependency advisory lookups, prompt-injection pattern checks and ClamAV when available.
- Shows severity, affected file/line, evidence, reasons and remediation. Records the resolved commit for reproducibility.
- Reports failed checks and skipped files. Repository code, dependency installers, Git hooks, LFS filters and submodules are never executed.
- Ignores caller-provided baselines and changed-files-only strategies; scores always cover the selected snapshot.
- See [repository review scope and scoring](docs/repository-reviews.md) for limits, dependency formats, network requirements and the score formula.

---

## Privacy & Security Guarantees

1. **No Raw Code Storage by Default**: When storing scan metadata and findings in MongoDB, raw source code is not persisted for full repositories or uploaded archives.
2. **Ephemeral Mode**: Users can toggle Ephemeral Mode to run scans entirely in-memory with zero database persistence.
3. **Snippet-Only AI Context**: The platform never sends entire repositories to the LLM. Only concise finding snippets and surrounding diff context are provided for remediation.
4. **Prompt Injection Hardening**: All scanned code is wrapped in strict untrusted data boundaries with a fixed system prompt forbidding execution of in-code directives.
5. **AI Advisory Transparency**: Every AI-generated remediation is marked with `advisory_source: "ai"`, `confidence`, and `requires_verification: true`.

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
                                                      - Full Repository Snapshot Review
                                                      - Grounded AI Explainer (Gemini)
```

---

## API Documentation (v1 Endpoints)

### 1. `POST /api/v1/files/scan`
Scan single file or pasted code snippet.
- Set `language` to `null` or `"auto"` and use `file_name: "snippet"` for automatic detection. Uncertain detection returns an actionable 422 error.
- `POST /api/v1/language/detect` accepts the same code fields and returns `language` and `confidence` without running a scan. It requires a signed-in session through the gateway.
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
Review a complete public GitHub repository snapshot. `branch` and `commit_sha` are optional; omit both for the current default branch. Legacy strategy/baseline fields are accepted but do not reduce review scope.
- **Request Body**:
  ```json
  {
    "repository_url": "https://github.com/owner/repo",
    "commit_sha": "7a3f89e",
    "branch": "main",
    "strategy": "full",
    "baseline_findings": [],
    "ephemeral": false
  }
  ```
- **Response**: Includes the resolved `commit_sha`, `parent_sha`, `scan_type: "commit"`, real `files_analyzed`, `files_skipped`, per-check `coverage`, `limitations`, findings and scoring metadata. This endpoint does not claim findings were fixed by comparing with an untrusted client baseline.

### 4. `GET /api/v1/scans/:scanId` & `DELETE /api/v1/scans/:scanId`
Retrieve or purge a scan record from the history vault.

---

## Local Setup & Quickstart

### Prerequisites
- Python 3.10+
- Node.js 22.12+
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


## Verified non-repository workflow and deployment

Paste scans and multipart uploads return real findings; scanner/API failures are
shown as errors instead of synthetic demo reports. Uploads preserve binary data,
extract ZIP/TAR source archives safely, and extract PDF/DOCX text for secret and
prompt-injection checks. Executables/images and nested archives are reported as
skipped for static analysis while original bytes remain eligible for malware
scanning. Files are never executed. Unsupported or malformed documents are
reported explicitly.

Analysis and saved reports require login. FastAPI scan routes accept only the
authenticated gateway's shared `ANALYSIS_SERVICE_TOKEN`. Reports save
findings/snippets in MongoDB, with owner-scoped retrieval and deletion. Complete
submitted source is not saved. Ephemeral reports stay in page memory and disappear
on a full reload; they are not written to localStorage, navigation state, or the
vault. AI explanations use bounded finding-local snippets and redact secret
findings; absent/unavailable Gemini falls back to labeled local remediation.

Authentication uses HttpOnly session cookies. Set `REDIS_URL` on the gateway to
store sessions in Redis; logout deletes the session and invalidates old-cookie
replay. Local development without Redis uses MongoDB sessions. A configured but
unavailable session store returns an error rather than permitting guest access.

For Render/Railway roots, Docker settings, environment variables, cookies, and
ClamAV signature setup, see [docs/deployment.md](docs/deployment.md).
Example variables are in each service's `.env.example`.

Regression checks (start the local stack and use a disposable MongoDB database
before running gateway integration tests):

```powershell
python -m pytest analysis-service/tests -q
cd frontend
npm test
npm run lint
npm run build
cd ../express-api
npm test
```

The gateway test creates isolated accounts and deletes only reports it creates.
It defaults to the frontend proxy at `http://127.0.0.1:5173/api`; set
`TEST_BASE_URL` only for a dedicated test environment.
