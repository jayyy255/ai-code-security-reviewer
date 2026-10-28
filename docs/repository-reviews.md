# Repository security reviews

Paste a public `https://github.com/owner/repository` URL into Repository mode.
Omit branch and commit to review the current default branch HEAD. A branch selects
its latest commit. A full 40-character SHA can select an older commit; abbreviated
SHAs work only when present in the shallow clone. The report records the exact SHA.

Every review scans the selected tracked snapshot, including unchanged files. The
legacy strategy and baseline request fields do not change this scope. There is no
automatic claim that a risk is fixed based on client-supplied findings.

## Checks and limits

- Semgrep runs this project's source and infrastructure rule collection. These
  rules cover selected injection, authentication, cryptography, configuration,
  file handling and language-specific hazards, not every possible vulnerability.
  Selected PHP, Python and JavaScript/TypeScript rules trace request input through
  intermediate variables into SQL/shell calls within a file. This does not provide
  complete cross-file or framework-aware data-flow analysis.
- Gitleaks scans the current snapshot for credentials. If its binary is missing,
  a smaller regex fallback runs and coverage is marked partial. Token validity
  and past Git history are not checked.
- GitHub Actions checks flag broad token permissions, actions following mutable
  main/master branches and selected direct event-to-shell interpolation hazards.
- OSV checks exact package versions from npm package-lock (including nested
  entries), pinned requirements text, Poetry/Cargo lockfiles and go.sum.
  Development and transitive packages in supported locks are included; go.sum may
  contain versions no longer used. Confirm actual reachability before remediation.
  Ranges, unsupported formats, malformed manifests and lookup failures are gaps.
- ClamAV scans the snapshot when available. Missing signatures or engine failures
  are reported; they never count as a clean result.
- Prompt-injection patterns are contextual review signals, not proof that an app
  exposes an LLM. Repository matches are low-severity, low-confidence until the
  data flow is verified. Normal cleanup commands are not prompt injection.

The service does not run builds, applications, dependency installs, Git hooks,
LFS filters, submodules or repository-provided scanner rules. Symlinks are not
followed. Vendored dependencies, build output and environment directories are
excluded; generated binaries need separate review. Snapshot limits are 5,000
files, 2 MB per file and 100 MB total, with a 20,000 tree-entry traversal limit.
Git clone and optional commit fetch have 60- and 30-second timeouts; the snapshot
byte limit applies after cloning, not to the transferred Git pack.

Dependency lookup sends only package ecosystem, name and version to
[OSV](https://google.github.io/osv.dev/post-v1-querybatch/); advisory details come
from its [vulnerability API](https://google.github.io/osv.dev/get-v1-vulns/).
It sends no source code and requires no API key. Permit outbound HTTPS to
github.com and api.osv.dev. Lookups are limited to 500 package locations, 60
advisory detail records and a 45-second request budget; incomplete work is marked
partial. Other scanner results remain visible during an OSV outage. Optional AI
enrichment receives only bounded finding snippets and is not needed for local
explanations or dependency upgrade guidance.

## Score version 2

This is a prioritization score, not a percentage probability of security.

1. Count distinct issues at each severity. Multiple rules with the same file,
   line and category count once at the highest severity. Separate dependency
   advisories/package versions remain separate. Raw severity totals still show
   all deduplicated findings for review.
2. Compute `burden = 40*log2(1+C) + 16*log2(1+H) + 6*log2(1+M) + 2*log2(1+L)`.
3. Compute `score = round(100 / (1 + burden/40))`.
4. Apply the lowest applicable severity ceiling: critical 49, high 69, medium 89,
   low 99. More findings cannot improve the score, and adding clean files cannot
   dilute risk. Logarithmic growth avoids immediately flattening large reports
   to zero while retaining the impact of severe findings.
5. Repository scores with incomplete coverage are provisional and capped at 79.
   A failed source/secret scan, or no eligible source/config files, produces no
   score (`null`), rather than a false 100. Missing malware checks and unresolved
   dependencies remain visible gaps even when all source rules succeed.

Weights and ceilings are explicit policy choices, not an industry standard or
calibrated exploitability model. Existing stored reports keep their original
score; run a new review to use version 2. Runtime authorization, business logic,
production configuration and exploitation paths require additional verification.
