# Render and Railway deployment

Use Render alone or Railway alone; you do not need both. Keep the existing MongoDB Atlas database. For Redis-backed sessions, add a Redis/Render Key Value instance in the same region.

Create three Docker services from this repository. Set each service's root
directory to the folder below; its Dockerfile is `Dockerfile` relative to that
root. Leave build/start overrides empty. Do not deploy the repository root as a
single Node/Python service.

| Service | Root directory | Health path |
| --- | --- | --- |
| Frontend | `frontend` | `/` |
| Gateway | `express-api` | `/health` |
| Analysis | `analysis-service` | `/health/` |

The analysis image installs Semgrep, Gitleaks, and ClamAV. A native Python
deployment without these OS packages does not provide the same scanner coverage.

Repository reviews also require outbound HTTPS to GitHub and `api.osv.dev`.
No GitHub or OSV secret is needed for public repository reviews. The gateway and
bundled frontend proxy allow up to 300 seconds for a repository scan; configure
any additional proxy to permit that duration. See [review scope and scoring](repository-reviews.md).

## Environment variables

### Frontend (Docker/Nginx runtime)

```dotenv
PORT=10000
API_GATEWAY_URL=https://YOUR-GATEWAY-DOMAIN
```

`API_GATEWAY_URL` must be the origin URL, without a trailing slash or `/api`.
The frontend forwards `/api/*` requests to the gateway, preserving same-origin
session cookies. Never put MongoDB credentials, SESSION_SECRET, or a Gemini key
in frontend environment variables. The UI needs no `VITE_*` variables.

### Gateway

```dotenv
NODE_ENV=production
PORT=5000
MONGODB_URI=mongodb+srv://USERNAME:PASSWORD@CLUSTER/DATABASE
FASTAPI_URL=https://YOUR-ANALYSIS-DOMAIN
FRONTEND_URL=https://YOUR-FRONTEND-DOMAIN
SESSION_SECRET=REPLACE-WITH-A-LONG-RANDOM-SECRET
TRUST_PROXY=1
ANALYSIS_SERVICE_TOKEN=SHARED-RANDOM-SECRET-32-CHARACTERS-MINIMUM
REDIS_URL=YOUR-PRIVATE-REDIS-CONNECTION-URL
```

Use a persistent MongoDB database (Atlas, or a Railway MongoDB service with a
persistent volume). Include a database name in the URI. Give SESSION_SECRET a
random value of at least 32 characters and preserve it across deployments.
`TRUST_PROXY=1` lets Express recognize HTTPS forwarded by the frontend proxy so
production login cookies work. The production frontend must use HTTPS.

### Analysis engine

```dotenv
PORT=8000
ANALYSIS_SERVICE_TOKEN=SAME-VALUE-AS-GATEWAY
GEMINI_API_KEY=YOUR-OPTIONAL-GEMINI-KEY
```

Without `GEMINI_API_KEY`, scanners and grounded local explanations still work;
the UI labels local suggestions separately from AI advisories. AI calls have a
20-second timeout. The gateway uses Redis for server-side sessions when REDIS_URL is set. Logout deletes the stored session, so replaying its old cookie fails. Without REDIS_URL, local development falls back to MongoDB sessions, which also invalidate on logout. A configured but unavailable Redis never falls back silently.

ClamAV needs current signature databases as well as its executable. Populate and
refresh its database with `freshclam` in the deployed scanner environment (use
persistent signature storage for regular updates). Installing the executable
alone does not establish antivirus coverage: results show `unavailable` or
`failed` when the engine/database cannot scan. Pasted code is not antivirus-scanned.

## Render

Use **Web Service → Docker** for each folder. Set Root Directory to the folder
name and Dockerfile Path to `./Dockerfile`. Services listen on `PORT`; you may use
Render's supplied port or explicitly set the values above. Keep all services in
the same region if using Render private service addresses.

For a simple setup, use the generated HTTPS domain for the gateway and analysis
URLs. For private backend services, use their provided internal host and explicit
listening port instead. Health check paths are listed above.

Do not select Static Site for this frontend configuration: the Nginx runtime
provides the API proxy needed by session authentication. A static deployment would
require separate proxy or cross-origin cookie configuration.

## Railway

Create a service for each folder and set **Settings → Source → Root Directory**
to `/frontend`, `/express-api`, and `/analysis-service`. Railway detects each
Dockerfile. Add variables in each service's Variables tab.

Generate a public domain for each service and select the target port matching
that service's `PORT`. Set the frontend and gateway URL variables using those
domains. Public HTTPS domains are the straightforward configuration across both
platforms; private domains need a matching IP bind and private listening port.

For a Railway MongoDB service named `MongoDB`, its connection URL can be
referenced in the gateway as `MONGODB_URI=${{MongoDB.MONGO_URL}}` if that variable
is provided by the selected database template. Service names are case-sensitive;
use the actual variable name shown by your template.

## Deployment order and verification

1. Provision MongoDB and deploy the analysis service.
2. Deploy the gateway with `MONGODB_URI` and `FASTAPI_URL`.
3. Deploy the frontend with `API_GATEWAY_URL`.
4. Set the gateway's `FRONTEND_URL` to the final frontend HTTPS origin.
5. Visit the frontend, confirm that analysis redirects to login, create a test
   account, scan a deliberately vulnerable snippet, and reopen it from History. Check that an ephemeral
   scan does not appear there. Upload a ZIP containing source code to confirm
   file paths/findings reach the report.

Scans are synchronous. Allow at least 180 seconds for reverse-proxy requests and
allocate sufficient memory for Semgrep and document/archive ingestion. The GitHub
repository workflow is outside this verification scope.

Official references: [Render monorepos](https://render.com/docs/monorepo-support),
[Render Docker](https://render.com/docs/docker),
[Render ports](https://render.com/docs/web-services#port-binding),
[Railway monorepos](https://docs.railway.com/deployments/monorepo),
[Railway Dockerfiles](https://docs.railway.com/builds/dockerfiles),
[Railway variables](https://docs.railway.com/variables).


## Authentication and access checks

Analysis, reports, and history require login. FastAPI scan routes additionally require the shared `ANALYSIS_SERVICE_TOKEN` header supplied by the gateway, using a FastAPI dependency. Keep this token exclusively in gateway/analysis environments. Backend services should use private networking where possible. The browser should access only the frontend origin and its `/api` proxy.

All saved-report reads/deletes and history purges are scoped to the authenticated account. Client history imports are disabled. The application uses HttpOnly session cookies, not JWTs; Redis stores these revocable sessions. Set a stable, randomly generated SESSION_SECRET and the same ANALYSIS_SERVICE_TOKEN on both services before deploying. Existing MongoDB sessions are not reused when switching to Redis; users sign in again.

`FRONTEND_URL` must exactly match the browser origin (including HTTPS and no trailing slash) for cross-site request protection. Auth/storage/scanner errors are displayed to users without exposing database credentials or stack traces.
