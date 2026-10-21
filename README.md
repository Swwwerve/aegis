# Aegis

Aegis is an open source vulnerability remediation service. It inspects GitHub
repositories, finds vulnerable dependencies, ranks findings with supporting
evidence, and helps investigate, plan, and generate fixes in a Docker sandbox.
The app uses a FastAPI backend, a React/TypeScript frontend, and SQLite storage.

## What has been achieved

- **Repository intake:** clone public GitHub repositories and reuse saved clones.
- **Repository understanding:** inventory Python, Node.js, and Java projects,
  manifests, lockfiles, dependency versions, and proposed build/test commands.
- **Vulnerability scanning:** query OSV for exact dependency versions and preserve
  advisory IDs, affected ranges, fixes, references, and coverage gaps.
- **Prioritization:** combine CVSS, EPSS, CISA KEV, and static source usage into
  an application risk score, with optional model reasoning.
- **Connected workspace:** stream progress, inspect findings and execution logs,
  export JSON, and reopen saved scans with their evidence.
- **Remediation:** investigate CVE source context, ask for missing information,
  create skill-guided plans, and run the Patch Agent inside restricted Docker.
- **Patch verification:** export patch artifacts and display declared validation
  commands, output, and results. A disposable demo exercises the patch workflow
  without an OpenAI key.
- **Automated coverage:** backend tests, frontend unit tests, and mocked browser
  tests cover scanning, streaming, context, planning, and patch behavior.

## 1. Install prerequisites

Use Python 3.11+, Node.js with npm, and Git. Docker Desktop with Linux containers
is needed for dependency resolution and patch execution. An `OPENAI_API_KEY` is
needed for model-assisted analysis and production remediation, but basic scans
and the Patch Agent demo can run without one.

The commands below use Windows PowerShell from the repository root.

## 2. Install the application

Create a Python environment and install backend dependencies:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
```

Install frontend dependencies and build the browser app:

```powershell
Set-Location frontend
npm ci
npm run build
Set-Location ..
```

For model features, add this line to a root `.env` file:

```dotenv
OPENAI_API_KEY=your-key-here
```

Keep the key on the backend; never put it in a `VITE_` variable. Model calls use
API credits. SQLite tables and the workspace directory are created as needed.

## 3. Prepare Docker when needed

Start Docker Desktop, then build the image containing Python, Node.js, Java,
and offline dependency caches:

```powershell
docker build -f docker/Dockerfile.polyglot -t aegis-sandbox:polyglot .
docker image inspect aegis-sandbox:polyglot
```

Use this image for dependency resolution and the npm Patch Agent demo.
`Dockerfile.sandbox` is the smaller Python image and does not provide the full
polyglot toolchain. Set `AEGIS_ANALYSIS_SANDBOX_IMAGE` to use a prepared custom
image for dependency analysis.

The host uses the network for cloning, advisory feeds, and model calls. Repository
execution stays in a network-disabled, nonroot, resource-limited sandbox. Offline
resolution needs cached packages; missing packages produce explicit coverage gaps.

## 4. Start the app

Run the backend and leave the terminal open:

```powershell
.\.venv\Scripts\python.exe -m uvicorn aegis.backend.main:app --host 127.0.0.1 --port 8000
```

Open **http://127.0.0.1:8000** for the built frontend, or
**http://127.0.0.1:8000/docs** to explore and test the API.

For frontend hot reload, keep the backend running and open a second terminal:

```powershell
Set-Location frontend
npm run dev
```

Open **http://127.0.0.1:5173**. Vite forwards API requests to port 8000.

## 5. Run a scan and review a fix

1. Enter a public GitHub URL or choose an example, then start analysis. Saved
   repositories reuse their existing clone; they do not automatically fetch
   newer commits.
2. Enable model assistance if a key is configured. Enable **Resolve dependency
   graph** only when Docker and the polyglot image are ready.
3. Follow inventory, vulnerability discovery, enrichment, usage inspection,
   prioritization, and saving in the live activity panel.
4. Open a finding to inspect affected versions, advisory references, confirmed
   fixes, priority evidence, source call sites, and coverage notes.
5. Export the report or reopen it from scan history to inspect saved evidence.
6. For a CVE finding, select **Investigate context**, answer any missing-context
   questions, then select **Create remediation plan** and review the proposal.
7. Once investigation is `completed` and the plan is `ready`, start the Patch
   Agent. Review the exported patch and **Patch verification → Validation
   results**, including command output and any failed or skipped checks.

A generated patch is a review artifact. `further_testing_required: true` means
additional testing is required; a dependency version change alone does not prove
that a vulnerability is fixed. Repository modifications happen inside Docker.

## 6. Run automated tests

Run backend tests from the repository root:

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

Run frontend unit tests, check the production build, and run browser tests:

```powershell
Set-Location frontend
npm run test:unit
npm run build
npx playwright install chromium
npm test
Set-Location ..
```

Expect passing tests and a successful build. Playwright starts Vite automatically
and uses mocked API responses for repeatable desktop/mobile checks. These tests
are separate from live provider and Docker verification.

Check real advisory feeds and saved results without model calls:

```powershell
.\.venv\Scripts\python.exe -m scripts.smoke_live_scan --prioritize
```

To also check model interpretation and prioritization, run the same command with
`--model` instead. These checks use temporary Git/SQLite fixtures and save reports
under `sandbox-smoke-results/`. Live advisory results can change over time.

## 7. Test the Patch Agent demo

Build the polyglot image first. Stop the backend, then restart it with the demo
enabled in the same terminal:

```powershell
$env:AEGIS_ENABLE_PATCH_DEMO = "true"
.\.venv\Scripts\python.exe -m uvicorn aegis.backend.main:app --host 127.0.0.1 --port 8000
```

Open the app and select **Run Patch Agent demo**. It creates a temporary committed
Git fixture, changes a synthetic npm dependency from `1.0.0` to `1.0.1` in Docker,
executes a declared validation check, exports the diff, and deletes the fixture.
It uses a deterministic model and leaves the configured repository untouched.

Expect `status: completed`, `modified_files: ["package.json"]`,
`demonstration: true`, validation output, and `further_testing_required: true`.
This verifies the demo workflow, not a security fix for a real repository.

## Current limits and troubleshooting

- **Incomplete scans:** unresolved versions and provider errors remain visible.
  `partial` is not a clean scan; inspect coverage and enrichment statuses.
- **Usage evidence:** static call sites do not prove runtime reachability or
  execution frequency. Java package-to-namespace usage mapping is unsupported.
- **Risk scores:** the 0–100 priority score is an application heuristic, not an
  exploit probability or CVSS severity classification.
- **Cannot connect:** check that `/docs` responds on port 8000 before starting
  Vite. Rebuild the frontend after UI changes when using port 8000.
- **Docker failures:** check `docker version` and the image inspection command
  above. Missing offline packages require a prepared image/cache.
- **Patch unavailable:** configure the backend API key and resolve context gaps
  until investigation is completed and the plan is ready.

See [the end-to-end testing guide](END_TO_END_TESTING.md) for detailed procedures
and [the frontend guide](frontend/README.md) for UI configuration and browser checks.

## Project layout

- `aegis/backend/` — API, analysis, vulnerability feeds, agents, skills, and sandbox.
- `frontend/` — React workspace and browser tests.
- `tests/` — backend regression tests.
- `scripts/` — live smoke checks.
- `docker/` — sandbox images and trusted cache fixtures.
- `evals/` — reserved benchmark area.
- `workspaces/`, `aegis.db`, `sandbox-smoke-results/` — generated local data.
