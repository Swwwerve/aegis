# Aegis end-to-end testing

This guide describes the current local workflow for testing Aegis from the
backend through the frontend, including the Docker-isolated Patch Agent
demonstration.

## Prerequisites

- Windows PowerShell
- Python 3.11 or newer
- Node.js and npm
- Docker Desktop running with Linux containers enabled
- The `aegis-sandbox:polyglot` image available locally for sandbox tests
- An `OPENAI_API_KEY` only for model-assisted scans or production remediation
- `rg`/ripgrep is optional; Aegis uses a bounded Python fallback for context
  search when it is not installed

The Patch Agent demonstration does not call OpenAI. It uses a deterministic
model and a synthetic remediation plan, so it can be tested without an API
key.

## Install dependencies

From the repository root:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"

Set-Location frontend
npm ci
Set-Location ..
```

If the sandbox image is not present, build it before running sandbox tests:

```powershell
docker build -f docker\Dockerfile.sandbox -t aegis-sandbox:polyglot .
```

Verify Docker and the image:

```powershell
docker version
docker image inspect aegis-sandbox:polyglot
```

## Run automated tests

Run the backend unit and integration tests:

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

Run the frontend unit tests and production build:

```powershell
Set-Location frontend
npm run test:unit
npm run build
Set-Location ..
```

Run the browser suite when Chromium is installed:

```powershell
Set-Location frontend
npx playwright install chromium
npm test
Set-Location ..
```

The browser suite uses mocked providers for deterministic coverage. It does not
replace the live workflow below.

## Start Aegis

Start the backend first, from the repository root. Keep this terminal open:

```powershell
.\.venv\Scripts\python.exe -m uvicorn aegis.backend.main:app `
  --host 127.0.0.1 --port 8000
```

Verify that FastAPI is reachable before starting Vite:

```powershell
Invoke-WebRequest http://127.0.0.1:8000/docs -UseBasicParsing
```

The response must have status `200`. If Vite reports
`connect ECONNREFUSED 127.0.0.1:8000`, this backend process is stopped, failed
during startup, or is listening on a different port. Stop the Vite process,
start FastAPI successfully, verify `/docs`, and then restart Vite.

Open <http://127.0.0.1:8000>. FastAPI serves the production frontend bundle
after `npm run build`.

For frontend hot reload, leave the backend terminal running and use a second
PowerShell window:

```powershell
Set-Location frontend
npm run dev
```

Open <http://127.0.0.1:5173>. Vite proxies API and SSE requests to port 8000.
The frontend uses `/api` as its API prefix; Vite rewrites that prefix when
forwarding to FastAPI.

## Test a real scan end to end

1. Open the frontend.
2. Enter a public GitHub repository URL, or select one of the built-in example
   repositories.
3. Start analysis.
4. Follow the live stages in the workspace:
   repository intake, inventory, optional dependency-graph resolution,
   repository interpretation, OSV discovery, CVSS/EPSS and KEV enrichment,
   static usage inspection, prioritization, and persistence.
5. Open a finding and inspect its advisory references, affected versions,
   confirmed fixes, source usage, and coverage notes.
6. Reopen the scan from history and verify that the saved inventory and finding
   evidence remain available.

For a deterministic live scan without model calls:

```powershell
.\.venv\Scripts\python.exe -m scripts.smoke_live_scan --prioritize
```

For model-assisted interpretation and prioritization, configure
`OPENAI_API_KEY` in the backend environment and run:

```powershell
.\.venv\Scripts\python.exe -m scripts.smoke_live_scan --model
```

## Test the Patch Agent demonstration

The demonstration is disabled by default. It never uses the configured
repository. Each run creates a temporary committed Git repository, applies a
synthetic npm dependency update inside Docker, exports the diff, streams
progress to the browser, and deletes the fixture.

Stop any existing backend process first, then start it with the demo enabled:

```powershell
$env:AEGIS_ENABLE_PATCH_DEMO = "true"
.\.venv\Scripts\python.exe -m uvicorn aegis.backend.main:app `
  --host 127.0.0.1 --port 8000
```

Keep this backend process running while the frontend is open. Confirm the
demonstration is enabled:

```powershell
(Invoke-WebRequest http://127.0.0.1:8000/api/remediation/demo/status `
  -UseBasicParsing).Content
```

The response must contain `"enabled":true`. This environment variable belongs
to the backend process; setting it after Uvicorn has already started has no
effect until the backend is restarted.
Open the frontend and select **Run Patch Agent demo**. The live activity should
show:

1. Disposable fixture creation
2. Docker sandbox patch execution
3. `npm-remediation` Skill loading
4. `package.json` read
5. `aegis-demo-package` update from `1.0.0` to `1.0.1`
6. Git diff inspection
7. A completed `PatchResult`
8. Fixture cleanup

The result should report:

- `status: completed`
- `modified_files: ["package.json"]`
- dependency change `1.0.0` → `1.0.1`
- `demonstration: true`
- `further_testing_required: true`
- no errors or unresolved issues

The same stream can be tested without the browser:

```powershell
Invoke-WebRequest `
  -Uri http://127.0.0.1:8000/remediation/demo/status

curl.exe -N -X POST `
  http://127.0.0.1:8000/remediation/demo/patch/stream
```

Expected terminal events are `result` followed by `end`. A Docker or sandbox
failure is returned as a redacted `error` event rather than exposing internal
paths or exception details.

## Why network access is used

Network access is needed outside the execution sandbox for operations that
cannot be satisfied from local data:

- cloning a public GitHub repository during intake
- querying OSV, NVD, EPSS, and CISA KEV advisory feeds
- calling the configured OpenAI model for context selection, investigation,
  remediation planning, or application-code patch reasoning
- installing frontend/backend dependencies during local setup

The Docker sandbox intentionally uses `network_mode=none`. Dependency
resolution and validation are therefore offline and can use only the tools and
caches baked into `aegis-sandbox:polyglot`. This prevents repository code or
package lifecycle scripts from reaching the network during analysis or patching.
It is not a missing permission that should be fixed by enabling sandbox network
access.

If a scan reports provider or clone failures, allow network access for the host
backend process and configure any required proxy or firewall exceptions. If a
model call fails, set `OPENAI_API_KEY` in the backend environment; never expose
it through a `VITE_` frontend variable. If offline dependency resolution is
unavailable, rebuild the polyglot image with the required fixture/cache
contents rather than enabling container networking.

## Test production remediation planning and patching

The interface uses a dark shadcn/ui theme with Overview, Repositories, and
Scan history in the top navigation. The agent activity panel expands into
observed actions, tool calls, and evidence; remediation plans also include
their supplied rationale and source references.

To inspect dependency retrieval, enable **Resolve dependency graph** before
starting a scan. The **Docker execution** panel shows each command, working
directory, stdout, stderr, and exit code. Output arrives when each command
finishes, rather than line by line. New scan reports retain these logs in
history and JSON exports; older scans may have no execution logs. The sandbox
uses offline caches, so missing dependencies are reported explicitly.

The production flow requires a real registered repository, a completed context
investigation, verified vulnerability evidence, and a `RemediationPlan` with
`status: ready`.

1. Register or select a repository.
2. Run a scan.
3. Open a finding and investigate context.
4. Resolve any missing-context requests.
5. Generate and review the remediation plan and its evidence references.
6. Start the Patch Agent from the finding view.
7. Review the live tool events and returned patch artifact.
8. Treat `further_testing_required: true` as mandatory: the Patch Agent does not
   claim that a vulnerability is fixed solely because a version changed.

Every declared validation command runs even if the model omits its tool call.
Open **Patch verification → Validation results** to review passed, failed,
pending, and skipped checks. Failed, skipped, unavailable, or timed-out checks
make the patch result require review. No recorded checks means no validation
has been demonstrated. Download execution logs or export the patch result to
retain the evidence. Console output is bounded to 16,384 characters per stream
per command, with a visible truncation notice.

The development Patch Agent demo also runs a declared Python command to verify
the synthetic dependency version and displays its real Docker output. It is a
fixture check, not a security regression test for your repository.

Production patch execution requires Docker and an OpenAI key because the
application-code reasoning path uses the configured Agents SDK model. All
repository modifications occur inside the restricted sandbox.

## Troubleshooting

### Docker errors

Confirm Docker Desktop is running and that the image exists:

```powershell
docker version
docker image inspect aegis-sandbox:polyglot
```

If the API emits `Sandbox demonstration could not finish`, inspect the backend
console for the local infrastructure failure. The browser intentionally receives
only the redacted message.

### Missing `rg` / ripgrep

Current Aegis versions do not require ripgrep. If `rg` is absent from the
backend process `PATH`, context retrieval records a diagnostic and uses a
bounded literal Python fallback. To use the faster native implementation,
install ripgrep and restart the backend. On Windows, either install it through
your package manager or install the standalone binary, then verify:

```powershell
rg --version
```

### Missing context

The planner and Patch Agent must not guess when context is incomplete. The Patch
Agent button appears only when the context investigation is `completed` and the
remediation plan is `ready`. Use the context clarification controls, provide
the requested repository facts, and complete the investigation before retrying.
If a plan is `needs_context`, the plan card now explains that the Patch Agent is
intentionally blocked and lists the evidence gaps that must be resolved.

### Frontend cannot connect

Ensure the backend is listening on port 8000 and that the frontend's
`AEGIS_API_TARGET` points to the same backend when using Vite.

### Stale generated output

Generated smoke reports, build output, caches, and temporary Patch Agent
fixtures are disposable. Remove them after local testing; do not remove
`workspaces/`, `.env`, `.venv/`, or `aegis.db` unless you intentionally want
to discard local repository clones, credentials configuration, dependencies, or
application state.
