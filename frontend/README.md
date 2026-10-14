# Aegis frontend

React + TypeScript, Vite, Tailwind CSS 4, and official shadcn/ui components.
No simulated scans or placeholder findings are displayed. Examples register and
inspect real public GitHub repositories through the backend.

## Run with one server

From `frontend/`:

```powershell
npm ci
npm run build
```

Then, from the project root:

```powershell
.\.venv\Scripts\python.exe -m uvicorn aegis.backend.main:app --host 127.0.0.1 --port 8000
```

Open **http://127.0.0.1:8000**. FastAPI serves the built assets and same-origin
`/api` routes. Existing `/repositories`, `/scans`, and `/docs` routes still work.
Restart a previously running backend after installing these changes.

## Develop with hot reload

Keep the backend on port 8000, then run `npm run dev` in this directory and open
**http://127.0.0.1:5173**. Vite proxies `/api` requests, including progress streams,
to `http://127.0.0.1:8000`. No CORS configuration is needed for this setup.

Set `AEGIS_API_TARGET` before starting Vite to proxy to a different backend.
`VITE_API_BASE` can override the browser's API prefix when hosting separately;
cross-origin deployments must configure their own backend CORS policy. These
are public connection settings. Keep `OPENAI_API_KEY` in the backend environment,
never in a `VITE_` variable. Both API and UI bind to loopback in this setup.

## Connected workflow

1. Enter a public GitHub URL or choose NodeGoat, PyGoat, or WebGoat. Click Analyze.
   Already registered repositories reuse their saved clones; this does not fetch
   newer remote commits. Repositories are also listed in the sidebar's repository view.
2. Follow real stage events: inventory, optional offline dependency resolution,
   optional model interpretation, OSV discovery, CVSS/EPSS/KEV enrichment,
   static usage inspection, priority scoring, and persistence.
3. Inspect languages, package managers, manifests, projects, important directories,
   dependency versions and proposed build/test commands. Proposed commands are not
   executed by this UI. Resolution diagnostics are available on project cards.
4. Filter ranked findings by package/CVE or priority. Open a finding for score
   components, model rationale, source call sites, confirmed fixes, affected
   ranges, feed dates, provenance and reference links.
5. Read coverage notes and unresolved dependencies; export inventory or full scan
   JSON. Reopen saved runs from history, including their repository inventory.
   Earlier scans without an inventory snapshot still display their saved findings.

Model assistance is on by default and requires the host's `OPENAI_API_KEY`.
Without a key the evidence scan continues and model status is unavailable.
Optional sandbox resolution requires Docker and the configured polyglot image.
Static package calls are not measured runtime calls or confirmed vulnerable-function
execution. Unavailable evidence and incomplete coverage stay explicit in the UI.

The browser sends a POST to `/api/scans/stream` and parses server-sent events.
Each `progress` frame carries a stage, status, message and optional inventory;
`result` carries the persisted ScanRead and `end` closes the stream. Keep-alive
comments preserve long requests. Stage statuses come from completed backend work,
without synthetic percentages. Disconnecting cancels streaming scan work and the
backend records a failed/cancelled run; an intake clone may continue independently.
After a disconnect, refresh history before retrying.

## Verification

```powershell
npm run build
npm run test:unit
npx playwright install chromium
npm test
npm audit
```

Browser tests cover desktop/mobile journeys, partial and failed scans, duplicate
registration/reuse, interrupted streams, search, finding dialogs, unsafe links,
JSON exports, saved history, responsive layouts and automated WCAG checks.
Unit tests cover chunked UTF-8/SSE parsing and URL validation. Backend tests in
`tests/test_progress.py` cover stage order, persisted inventory, failed runs,
and cancellation. Tests mock providers rather than requiring credentials.

An optional live browser smoke test uses a real NodeGoat clone, backend and feeds:

```powershell
$env:AEGIS_UI_URL='http://127.0.0.1:8000'
npx tsx scripts/smoke-live.ts
```

This registers/reuses the example, disables model assistance, creates a real scan,
and saves screenshots and its report to ignored `test-results/`.

Use `npx shadcn add <component>` to extend the registered component library.
Configuration is in `components.json`; generated components live in `src/components/ui`.
