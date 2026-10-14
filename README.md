# Aegis

Open source vulnerability remediation service.

The `aegis/backend` package contains the FastAPI application and production
logic. Benchmark material lives under `evals`, tests under `tests`, and
deployment/UI placeholders under `docker` and `frontend`.

## Directory layout

```text
Aegis/
  aegis/backend/          Python application package
    core/config.py       Environment-backed settings
    db/models.py         Database models
    api/                 HTTP endpoints
    agents/              Agent definitions
    analysis/            Repository inventory and dependency parsing
    sandbox/             Restricted Docker execution
  docker/                Dockerfiles, including the sandbox image
  frontend/              Reserved for the web UI
  tests/                 Automated tests
  scripts/               Developer utilities and smoke tests
  evals/                 Reserved for evaluation benchmarks
  workspaces/            Generated repository clones (ignored by Git)
  sandbox-smoke-results/ Generated test artifacts (ignored by Git)
  pyproject.toml         Python dependencies and packaging
```

Keep Docker build files, frontend code, tests, and scripts at the project root.
Runtime data belongs outside the Python package. The database (`aegis.db`),
local environment (`.env`), and virtual environment (`.venv/`) are ignored by Git.

## Setup

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
# Optional: create .env with OPENAI_API_KEY=... for model-assisted analysis.
uvicorn aegis.backend.main:app --reload
```

Run tests with `pytest`.

## Step 5: live, model-assisted vulnerability prioritization

`POST /scans` now enriches findings with CVSS base scores (v2/v3/v4 vectors),
FIRST EPSS probability/percentile/date, CISA KEV catalog matches, advisory source
links/dates/ranges, confirmed fixes, and static package usage evidence. Findings
are returned in descending `priority.score` order and saved with their evidence;
historical scan results retain their original snapshots.

`use_model: true` requests a non-deterministic OpenAI assessment as well as repo
interpretation. Configure `OPENAI_API_KEY` in the host environment or `.env`.
The model receives bounded advisory facts and source locations, proposes an
adjustment of at most 10 points in either direction, and supplies a rationale
with evidence fields. It cannot overwrite CVSS, EPSS, KEV, fixes, or affected
status. Model failures retain the evidence score and report their status.
`use_model: false` still fetches live feeds and computes the evidence baseline.
No EPSS/CISA credentials are needed; CISA's official GitHub mirror is the fallback.

The application ranking score is 0-100: `5 * CVSS base`, plus
`30 * sqrt(EPSS probability)`, plus up to 10 points for static package call sites
(`3 * log2(1 + calls)`), plus 10 for known runtime scopes or 5 for dev/unknown
scopes. Missing CVSS and EPSS provisionally contribute 25 and 5 respectively.
A KEV match always scores at least 90 and a model cannot downgrade it.
Priority levels are critical >=90, high >=70, medium >=40, and low <40.
This is a configurable-in-code ranking heuristic, not an exploit probability,
CVSS severity classification, or an industry standard. Fix availability is
reported for remediation and does not lower risk. `kev: false` means absence
from the successfully fetched catalog; a feed failure produces `kev: null`.

Inspect `report.prioritization_status`, `priority.missing_evidence`, provider
statuses/timestamps in `enrichment`, and `priority.model_status`. Scan coverage
status and prioritization status are independent. EPSS readings preserve every
available CVE; `epss_probability` is their maximum, with missing aliases flagged.
EPSS readings older than 7 days are retained as evidence and excluded from scoring.
A KEV catalog older than 14 days still establishes positive matches, but its
non-matches become unknown. Both conditions are flagged in provider statuses.
The newest available CVSS generation is preferred, then the highest base score
within that generation. Original vectors and advisory ranges remain available.
CISA catalog due dates are catalog evidence, not application-specific deadlines.

`usage.static_call_count` counts source call sites for the affected package.
Python uses AST import/alias analysis; Node uses import/require lexical heuristics.
The bounded scan excludes generated/vendor/cache directories and symlinks.
Evidence includes source path, line, symbol, method, limits, and scan status.
Python advisory function names, when supplied, allow exact symbol matching in
`affected_function_call_count`. Maven package-to-namespace mapping is currently
unsupported, so Java call evidence is explicitly unknown. Dynamic dispatch,
wrappers, local module shadowing and transitive usage can leave evidence incomplete.
No detected call sites proves neither safety nor non-reachability.
`usage.runtime_call_count` remains null: measuring how often a vulnerable path
actually executes requires runtime instrumentation, which this step does not add.

Run regression tests and disposable live checks (no fixture code is executed):

```powershell
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m scripts.smoke_live_scan --prioritize
# Also exercise OpenAI repo interpretation and priority assessment:
.\.venv\Scripts\python.exe -m scripts.smoke_live_scan --model
```

The smoke check uses temporary Git/SQLite fixtures and saves its complete report
under ignored `sandbox-smoke-results/`. The model check uses your API key.

## Step 4: live dependency vulnerability scanning

Start the API and open `http://127.0.0.1:8000/docs`. Submit a repository through
`POST /repositories`, or reuse its existing ID from `GET /repositories`.
Then call `POST /scans`:

```json
{
  "repository_id": 1,
  "use_model": true,
  "resolve_dependencies": false
}
```

`use_model` enables Step 3's non-deterministic README/CI interpretation and
Step 5's model-assisted priority assessment when an OpenAI key is available.
Advisory discovery uses live OSV data and can change
between scans. Vulnerability identities, affected status, and fix versions are
grounded in advisory evidence. Models do not populate vulnerability fields or
choose dependency versions; their separate repo interpretation is retained in
`report.analysis_summary` with an inference status.
No OSV API key or scanner binary is needed. OSV includes GitHub Advisory Database
records, so a separate GitHub token/provider is unnecessary for these advisories.

The response contains a persisted scan ID/status and `report.vulnerabilities`:

```json
{
  "package": "urllib3",
  "installed_version": "1.26.4",
  "cve": "CVE-2023-45803",
  "affected": true,
  "fixed_version": "1.26.18"
}
```

Each finding also preserves ecosystem, all OSV IDs/aliases/CVEs, reported fix
versions, references, severity vectors, manifests, scopes, conditional markers,
and version provenance. Advisories without a CVE use `cve: null` and retain their
advisory ID. Unpatched advisories or incomparable version schemes use
`fixed_version: null`; Git commit hashes and `last_affected` boundaries are never
presented as patched releases. A suggested fix addresses that advisory only,
not every vulnerability in the package, and may still require compatibility testing.

The scanner maps Python to PyPI, Node to npm, and Java to Maven. It queries exact
lock/resolved versions and exact manifest pins, including discovered transitive,
development and optional dependencies. `installed_version` names that concrete
version; a pin/lockfile does not prove the package is installed. `version_source`,
markers and manifests explain the evidence. Constraints, BOM/catalog policy entries,
unresolved ranges and local/git dependencies are not guessed as installed packages.
Unresolved dependencies remain in `report.unscanned_dependencies`.

Set `resolve_dependencies: true` to run Step 3's offline Docker resolution first.
This requires `aegis-sandbox:polyglot` or a prepared image selected through
`AEGIS_ANALYSIS_SANDBOX_IMAGE`. The host then performs OSV requests; repository
code continues to run only inside network-disabled Docker. Only package identifiers
and versions are sent to OSV. Model interpretation has Step 3's separate context rules.

`GET /scans/{id}` returns a saved result. `GET /scans?repository_id=1` returns
history, newest first (`limit` 1..100 and nonnegative `offset` are supported).
The POST runs synchronously and returns 201 for the created scan resource;
inspect its status even when the HTTP request succeeds. `completed` means all
identified exact versions were queried without recorded coverage/provider gaps,
`partial` retains available findings with unresolved coverage/errors, and `failed`
means the scan could not produce a usable result. No result claims an exhaustive
source-code audit, reachability analysis, or detection of undisclosed vulnerabilities.

Scan history is stored in `scan_runs.result`; deduplicated findings are stored in
the new `vulnerability_findings` table. Normalization merges transitive OSV aliases
within each ecosystem/package/version, preserving separate versions and packages.
Withdrawn advisories are ignored; related IDs are not treated as aliases. Startup
creates the new table alongside existing tables without deleting the database or
changing existing scan/repository columns. Rescans create new historical runs.

OSV requests use bounded batches, per-package pagination, limited concurrent
advisory hydration, timeouts/retries, response-size budgets, and explicit errors.
A failed lookup or unavailable exact inventory is never presented as a clean scan.

Run the offline regression suite and a live smoke test:

```powershell
.\.venv\Scripts\python.exe -m pytest tests/test_vulnerabilities.py -q
.\.venv\Scripts\python.exe -m scripts.smoke_live_scan
```

The live test uses disposable Git/SQLite fixtures, checks vulnerable Python/npm/Maven
packages against OSV, verifies persistence/deduplication and the urllib3 example,
and writes the full JSON report under ignored `sandbox-smoke-results/`. It does not
change the application's registered repositories and does not make OpenAI calls.
Live advisory data can change; offline tests use controlled OSV responses.

References: [OSV API](https://google.github.io/osv.dev/api/),
[batch pagination](https://google.github.io/osv.dev/post-v1-querybatch/),
[OSV alias/range schema](https://ossf.github.io/osv-schema/),
[OSV data sources](https://google.github.io/osv.dev/data/).

## Step 3: repository understanding

Analyze an existing clone without executing any repository code:

```powershell
.\.venv\Scripts\python.exe -m aegis.backend.analysis.repo_analyzer workspaces/OWNER-NAME-CLONE_ID
```

Add `--model` to interpret README, CI, and manifest evidence using OpenAI
(requires `OPENAI_API_KEY` in `.env` and makes paid API calls). Without a key,
or if inference fails, the static inventory is retained with an explicit status.
Only bounded excerpts of inventoried manifests, README and CI files are sent;
`.env`, source files, and generated artifacts are excluded from model context.
Repository text is treated as untrusted data.

For an ingested repository, use `POST /repositories/{id}/analysis` in `/docs`:

```json
{"use_model": false}
```

Set `use_model` to `true` for model interpretation. Analysis is computed on
demand from the existing clone; it does not refresh the clone or change the DB.
Reports contain source-file language counts, project roots, manifests, lockfiles,
declared and supported resolved dependencies, dependency scopes and markers,
package-manager conflicts, runtime constraints, important directories, CI/docs,
container files, and proposed install/build/test/lint/typecheck commands. Commands
include their working directory, source evidence, origin and confidence.
Nested projects are analyzed independently; Node packages inherit an ancestor's
package manager when they do not declare one locally.

Python supports pyproject (PEP 621, dependency groups, Poetry), requirements and
constraints includes, Pipfile, setup.cfg, uv/Poetry/Pipenv locks. Node supports
package.json, npm/pnpm/Yarn Classic/Yarn Berry/Bun text lock inventories. Java
supports Maven dependencies/properties/scopes, Gradle coordinates, Gradle lockfiles,
and version catalogs. Legacy binary Bun lockfiles are decoded inside Docker.

Dynamic Python metadata, Maven parent/BOM inheritance, computed Gradle dependencies,
and transitive graphs can be evaluated in the offline polyglot sandbox:

```powershell
docker build -f docker/Dockerfile.polyglot -t aegis-sandbox:polyglot .
.\.venv\Scripts\python.exe -m aegis.backend.analysis.repo_analyzer workspaces/OWNER-NAME-CLONE_ID --resolve
```

Or request `{"use_model": false, "resolve_dependencies": true}` at the analysis
endpoint. Add `--model` or `use_model: true` to interpret the resolved report.
`resolutions` records each method's status, exact dependencies, dependency edges,
and diagnostics. Python uses build backend metadata and installed distribution
metadata; Maven uses its dependency-tree plugin, including parent/BOM resolution;
Gradle evaluates the build and inspects all resolvable configurations, including
computed values and catalogs; npm/pnpm/Yarn/Bun install offline with lifecycle
scripts disabled and inspect installed packages. Yarn Berry uses its Plug'n'Play
API when appropriate. Lockfile inventories describe the locked packages,
but do not imply those packages are installed. Analysis never proves tests pass.

To verify selected commands, use `SandboxExecutor` inside a Step 2 sandbox:

```python
from aegis.backend.analysis.repo_analyzer import analyze_repository
from aegis.backend.sandbox.docker_runner import create_sandbox
from aegis.backend.sandbox.executor import SandboxExecutor
from aegis.backend.sandbox.policies import SandboxPolicy

report = analyze_repository(repo_path)
async with await create_sandbox(repo_path, policy=SandboxPolicy.polyglot()) as box:
    executor = SandboxExecutor(box)
    for project in report.projects:
        for command in project.commands:
            if command.kind == "test":
                result = await executor.execute(command)
                print(result.model_dump())
```

Run this snippet in an async function, with `repo_path` set to a registered clone.
Execution is explicit and confined to Docker, including a resolved-path check on
the working directory. Results distinguish passing, failing, missing tools,
timeouts, and execution errors. Network-requiring commands are skipped. Offline
install commands can execute explicitly; Node resolvers prepare dependencies
automatically using private caches with lifecycle scripts disabled. Project test scripts,
wrappers, Python backends and Gradle configuration execute only inside Docker.

The built `aegis-sandbox:polyglot` image includes Python 3.12, Node 22, npm,
pnpm 10, Yarn Classic 1 and Berry 4, Bun 1, Temurin JDK 21, Maven 3.9 and Gradle 8. Upstream
Node/Maven/Gradle/Bun images are pinned by digest in `docker/Dockerfile.polyglot`.
The runtime policy increases memory to 2 GiB and writable workspace space to
1 GiB for Java while retaining nonroot execution, no network, no mounts or host
secrets, a read-only image, dropped capabilities and time/resource limits.

The image seeds public Maven plugins, JUnit/Hamcrest and small Node fixture caches
using only checked-in trusted fixtures during image construction. Every sandbox
gets a private writable copy; caches are never shared across runs. An uncached
artifact cannot be downloaded with network disabled: resolution reports `partial`
or `unavailable`, rather than claiming an empty successful graph. Populate
project-specific caches in a derived image when needed, for example:

```dockerfile
FROM aegis-sandbox:polyglot
USER root
COPY trusted-caches/maven/ /opt/aegis-cache/maven/
COPY trusted-caches/npm/ /opt/aegis-cache/npm/
COPY trusted-caches/pnpm/ /opt/aegis-cache/pnpm/
COPY trusted-caches/yarn/ /opt/aegis-cache/yarn/
COPY trusted-caches/yarn1/ /opt/aegis-cache/yarn1/
COPY trusted-caches/bun/ /opt/aegis-cache/bun/
COPY trusted-caches/gradle/ /opt/aegis-cache/gradle/
USER 10001:10001
```

Use `dataclasses.replace(SandboxPolicy.polyglot(), image="your-prepared-image")`
with `create_sandbox` or `resolve_repository_analysis` to select that image.
For API and CLI resolution, set `AEGIS_ANALYSIS_SANDBOX_IMAGE=your-prepared-image`
in the host environment or `.env`, then restart the backend.
Use caches populated by the matching toolchain from a trusted build environment;
do not copy credential-bearing settings or enable network for repository code.
Different required Node/JDK/Gradle versions need matching derived toolchains.
pnpm caches must include registry metadata as well as the content store; Yarn
Berry caches must include the global metadata/cache directory. Required Python
build backends must also be installed in the prepared image. The base image
includes setuptools and wheel; arbitrary backend/plugin dependencies are reported
as unavailable until provisioned. The offline boundary is preserved during all
repository inspection and test execution.

Run the Step 3 tests with:

```powershell
.\.venv\Scripts\python.exe -m pytest tests/test_analysis.py tests/test_resolution.py tests/test_repos.py tests/test_sandbox.py -q
```

## Step 2: restricted remediation sandbox

Start Docker Desktop and build the local test image:

```powershell
docker build -f docker/Dockerfile.sandbox -t aegis-sandbox:py312 .
python -m pytest tests/test_sandbox.py -q
```

To run a real OpenAI agent after putting `OPENAI_API_KEY` in Aegis's `.env`:

```powershell
python -m scripts.smoke_live_sandbox
```

This creates a disposable Git repo with one failing test, asks the agent to fix it
inside Docker, reruns pytest, and saves the patch, checks, and token counts under
`sandbox-smoke-results/`. The key stays in the host process.

`create_sandbox()` accepts the `local_path` saved for a Step 1 repository. It copies
that clone into `/workspace/repo` in a fresh Docker container. The host clone is not
mounted and is not modified. Use one `SandboxWorkspace` across the agent and all
check iterations. Exiting its async context removes the container. Save a snapshot
before exit if the run will be resumed later.

```python
import asyncio
from pathlib import Path
from aegis.backend.sandbox.docker_runner import create_sandbox

async def main():
    repo = Path("workspaces/OWNER-NAME-CLONE_ID")  # Repository.local_path from Step 1
    async with await create_sandbox(repo) as box:
        print((await box.exec("ls", "/workspace/repo")).stdout.decode())
        # Set OPENAI_API_KEY on the host to run the OpenAI agent; it is never
        # forwarded into the container.
        # result = await box.run_agent("Fix the reported issue and run tests")
        print(await box.run_checks({"tests": ["python", "-m", "pytest", "-q"]}, "results/checks"))
        await box.export_results("results/export")

asyncio.run(main())
```

The image includes Python 3.12, Git, pytest, and Bandit. Checks can also run
`bandit -r /workspace/repo`; internet based scanners cannot download data inside
the network disabled container. The result export contains `patch.diff`, Git status,
container output, and `workspace.tar`; declared check stdout, stderr, and exit codes
are saved by `run_checks`. To resume changes, pass `snapshot="results/export/workspace.tar"`
to `create_sandbox`. Keep exported results outside the source clone.

The Agents SDK and OpenAI Python package are pinned together because their sandbox
and usage interfaces change. Review `SecureDockerSandboxClient` before upgrading
either dependency; it enforces container restrictions through an SDK creation hook.

Containers run as UID 10001 with no network or published ports, a read only image,
bounded writable tmpfs, CPU, memory and process limits, all Linux capabilities
dropped, and no Docker socket or host secrets. The host process needs access to the
Docker daemon. These restrictions limit untrusted code, but Docker is not a hardened
multi tenant boundary; use a dedicated machine or VM for hostile repositories.
