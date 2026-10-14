# Aegis

Open source vulnerability remediation service.

The `aegis/backend` package contains the FastAPI application and production
logic. Benchmark material lives under `evals`, tests under `tests`, and
deployment/UI placeholders under `docker` and `frontend`.

## Setup

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
Copy-Item .env.example .env
uvicorn aegis.backend.main:app --reload
```

Run tests with `pytest`.

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
