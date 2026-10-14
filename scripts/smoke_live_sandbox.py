"""Run one real OpenAI SandboxAgent against a tiny, disposable Git repository."""

import asyncio
import json
import subprocess
import tempfile
from pathlib import Path
from uuid import uuid4

from agents.exceptions import AgentsException
from agents.lifecycle import RunHooksBase
from openai import APIError

from aegis.backend.core.config import settings
from aegis.backend.sandbox.docker_runner import create_sandbox


def git(*args: str) -> None:
    subprocess.run(["git", *args], check=True, capture_output=True)


class TraceHooks(RunHooksBase):
    def __init__(self, path: Path) -> None:
        self.path = path

    async def on_llm_end(self, context, agent, response) -> None:
        with self.path.open("a", encoding="utf-8") as stream:
            for item in response.output:
                stream.write(json.dumps(item.model_dump(exclude_none=True), default=str) + "\n")

    async def on_tool_end(self, context, agent, tool, result) -> None:
        with self.path.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps({"tool": tool.name, "result": result[:1000]}) + "\n")


async def main() -> None:
    if settings.openai_api_key is None:
        raise SystemExit("Set OPENAI_API_KEY in Aegis/.env before running this smoke test")

    output = Path("sandbox-smoke-results") / uuid4().hex
    output.mkdir(parents=True)
    with tempfile.TemporaryDirectory(prefix="aegis-live-") as temporary:
        root = Path(temporary) / "workspaces"
        repo = root / "example"
        repo.mkdir(parents=True)
        git("init", str(repo))
        (repo / "calculator.py").write_bytes(b"def add(a, b):\n    return a - b\n")
        (repo / "test_calculator.py").write_bytes(
            b"from calculator import add\n\ndef test_add():\n    assert add(2, 3) == 5\n"
        )
        (repo / ".gitignore").write_bytes(b"__pycache__/\n.pytest_cache/\n")
        git("-C", str(repo), "add", ".")
        git("-C", str(repo), "-c", "user.name=Aegis smoke", "-c",
            "user.email=smoke@example.invalid", "commit", "-m", "initial")

        async with await create_sandbox(repo, workspace_root=root) as box:
            container = box.client.docker_client.containers.get(box.session.state.container_id)
            assert not any("OPENAI_API_KEY" in item for item in container.attrs["Config"]["Env"])
            response = None
            agent_error = None
            try:
                response = await box.run_agent(
                    "In /workspace/repo, fix calculator.py so the existing test passes. "
                    "Use the sandbox shell to inspect and run the test. Use apply_patch to edit "
                    "repo/calculator.py. Do not edit test_calculator.py. Keep the change minimal.",
                    max_turns=20,
                    hooks=TraceHooks(output / "agent-trace.jsonl"),
                )
            except (AgentsException, APIError, TimeoutError) as exc:
                agent_error = f"{type(exc).__name__}: {exc}"
            checks = await box.run_checks(
                {"pytest": ["python", "-m", "pytest", "-q", "/workspace/repo/test_calculator.py"]},
                output / "checks",
            )
            await box.export_results(output / "export")

        summary = {
            "checks": checks,
            "agent_output": str(response.final_output) if response else None,
            "agent_error": agent_error,
            "input_tokens": sum(item.usage.input_tokens for item in response.raw_responses) if response else None,
            "output_tokens": sum(item.usage.output_tokens for item in response.raw_responses) if response else None,
        }
        (output / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
        if checks["pytest"] != 0 or agent_error:
            raise SystemExit(f"Live sandbox test failed; inspect {output.resolve()}: {agent_error}")
        print(f"Live sandbox test passed. Results: {output.resolve()}")
        print(f"Tokens: {summary['input_tokens']} input, {summary['output_tokens']} output")


if __name__ == "__main__":
    asyncio.run(main())
