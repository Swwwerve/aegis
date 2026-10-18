import asyncio
import json
from types import SimpleNamespace

from aegis.backend.agents.patch_agent import PatchTools, _safe_path
from aegis.backend.schemas.remediation import (
    PlanStep,
    ProposedCheck,
    RemediationPlan,
    VersionChange,
)
from aegis.backend.services.patch_demo import DemoPatchModel, demo_packet, demo_plan
from aegis.backend.services.patch_service import patch_remediation


class FakeWorkspace:
    def __init__(self, files=None, results=None):
        self.files = {key: value.encode() for key, value in (files or {}).items()}
        self.results = results or {}
        self.policy = SimpleNamespace(
            command_timeout_seconds=5,
            agent_timeout_seconds=30,
        )
        self.commands = []

    async def read_file(self, path):
        return self.files[path]

    async def write_file(self, path, data):
        self.files[path] = data

    async def exec(self, *command, timeout=None):
        self.commands.append(command)
        key = tuple(command)
        if "--name-only" in command:
            return SimpleNamespace(
                exit_code=0, stdout=b"package.json\n", stderr=b""
            )
        return self.results.get(
            key,
            SimpleNamespace(exit_code=0, stdout=b"", stderr=b""),
        )

    async def export_results(self, output):
        output.mkdir(parents=True, exist_ok=True)


def make_plan(**overrides):
    values = {
        "cve_id": "CVE-2024-1234",
        "status": "ready",
        "summary": "Upgrade the affected package",
        "skills_used": ["npm-remediation"],
        "steps": [
            PlanStep(
                kind="dependency",
                description="Update package.json",
                paths=["package.json"],
                evidence_ids=["snippet-1"],
            )
        ],
        "version_changes": [
            VersionChange(
                package="lodash",
                ecosystem="npm",
                installed_version="4.17.20",
                proposed_version="4.17.21",
            )
        ],
        "validation": [
            ProposedCheck(
                description="Run tests",
                argv=["npm", "test"],
                cwd=".",
                evidence_ids=["snippet-1"],
            )
        ],
        "risks": [],
        "missing_context": [],
    }
    values.update(overrides)
    return RemediationPlan(**values)


def invoke(tool, payload):
    context = SimpleNamespace(tool_name=tool.name)
    return json.loads(asyncio.run(tool.on_invoke_tool(context, json.dumps(payload))))


def test_safe_path_rejects_traversal_and_unlisted_files():
    assert _safe_path("package.json", {"package.json"}) == "package.json"
    for path in ("../package.json", r"src\app.py", "/etc/passwd", "other.txt"):
        try:
            _safe_path(path, {"package.json"})
        except ValueError:
            pass
        else:
            raise AssertionError(f"{path} should be rejected")


def test_patch_tools_update_only_authorized_dependency():
    workspace = FakeWorkspace({"package.json": '{"lodash":"4.17.20"}'})
    tools = PatchTools(workspace, make_plan()).tools()
    result = invoke(
        next(tool for tool in tools if tool.name == "update_dependency"),
        {"package": "lodash", "from_version": "4.17.20", "to_version": "4.17.21"},
    )
    assert result == {"updated": ["package.json"]}
    assert b"4.17.21" in workspace.files["package.json"]

    rejected = invoke(
        next(tool for tool in tools if tool.name == "update_dependency"),
        {"package": "lodash", "from_version": "4.17.20", "to_version": "4.17.22"},
    )
    assert "error" in rejected


def test_patch_tools_reject_undeclared_commands_and_apply_authorized_patch():
    workspace = FakeWorkspace({"package.json": '{"lodash":"4.17.20"}'})
    tools = PatchTools(workspace, make_plan()).tools()
    command_tool = next(tool for tool in tools if tool.name == "run_command")
    assert "error" in invoke(command_tool, {"argv": ["rm", "-rf", "."], "cwd": "."})
    assert invoke(command_tool, {"argv": ["npm", "test"], "cwd": "."})["exit_code"] == 0

    patch_tool = next(tool for tool in tools if tool.name == "apply_patch")
    patch = (
        "--- a/package.json\n"
        "+++ b/package.json\n"
        "@@ -1 +1 @@\n"
        '-{"lodash":"4.17.20"}\n'
        '+{"lodash":"4.17.21"}\n'
    )
    result = invoke(patch_tool, {"path": "package.json", "patch": patch})
    assert "error" in result or result.get("applied") == "package.json"


def test_demo_model_drives_the_real_patch_agent_loop():
    async def run():
        workspace = FakeWorkspace(
            {"package.json": '{"dependencies":{"aegis-demo-package":"1.0.0"}}'}
        )
        result = await patch_remediation(
            workspace,
            demo_plan(),
            demo_packet(),
            model=DemoPatchModel(),
            demonstration=True,
        )
        return result, workspace

    result, workspace = asyncio.run(run())
    assert result.status == "completed"
    assert result.demonstration is True
    assert result.modified_files == ["package.json"]
    assert b"1.0.1" in workspace.files["package.json"]


def test_patch_service_blocks_incomplete_plans():
    async def run():
        workspace = FakeWorkspace({"package.json": '{"lodash":"4.17.20"}'})
        return await patch_remediation(
            workspace,
            make_plan(status="needs_context", missing_context=["Missing caller evidence"]),
            demo_packet(),
            model=DemoPatchModel(),
        )

    result = asyncio.run(run())
    assert result.status == "needs_context"
    assert result.human_intervention_required is True
    assert "Only a ready RemediationPlan can be executed" in result.errors
