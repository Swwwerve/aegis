"""Deterministic local fixture and model for the sandbox Patch Agent demo."""

import json
import subprocess
from pathlib import Path

from agents.items import ModelResponse
from agents.models.interface import Model
from agents.usage import Usage
from openai.types.responses import (
    ResponseFunctionToolCall,
    ResponseOutputMessage,
    ResponseOutputText,
)

from ..context.context_planner import ContextPacket, ContextSnippet
from ..schemas.remediation import (
    AdvisoryReference,
    EvidenceReference,
    PlanStep,
    RemediationPlan,
    SkillReference,
    VersionChange,
)


class DemoPatchModel(Model):
    """Drive the real Patch Agent tools without an external model call."""

    def __init__(self):
        self.turn = 0

    async def get_response(self, *args, **kwargs):
        if self.turn == 0:
            output = [
                ResponseFunctionToolCall(
                    type="function_call",
                    id="demo-read",
                    call_id="demo-read",
                    name="load_skill",
                    arguments=json.dumps({"name": "npm-remediation"}),
                )
            ]
        elif self.turn == 1:
            output = [
                ResponseFunctionToolCall(
                    type="function_call",
                    id="demo-read-file",
                    call_id="demo-read-file",
                    name="read_file",
                    arguments=json.dumps(
                        {"path": "package.json", "start": 1, "end": 40}
                    ),
                )
            ]
        elif self.turn == 2:
            output = [
                ResponseFunctionToolCall(
                    type="function_call",
                    id="demo-update",
                    call_id="demo-update",
                    name="update_dependency",
                    arguments=json.dumps(
                        {
                            "package": "aegis-demo-package",
                            "from_version": "1.0.0",
                            "to_version": "1.0.1",
                        }
                    ),
                )
            ]
        elif self.turn == 3:
            output = [
                ResponseFunctionToolCall(
                    type="function_call",
                    id="demo-diff",
                    call_id="demo-diff",
                    name="git_diff",
                    arguments="{}",
                )
            ]
        else:
            text = {
                "status": "completed",
                "summary": "Demo dependency update applied inside the isolated sandbox.",
                "actions": [
                    "Loaded the npm remediation Skill",
                    "Read the supplied package manifest",
                    "Applied the supplied dependency version change",
                    "Inspected the resulting sandbox diff",
                ],
                "errors": [],
            }
            output = [
                ResponseOutputMessage(
                    id="demo-result",
                    role="assistant",
                    status="completed",
                    type="message",
                    content=[
                        ResponseOutputText(
                            type="output_text",
                            text=json.dumps(text),
                            annotations=[],
                        )
                    ],
                )
            ]
        self.turn += 1
        return ModelResponse(output=output, usage=Usage(), response_id=None)

    async def stream_response(self, *args, **kwargs):
        if False:
            yield None


def create_demo_repository(root: Path) -> Path:
    """Create a disposable, committed Git fixture under the configured workspace."""

    root.mkdir(parents=True, exist_ok=True)
    if any(root.iterdir()):
        raise ValueError("Demo repository directory must be empty")
    (root / "package.json").write_text(
        '{\n  "name": "aegis-patch-agent-demo",\n'
        '  "dependencies": {"aegis-demo-package": "1.0.0"}\n}\n',
        encoding="utf-8",
    )
    commands = [
        ["git", "init", "-q", str(root)],
        ["git", "-C", str(root), "config", "user.email", "demo@aegis.local"],
        ["git", "-C", str(root), "config", "user.name", "Aegis Demo"],
        ["git", "-C", str(root), "add", "package.json"],
        ["git", "-C", str(root), "commit", "-qm", "Initial demo fixture"],
    ]
    for command in commands:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        if completed.returncode:
            raise RuntimeError("Unable to initialize the disposable demo repository")
    return root


def demo_plan() -> RemediationPlan:
    return RemediationPlan(
        cve_id="CVE-2099-0001",
        status="ready",
        summary="Upgrade the demo package from the supplied confirmed version.",
        root_cause="The demo manifest pins a vulnerable package release.",
        affected_files=["package.json"],
        application_code_changes=[],
        reasoning="This is a deterministic demonstration plan, not a real advisory.",
        confidence=1,
        skills_used=["npm-remediation"],
        source_references=[
            EvidenceReference(
                evidence_id="demo-manifest",
                path="package.json",
                sha256="0" * 64,
            )
        ],
        advisory_references=[
            AdvisoryReference(
                advisory_id="DEMO-ADVISORY-0001",
                source="https://example.invalid/aegis-demo",
            )
        ],
        skill_references=[
            SkillReference(
                name="npm-remediation",
                path="backend/skills/npm-remediation/SKILL.md",
                sha256="0" * 64,
            )
        ],
        steps=[
            PlanStep(
                kind="dependency",
                description="Update the demo package declaration.",
                paths=["package.json"],
                evidence_ids=["demo-manifest"],
            )
        ],
        version_changes=[
            VersionChange(
                package="aegis-demo-package",
                ecosystem="npm",
                installed_version="1.0.0",
                proposed_version="1.0.1",
            )
        ],
        validation=[],
        risks=["This disposable fixture is not a real vulnerability finding."],
        missing_context=[],
    )


def demo_packet() -> ContextPacket:
    return ContextPacket(
        cve_id="CVE-2099-0001",
        status="completed",
        investigation_status="completed",
        advisories={
            "findings": [
                {
                    "package": "aegis-demo-package",
                    "ecosystem": "npm",
                    "installed_version": "1.0.0",
                    "fixed_version": "1.0.1",
                    "summary": "Synthetic demonstration advisory.",
                    "advisory_ids": ["DEMO-ADVISORY-0001"],
                    "advisory_evidence": [
                        {
                            "advisory_id": "DEMO-ADVISORY-0001",
                            "source": "https://example.invalid/aegis-demo",
                        }
                    ],
                }
            ]
        },
        dependencies=[
            {
                "package": "aegis-demo-package",
                "projects": [
                    {
                        "root": ".",
                        "manifests": ["package.json"],
                        "test_commands": [],
                    }
                ],
            }
        ],
        snippets=[
            ContextSnippet(
                snippet_id="demo-manifest",
                path="package.json",
                start=1,
                end=10,
                content='{"dependencies":{"aegis-demo-package":"1.0.0"}}',
                truncated=False,
                reason="Demo manifest evidence",
                sha256="0" * 64,
            )
        ],
    )
