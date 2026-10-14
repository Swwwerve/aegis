"""Real SDK lazy-skill selection and capability-free remediation plans."""

# ruff: noqa: F811 -- imported pytest fixture

import asyncio
import json

import pytest
from agents.items import ModelResponse
from agents.models.interface import Model
from agents.usage import Usage
from openai.types.responses import (
    ResponseFunctionToolCall,
    ResponseOutputMessage,
    ResponseOutputText,
)
from test_context import CVE, PlanningModel, ReviewModel, report, repository  # noqa: F401

from aegis.backend.agents.remediation_agent import make_remediation_agent
from aegis.backend.context.context_planner import plan_hybrid_context
from aegis.backend.context.remediation_skills import RemediationSkills
from aegis.backend.services.remediation_service import plan_remediation


class PlanModel(Model):
    def __init__(self, *, skill="python-remediation", version="1.26.18", path=None):
        self.skill, self.version, self.path = skill, version, path
        self.turn = 0
        self.tools = []
        self.seed = None

    async def get_response(self, *args, **kwargs):
        inputs = kwargs.get("input", args[1] if len(args) > 1 else [])
        self.tools = [tool.name for tool in kwargs["tools"]]
        user = next(
            item
            for item in inputs
            if isinstance(item, dict) and item.get("role") == "user"
        )
        content = user["content"]
        if isinstance(content, list):
            content = "".join(item.get("text", "") for item in content)
        self.seed = json.loads(content)
        if self.turn == 0:
            output = [
                ResponseFunctionToolCall(
                    type="function_call",
                    id="load",
                    call_id="load",
                    name="load_skill",
                    arguments=json.dumps({"name": self.skill}),
                )
            ]
        else:
            evidence = self.seed["evidence"]
            pin = next(
                s for s in evidence["snippets"] if s["path"] == "requirements.txt"
            )
            text = json.dumps(
                {
                    "cve_id": evidence["cve_id"],
                    "status": "ready",
                    "summary": "Propose a targeted urllib3 upgrade and regression checks.",
                    "skills_used": [self.skill],
                    "steps": [
                        {
                            "kind": "dependency",
                            "description": "Propose changing the owning pin to the confirmed fixed release",
                            "paths": [self.path or pin["path"]],
                            "evidence_ids": [pin["snippet_id"]],
                        }
                    ],
                    "version_changes": [
                        {
                            "package": "urllib3",
                            "ecosystem": "PyPI",
                            "installed_version": "1.26.4",
                            "proposed_version": self.version,
                        }
                    ],
                    "validation": [
                        {
                            "description": "Propose the declared regression suite",
                            "argv": [],
                            "cwd": ".",
                            "evidence_ids": [pin["snippet_id"]],
                        }
                    ],
                    "risks": [
                        "Confirm interpreter and caller compatibility before implementation"
                    ],
                    "missing_context": [],
                }
            )
            output = [
                ResponseOutputMessage(
                    id="plan",
                    role="assistant",
                    status="completed",
                    type="message",
                    content=[
                        ResponseOutputText(
                            type="output_text", text=text, annotations=[]
                        )
                    ],
                )
            ]
        self.turn += 1
        return ModelResponse(output=output, usage=Usage(), response_id=None)

    async def stream_response(self, *args, **kwargs):
        if False:
            yield None


def packet_for(root):
    return asyncio.run(
        plan_hybrid_context(
            root,
            CVE,
            report(root),
            model=PlanningModel(),
            investigator_model=ReviewModel(),
        )
    )


def test_agent_has_no_execution_or_repository_capabilities():
    agent = make_remediation_agent()
    assert agent.tools == [] and agent.handoffs == []
    assert type(agent).__name__ == "Agent"


def test_only_requested_eligible_skill_is_loaded_and_plan_changes_nothing(repository):
    packet = packet_for(repository)
    skills = RemediationSkills(packet)
    assert "npm-remediation" not in skills.eligible and skills.loaded == {}
    assert "instructions" not in json.dumps(skills.catalog)
    before = {
        p.relative_to(repository).as_posix(): p.read_bytes()
        for p in repository.rglob("*")
        if p.is_file()
    }
    model = PlanModel()
    events = []

    async def progress(event):
        events.append(event)

    plan = asyncio.run(plan_remediation(packet, model=model, progress=progress))
    assert plan.status == "ready", plan.model_dump()
    assert plan.skills_used == ["python-remediation"] and model.tools == ["load_skill"]
    assert "Maven parent" not in json.dumps(model.seed)
    assert [event["skill"] for event in events if "skill" in event] == [
        "python-remediation"
    ]
    after = {
        p.relative_to(repository).as_posix(): p.read_bytes()
        for p in repository.rglob("*")
        if p.is_file()
    }
    assert before == after


@pytest.mark.parametrize(
    "ecosystem,manifest,skill,excluded",
    [
        ("PyPI", "requirements.txt", "python-remediation", "npm-remediation"),
        ("npm", "package.json", "npm-remediation", "python-remediation"),
        ("Maven", "pom.xml", "maven-remediation", "gradle-remediation"),
        ("Maven", "build.gradle.kts", "gradle-remediation", "maven-remediation"),
    ],
)
def test_skills_follow_affected_project_ecosystem(
    repository, ecosystem, manifest, skill, excluded
):
    packet = packet_for(repository)
    packet.advisories["findings"][0]["ecosystem"] = ecosystem
    packet.dependencies[0]["projects"][0]["manifests"] = [manifest]
    assert skill in RemediationSkills(packet).eligible
    assert excluded not in RemediationSkills(packet).eligible


def test_vulnerability_skills_are_conditional_and_traversal_is_rejected(repository):
    packet = packet_for(repository)
    assert "injection-remediation" not in RemediationSkills(packet).eligible
    packet.advisories["findings"][0]["summary"] = (
        "Unsafe deserialization and SQL injection"
    )
    skills = RemediationSkills(packet)
    assert {
        "deserialization-remediation",
        "injection-remediation",
        "security-review",
    } <= skills.eligible
    assert "error" in json.loads(asyncio.run(skills.load("../../secret")))
    assert skills.loaded == {}


@pytest.mark.parametrize(
    "options",
    [{"skill": "maven-remediation"}, {"version": "99.0.0"}, {"path": "unseen.py"}],
)
def test_ungrounded_skill_version_or_file_changes_need_context(repository, options):
    plan = asyncio.run(
        plan_remediation(packet_for(repository), model=PlanModel(**options))
    )
    assert plan.status == "needs_context" and plan.missing_context


def test_unreviewed_context_and_exhausted_turns_cannot_produce_ready_plans(repository):
    packet = packet_for(repository)
    packet.investigation_status = "not_requested"
    model = PlanModel()
    assert asyncio.run(plan_remediation(packet, model=model)).status == "needs_context"
    assert model.turn == 0
    packet.investigation_status = "completed"
    plan = asyncio.run(plan_remediation(packet, model=model, max_turns=1))
    assert plan.status == "failed"
