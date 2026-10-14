"""Skill-guided remediation planning without repository execution."""

import asyncio
import hashlib
import json
from pathlib import PurePosixPath

from agents import RunConfig, Runner
from agents.models.openai_responses import OpenAIResponsesModel
from openai import AsyncOpenAI

from ..agents.remediation_agent import make_remediation_agent
from ..context.context_planner import plan_hybrid_context
from ..context.remediation_skills import RemediationSkills
from ..core.config import settings
from ..core.progress import emit
from ..schemas.remediation import (
    AdvisoryReference,
    EvidenceReference,
    RemediationPlan,
    SkillReference,
    incomplete_plan,
)


def validate_plan(plan, packet, skills):
    gaps = list(plan.missing_context)
    if plan.cve_id != packet.cve_id:
        gaps.append("Plan CVE does not match the reviewed context")
    if set(plan.skills_used) != set(skills.loaded) or skills.errors:
        gaps.append("Plan skills are not backed by eligible loaded skills")
    primary = skills.eligible & {
        "python-remediation",
        "npm-remediation",
        "maven-remediation",
        "gradle-remediation",
    }
    if not primary <= set(skills.loaded) or not primary:
        gaps.append("No applicable repository remediation skill was loaded")
    paths = {s.path for s in packet.snippets}
    ids = {s.snippet_id for s in packet.snippets}
    findings = packet.advisories.get("findings", [])
    ids.update(i for f in findings for i in f.get("advisory_ids", []))
    roots = {p["root"] for d in packet.dependencies for p in d.get("projects", [])}
    declared_checks = {
        (tuple(command["argv"]), command["cwd"])
        for info in packet.dependencies
        for project in info.get("projects", [])
        for command in project.get("test_commands", [])
    }
    for entry in [*plan.steps, *plan.validation]:
        if not set(entry.evidence_ids) <= ids:
            gaps.append("A proposed step or check cites evidence outside the packet")
    for step in plan.steps:
        if not set(step.paths) <= paths:
            gaps.append("A proposed file change needs additional source context")
    for check in plan.validation:
        path = PurePosixPath(check.cwd)
        if (
            path.is_absolute()
            or ".." in path.parts
            or "\\" in check.cwd
            or ":" in check.cwd
            or check.cwd not in roots
        ):
            gaps.append("A proposed check lacks an affected project working directory")
        if check.argv and (tuple(check.argv), check.cwd) not in declared_checks:
            gaps.append(
                "A proposed validation command needs declared test-command evidence"
            )
    for change in plan.version_changes:
        if not any(
            change.package == f["package"]
            and change.ecosystem == f["ecosystem"]
            and change.installed_version == f["installed_version"]
            and change.proposed_version == f.get("fixed_version")
            for f in findings
        ):
            gaps.append(
                "A proposed upgrade is not a confirmed fixed version in the packet"
            )
    plan.affected_files = list(
        dict.fromkeys(
            [
                *plan.affected_files,
                *(path for step in plan.steps for path in step.paths),
            ]
        )
    )[:20]
    # References are attached by the service, not trusted from model-generated
    # paths or hashes. This keeps the persisted plan auditable and packet-scoped.
    plan.source_references = [
        EvidenceReference(
            evidence_id=snippet.snippet_id,
            path=snippet.path,
            sha256=snippet.sha256,
        )
        for snippet in packet.snippets
        if snippet.path in plan.affected_files
        or any(snippet.snippet_id in entry.evidence_ids for entry in plan.steps)
        or any(snippet.snippet_id in entry.evidence_ids for entry in plan.validation)
    ]
    plan.advisory_references = [
        AdvisoryReference(
            advisory_id=advisory_id,
            source=evidence.get("source", ""),
        )
        for finding in findings
        for evidence in finding.get("advisory_evidence", [])
        for advisory_id in dict.fromkeys(
            [
                evidence.get("advisory_id", ""),
                finding.get("advisory_id", ""),
                *finding.get("advisory_ids", []),
            ]
        )
        if advisory_id and evidence.get("source")
    ]
    plan.advisory_references = list(
        {
            (item.advisory_id, item.source): item
            for item in plan.advisory_references
        }.values()
    )
    plan.skill_references = [
        SkillReference(
            name=name,
            path=f"backend/skills/{name}/SKILL.md",
            sha256=hashlib.sha256(skills.loaded[name].encode()).hexdigest(),
        )
        for name in plan.skills_used
        if name in skills.loaded
    ]
    if not plan.source_references:
        gaps.append("Plan does not reference a supplied source or dependency snippet")
    if not plan.advisory_references:
        gaps.append("Plan does not reference supplied advisory evidence")
    if not plan.skill_references:
        gaps.append("Plan does not reference loaded Skill instructions")
    if plan.status == "ready" and (not plan.steps or not plan.validation):
        gaps.append("A ready plan requires concrete steps and proposed validation")
    if gaps:
        plan.status = "needs_context"
        plan.missing_context = list(dict.fromkeys(gaps))[:12]
    return plan


async def plan_remediation(
    packet, *, model="gpt-5.4", progress=None, max_turns=10, timeout_seconds=120
):
    try:
        payload = packet.remediation_payload()
    except ValueError:
        return incomplete_plan(
            packet.cve_id,
            "needs_context",
            "Context investigation must be complete before remediation planning",
        )
    if isinstance(model, str) and settings.openai_api_key is None:
        return incomplete_plan(
            packet.cve_id, "unavailable", "OPENAI_API_KEY is not configured"
        )
    client = None
    try:
        skills = RemediationSkills(packet, progress=progress)
        await emit(
            progress,
            "remediation_plan",
            "running",
            "Selecting necessary skills and proposing the fix and regression checks.",
        )
        if isinstance(model, str):
            client = AsyncOpenAI(api_key=settings.openai_api_key.get_secret_value())
            model = OpenAIResponsesModel(model=model, openai_client=client)
        result = await asyncio.wait_for(
            Runner.run(
                make_remediation_agent(model, skill_tool=skills.tool()),
                json.dumps({"evidence": payload, "eligible_skills": skills.catalog}),
                max_turns=max_turns,
                run_config=RunConfig(tracing_disabled=True),
            ),
            timeout=timeout_seconds,
        )
        plan = validate_plan(
            RemediationPlan.model_validate(result.final_output), packet, skills
        )
        await emit(
            progress,
            "remediation_plan",
            plan.status,
            "Remediation plan is ready for review."
            if plan.status == "ready"
            else "Planning needs additional evidence.",
            skills=plan.skills_used,
        )
        return plan
    except Exception as exc:  # noqa: BLE001 -- provider errors can contain private evidence
        await emit(
            progress,
            "remediation_plan",
            "failed",
            f"Planning failed ({type(exc).__name__}).",
        )
        return incomplete_plan(
            packet.cve_id,
            "failed",
            f"Remediation planning failed ({type(exc).__name__})",
        )
    finally:
        if client is not None:
            await client.close()


async def plan_repository_remediation(
    path, cve_id, report, *, progress=None, clarification="", model="gpt-5.4"
):
    packet = await plan_hybrid_context(
        path,
        cve_id,
        report,
        progress=progress,
        clarification=clarification,
        model=model,
    )
    if packet.status != "completed":
        status = (
            packet.status
            if packet.status in {"unavailable", "failed"}
            else "needs_context"
        )
        return incomplete_plan(
            cve_id,
            status,
            "; ".join(packet.missing_context) or "Context investigation is incomplete",
        )
    return await plan_remediation(packet, model=model, progress=progress)
