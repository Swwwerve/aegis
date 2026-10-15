"""Execute one validated remediation plan in the restricted Docker sandbox."""

import asyncio
import json
import tempfile
from pathlib import Path
from uuid import uuid4

from agents import RunConfig, Runner
from agents.models.interface import Model
from agents.models.openai_responses import OpenAIResponsesModel
from openai import AsyncOpenAI

from ..agents.patch_agent import PatchTools, make_patch_agent
from ..context.remediation_skills import RemediationSkills
from ..core.config import settings
from ..core.progress import emit
from ..sandbox.docker_runner import SandboxWorkspace
from ..schemas.remediation import DependencyPatch, PatchResult, RemediationPlan


async def patch_remediation(
    workspace: SandboxWorkspace,
    plan: RemediationPlan,
    packet,
    *,
    model: str | Model = "gpt-5.4",
    progress=None,
    max_turns: int = 16,
) -> PatchResult:
    run_id = str(uuid4())
    remediation_id = f"{plan.cve_id}:{run_id}"
    base = PatchResult(
        remediation_id=remediation_id,
        run_id=run_id,
        cve_id=plan.cve_id,
        status="failed",
        plan_references=[
            *[reference.evidence_id for reference in plan.source_references],
            *[reference.advisory_id for reference in plan.advisory_references],
            *[reference.name for reference in plan.skill_references],
        ],
    )
    if plan.status != "ready":
        base.status = "needs_context"
        base.errors.append("Only a ready RemediationPlan can be executed")
        base.human_intervention_required = True
        return base
    if not plan.version_changes and not plan.application_code_changes:
        base.status = "needs_context"
        base.errors.append("Plan contains no authorized dependency or application change")
        base.human_intervention_required = True
        return base
    if isinstance(model, str) and settings.openai_api_key is None:
        base.status = "failed"
        base.errors.append("OPENAI_API_KEY is not configured")
        base.human_intervention_required = True
        return base

    client = None
    try:
        skills = RemediationSkills(packet, progress=progress)
        tools = PatchTools(workspace, plan)
        await emit(progress, "patch_agent", "running", "Starting sandbox patch execution", run_id=run_id)
        if isinstance(model, str):
            client = AsyncOpenAI(api_key=settings.openai_api_key.get_secret_value())
            model = OpenAIResponsesModel(model=model, openai_client=client)
        prompt = json.dumps(
            {
                "remediation_plan": plan.model_dump(mode="json"),
                "evidence": packet.remediation_payload(),
                "eligible_skills": skills.catalog,
                "execution_rule": "Load only skills needed for this plan, then apply and inspect the patch.",
            },
            ensure_ascii=False,
        )
        result = await asyncio.wait_for(
            Runner.run(
                make_patch_agent(
                    model,
                    tools=[*tools.tools(), skills.tool()],
                ),
                prompt,
                max_turns=max_turns,
                run_config=RunConfig(tracing_disabled=False),
            ),
            timeout=workspace.policy.agent_timeout_seconds,
        )
        report = result.final_output
        artifact_dir = Path(tempfile.mkdtemp(prefix="aegis-patch-"))
        await workspace.export_results(artifact_dir)
        status = await workspace.exec(
            "git", "-C", "/workspace/repo", "diff", "--name-only", "HEAD"
        )
        modified = [
            line.strip()
            for line in status.stdout.decode("utf-8", errors="replace").splitlines()
            if line.strip()
        ]
        allowed = set(plan.affected_files) | {
            path for step in plan.steps for path in step.paths
        }
        unexpected = sorted(set(modified) - allowed)
        if unexpected:
            base.errors.append(f"Unexpected files changed: {', '.join(unexpected)}")
            base.unresolved_issues.append("Sandbox patch exceeded the authorized file scope")
            base.human_intervention_required = True
        base.status = "completed" if report.status == "completed" and not base.errors else "failed"
        base.modified_files = modified
        base.artifact_location = str(artifact_dir)
        base.commands_executed = tools.executed
        base.errors.extend(tools.errors)
        base.unresolved_issues.extend(report.errors)
        base.further_testing_required = True
        base.dependency_changes = [
            DependencyPatch(
                package=change.package,
                ecosystem=change.ecosystem,
                from_version=change.installed_version,
                to_version=change.proposed_version,
                files=[
                    path
                    for path in plan.affected_files
                    if path.endswith(
                        ("requirements.txt", "package.json", "pom.xml", "build.gradle", "build.gradle.kts")
                    )
                ],
            )
            for change in plan.version_changes
        ]
        await emit(
            progress,
            "patch_agent",
            base.status,
            "Sandbox patch execution completed; independent testing is still required."
            if base.status == "completed"
            else "Sandbox patch execution requires review.",
            run_id=run_id,
            modified_files=base.modified_files,
            artifact_location=base.artifact_location,
        )
        return base
    except TimeoutError:
        base.status = "sandbox_error"
        base.errors.append("Patch agent exceeded the sandbox execution timeout")
        base.human_intervention_required = True
        return base
    except Exception as exc:  # noqa: BLE001 -- convert provider/sandbox failures to PatchResult
        base.status = "sandbox_error"
        base.errors.append(f"Patch execution failed ({type(exc).__name__})")
        base.human_intervention_required = True
        await emit(progress, "patch_agent", "failed", base.errors[-1], run_id=run_id)
        return base
    finally:
        if client is not None:
            await client.close()
