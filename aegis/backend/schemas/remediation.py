"""Proposals for human review, without execution results."""

from typing import Literal

from pydantic import BaseModel, Field


class EvidenceReference(BaseModel):
    """A precise, packet-backed reference used by a proposed plan."""

    evidence_id: str = Field(min_length=1, max_length=200)
    path: str = Field(min_length=1, max_length=500)
    sha256: str | None = Field(default=None, min_length=64, max_length=64)


class AdvisoryReference(BaseModel):
    """A reference to advisory evidence retained by the vulnerability scanner."""

    advisory_id: str = Field(min_length=1, max_length=200)
    source: str = Field(min_length=1, max_length=1000)
    evidence_ids: list[str] = Field(default_factory=list, max_length=12)


class SkillReference(BaseModel):
    """A traceable reference to the trusted Skill instructions loaded by the agent."""

    name: str = Field(min_length=1, max_length=100)
    path: str = Field(min_length=1, max_length=500)
    sha256: str = Field(min_length=64, max_length=64)


class PlanStep(BaseModel):
    kind: Literal["dependency", "code", "configuration", "validation", "review"]
    description: str = Field(min_length=1, max_length=1500)
    paths: list[str] = Field(max_length=12)
    evidence_ids: list[str] = Field(min_length=1, max_length=12)


class ProposedCheck(BaseModel):
    description: str = Field(min_length=1, max_length=800)
    argv: list[str] = Field(max_length=64)
    cwd: str
    evidence_ids: list[str] = Field(min_length=1, max_length=12)


class VersionChange(BaseModel):
    package: str
    ecosystem: str
    installed_version: str
    proposed_version: str


class RemediationPlan(BaseModel):
    cve_id: str
    status: Literal["ready", "needs_context", "unavailable", "failed"]
    summary: str = Field(max_length=1500)
    root_cause: str = Field(default="", max_length=1500)
    affected_files: list[str] = Field(default_factory=list, max_length=20)
    application_code_changes: list[str] = Field(default_factory=list, max_length=12)
    reasoning: str = Field(default="", max_length=2000)
    confidence: float = Field(default=0, ge=0, le=1)
    human_intervention_required: bool = False
    skills_used: list[str] = Field(max_length=8)
    source_references: list[EvidenceReference] = Field(
        default_factory=list, max_length=20
    )
    advisory_references: list[AdvisoryReference] = Field(
        default_factory=list, max_length=12
    )
    skill_references: list[SkillReference] = Field(
        default_factory=list, max_length=8
    )
    steps: list[PlanStep] = Field(max_length=20)
    version_changes: list[VersionChange] = Field(max_length=12)
    validation: list[ProposedCheck] = Field(max_length=12)
    risks: list[str] = Field(max_length=12)
    missing_context: list[str] = Field(max_length=12)


class DependencyPatch(BaseModel):
    package: str
    ecosystem: str
    from_version: str
    to_version: str
    files: list[str] = Field(default_factory=list, max_length=12)


class PatchResult(BaseModel):
    """Evidence of a sandbox patch attempt; it is not proof of remediation."""

    remediation_id: str
    run_id: str
    cve_id: str
    status: Literal["completed", "needs_context", "failed", "sandbox_error"]
    modified_files: list[str] = Field(default_factory=list, max_length=40)
    dependency_changes: list[DependencyPatch] = Field(
        default_factory=list, max_length=12
    )
    artifact_location: str | None = None
    commands_executed: list[list[str]] = Field(default_factory=list, max_length=40)
    errors: list[str] = Field(default_factory=list, max_length=20)
    unresolved_issues: list[str] = Field(default_factory=list, max_length=20)
    further_testing_required: bool = True
    human_intervention_required: bool = False
    plan_references: list[str] = Field(default_factory=list, max_length=40)


def incomplete_plan(cve_id: str, status: str, message: str) -> RemediationPlan:
    return RemediationPlan(
        cve_id=cve_id,
        status=status,
        summary=message,
        human_intervention_required=True,
        skills_used=[],
        steps=[],
        version_changes=[],
        validation=[],
        risks=[],
        missing_context=[message],
    )
