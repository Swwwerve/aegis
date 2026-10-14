"""Proposals for human review, without execution results."""

from typing import Literal

from pydantic import BaseModel, Field


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
    skills_used: list[str] = Field(max_length=8)
    steps: list[PlanStep] = Field(max_length=20)
    version_changes: list[VersionChange] = Field(max_length=12)
    validation: list[ProposedCheck] = Field(max_length=12)
    risks: list[str] = Field(max_length=12)
    missing_context: list[str] = Field(max_length=12)


def incomplete_plan(cve_id: str, status: str, message: str) -> RemediationPlan:
    return RemediationPlan(
        cve_id=cve_id,
        status=status,
        summary=message,
        skills_used=[],
        steps=[],
        version_changes=[],
        validation=[],
        risks=[],
        missing_context=[message],
    )
