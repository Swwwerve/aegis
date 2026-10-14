"""Schemas for repository intake and retrieval."""

from datetime import datetime
from pathlib import PurePosixPath
from typing import Literal

from pydantic import AnyHttpUrl, BaseModel, ConfigDict, Field, field_validator


class RepositoryCreate(BaseModel):
    """Request body for registering a public GitHub repository."""

    url: AnyHttpUrl = Field(description="Public GitHub repository URL")


class RepositoryRead(BaseModel):
    """Repository metadata returned by the API."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    url: AnyHttpUrl
    owner: str
    name: str
    default_branch: str | None = None
    local_path: str
    created_at: datetime


class Dependency(BaseModel):
    name: str
    version: str | None = None
    ecosystem: Literal["Python", "Node", "Java"]
    scope: str = "runtime"
    manifest: str
    marker: str | None = None
    resolved: bool = False


class CommandPlan(BaseModel):
    """A proposal, never proof that a build or test succeeds."""

    kind: Literal["install", "build", "test", "lint", "typecheck"]
    argv: list[str] = Field(min_length=1, max_length=64)
    cwd: str = "."
    source: str
    confidence: Literal["high", "medium", "low"] = "medium"
    requires_network: bool = False
    origin: Literal["declared", "inferred", "model"] = "inferred"
    reason: str = ""

    @field_validator("cwd")
    @classmethod
    def confined_directory(cls, value: str) -> str:
        path = PurePosixPath(value)
        if (
            path.is_absolute()
            or ".." in path.parts
            or "\\" in value
            or ":" in value
            or "\x00" in value
        ):
            raise ValueError("cwd must be a relative repository directory")
        return str(path)

    @field_validator("argv")
    @classmethod
    def valid_arguments(cls, value: list[str]) -> list[str]:
        if any(not item or "\x00" in item or len(item) > 4096 for item in value):
            raise ValueError("Command arguments must be nonempty, bounded strings")
        return value


class ProjectAnalysis(BaseModel):
    root: str
    languages: list[str] = Field(default_factory=list)
    manifests: list[str] = Field(default_factory=list)
    lockfiles: list[str] = Field(default_factory=list)
    package_managers: list[str] = Field(default_factory=list)
    runtime_constraints: dict[str, str] = Field(default_factory=dict)
    dependencies: list[Dependency] = Field(default_factory=list)
    commands: list[CommandPlan] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    resolutions: list["DependencyResolution"] = Field(default_factory=list)


class ImportantDirectory(BaseModel):
    path: str
    role: str
    evidence: str


class RepositoryAnalysis(BaseModel):
    schema_version: int = 1
    languages: dict[str, int] = Field(
        default_factory=dict, description="Source file counts, not byte percentages"
    )
    primary_language: str | None = None
    projects: list[ProjectAnalysis] = Field(default_factory=list)
    important_directories: list[ImportantDirectory] = Field(default_factory=list)
    ci_files: list[str] = Field(default_factory=list)
    documentation: list[str] = Field(default_factory=list)
    container_files: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    files_examined: int = 0
    truncated: bool = False
    inference_status: Literal["not_requested", "completed", "unavailable", "failed"] = (
        "not_requested"
    )
    summary: str | None = None
    resolution_status: Literal[
        "not_requested", "completed", "partial", "unavailable"
    ] = "not_requested"


class AnalysisRequest(BaseModel):
    use_model: bool = True
    resolve_dependencies: bool = False


class ModelInsight(BaseModel):
    """Bounded model interpretation; dependency inventory stays manifest-backed."""

    summary: str = Field(max_length=8000)
    commands: list[CommandPlan] = Field(default_factory=list, max_length=30)
    warnings: list[str] = Field(default_factory=list, max_length=30)


class ExecutionResult(BaseModel):
    command: CommandPlan
    status: Literal["passed", "failed", "skipped", "timeout", "error"]
    exit_code: int | None = None
    stdout: str = ""
    stderr: str = ""
    reason: str = ""


class DependencyEdge(BaseModel):
    parent: str
    child: str
    scope: str = "runtime"


class DependencyResolution(BaseModel):
    ecosystem: Literal["Python", "Node", "Java"]
    method: str
    status: Literal["completed", "partial", "unavailable", "failed", "timeout"]
    dependencies: list[Dependency] = Field(default_factory=list)
    edges: list[DependencyEdge] = Field(default_factory=list)
    diagnostics: list[str] = Field(default_factory=list)
