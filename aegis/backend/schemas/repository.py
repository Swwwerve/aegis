




"""Schemas for repository intake and retrieval."""

from datetime import datetime

from pydantic import AnyHttpUrl, BaseModel, ConfigDict, Field


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
