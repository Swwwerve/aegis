"""HTTP endpoints for repository intake and retrieval."""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db.database import get_db
from ..db.models import Repository
from ..schemas.repository import (
    AnalysisRequest,
    RepositoryAnalysis,
    RepositoryCreate,
    RepositoryRead,
)
from ..services import repository_service

router = APIRouter()


@router.post(
    "",
    response_model=RepositoryRead,
    status_code=status.HTTP_201_CREATED,
)
def submit_repository(
    request: RepositoryCreate,
    db: Annotated[Session, Depends(get_db)],
) -> Repository:
    """Validate, clone, and register a public GitHub repository."""

    try:
        metadata = repository_service.clone_repository(request.url)
    except repository_service.RepositoryIntakeError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        ) from exc

    existing = db.scalar(select(Repository).where(Repository.url == metadata.url))
    if existing is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Repository is already registered.",
        )

    repository = Repository(
        url=metadata.url,
        owner=metadata.owner,
        name=metadata.name,
        default_branch=metadata.default_branch,
        local_path=str(metadata.local_path),
    )
    db.add(repository)
    db.commit()
    db.refresh(repository)
    return repository


@router.post("/{repository_id}/analysis", response_model=RepositoryAnalysis)
async def analyze_registered_repository(
    repository_id: int,
    request: AnalysisRequest,
    db: Annotated[Session, Depends(get_db)],
) -> RepositoryAnalysis:
    """Inspect an existing clone, optionally interpreting README/CI with a model."""
    import asyncio

    from ..analysis.repo_analyzer import analyze_repository, analyze_with_model
    from ..sandbox.policies import validate_repository_path

    repository = db.get(Repository, repository_id)
    if repository is None:
        raise HTTPException(status_code=404, detail="Not found")
    try:
        path = validate_repository_path(repository.local_path)
        report = await asyncio.to_thread(analyze_repository, path)
        if request.resolve_dependencies:
            from ..sandbox.executor import resolve_repository_analysis

            report = await resolve_repository_analysis(path, report)
        if request.use_model:
            report = await analyze_with_model(path, report=report)
        return report
    except (ValueError, OSError) as exc:
        raise HTTPException(
            status_code=422,
            detail="Registered repository clone is unavailable or outside the workspace",
        ) from exc


@router.get("", response_model=list[RepositoryRead])
def list_repositories(db: Annotated[Session, Depends(get_db)]) -> list[Repository]:
    """Return all registered repositories."""

    return list(db.scalars(select(Repository).order_by(Repository.id)))


@router.get("/{repository_id}", response_model=RepositoryRead)
def get_repository(
    repository_id: int, db: Annotated[Session, Depends(get_db)]
) -> Repository:
    """Return one registered repository by ID."""

    repository = db.get(Repository, repository_id)
    if repository is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")
    return repository
