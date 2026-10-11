"""HTTP endpoints for repository intake and retrieval."""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db.database import get_db
from ..db.models import Repository
from ..schemas.repository import RepositoryCreate, RepositoryRead
from ..services import repository_service

router = APIRouter()


@router.post(
    "",
    response_model=RepositoryRead,
    status_code=status.HTTP_201_CREATED,
)
def submit_repository(
    request: RepositoryCreate,
    db: Session = Depends(get_db),
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


@router.get("", response_model=list[RepositoryRead])
def list_repositories(db: Session = Depends(get_db)) -> list[Repository]:
    """Return all registered repositories."""

    return list(db.scalars(select(Repository).order_by(Repository.id)))


@router.get("/{repository_id}", response_model=RepositoryRead)
def get_repository(repository_id: int, db: Session = Depends(get_db)) -> Repository:
    """Return one registered repository by ID."""

    repository = db.get(Repository, repository_id)
    if repository is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")
    return repository
