"""Create scans and retrieve historical results for ingested repositories."""

from collections.abc import AsyncGenerator
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db.database import get_db
from ..db.models import Repository, ScanRun
from ..schemas.vulnerability import ScanRead, ScanRequest
from ..security.osv_client import OSVClient
from ..security.vulnerability_scanner import VulnerabilityScanner
from ..services.scan_service import ScanInputError, scan_read, scan_repository

router = APIRouter()


async def get_scanner() -> AsyncGenerator[VulnerabilityScanner, None]:
    async with OSVClient() as client:
        yield VulnerabilityScanner(client)


@router.post("", response_model=ScanRead, status_code=201)
async def create_scan(
    request: ScanRequest,
    db: Annotated[Session, Depends(get_db)],
    scanner: Annotated[VulnerabilityScanner, Depends(get_scanner)],
) -> ScanRead:
    """Run a scan now; inspect report.status for provider/coverage failures."""
    try:
        run = await scan_repository(db, request, scanner)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail="Repository not found") from exc
    except ScanInputError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return scan_read(run)


@router.get("", response_model=list[ScanRead])
def list_scans(
    db: Annotated[Session, Depends(get_db)],
    repository_id: int | None = None,
    limit: int = 100,
    offset: int = 0,
) -> list[ScanRead]:
    if not 1 <= limit <= 100 or offset < 0:
        raise HTTPException(
            status_code=422,
            detail="limit must be 1..100 and offset must be nonnegative",
        )
    query = select(ScanRun).order_by(ScanRun.id.desc()).limit(limit).offset(offset)
    if repository_id is not None:
        if db.get(Repository, repository_id) is None:
            raise HTTPException(status_code=404, detail="Repository not found")
        query = query.where(ScanRun.repository_id == repository_id)
    return [scan_read(run) for run in db.scalars(query)]


@router.get("/{scan_id}", response_model=ScanRead)
def get_scan(scan_id: int, db: Annotated[Session, Depends(get_db)]) -> ScanRead:
    run = db.get(ScanRun, scan_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan_read(run)
