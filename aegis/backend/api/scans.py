"""Create scans and retrieve historical results for ingested repositories."""

import asyncio
import json
from collections.abc import AsyncGenerator
from contextlib import suppress
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db.database import get_db
from ..db.models import Repository, ScanRun
from ..schemas.vulnerability import ScanRead, ScanRequest
from ..security.advisory_client import AdvisoryClient
from ..security.epss_client import EPSSClient
from ..security.kev_client import KEVClient
from ..security.osv_client import OSVClient
from ..security.vulnerability_scanner import VulnerabilityScanner
from ..services.scan_service import ScanInputError, scan_read, scan_repository

router = APIRouter()


async def get_scanner() -> AsyncGenerator[VulnerabilityScanner, None]:
    async with OSVClient() as client, EPSSClient() as epss, KEVClient() as kev:
        yield VulnerabilityScanner(client, advisory_client=AdvisoryClient(epss, kev))


@router.post("/stream")
async def stream_scan(
    request: ScanRequest,
    db: Annotated[Session, Depends(get_db)],
    scanner: Annotated[VulnerabilityScanner, Depends(get_scanner)],
):
    """Stream actual stage events, then the persisted ScanRead. Disconnect cancels work."""
    if db.get(Repository, request.repository_id) is None:
        raise HTTPException(status_code=404, detail="Repository not found")

    async def events():
        queue: asyncio.Queue = asyncio.Queue()

        async def progress(data):
            await queue.put(("progress", data))

        async def work():
            try:
                run = await scan_repository(db, request, scanner, progress=progress)
                await queue.put(("result", scan_read(run).model_dump(mode="json")))
            except (LookupError, ScanInputError) as exc:
                await queue.put(("error", {"message": str(exc)}))
            except Exception:  # noqa: BLE001 -- do not expose private provider/DB errors
                await queue.put(
                    (
                        "error",
                        {
                            "message": "Scan could not finish. Check scan history before retrying."
                        },
                    )
                )
            finally:
                await queue.put(("end", {}))

        task = asyncio.create_task(work())
        try:
            while True:
                try:
                    event, data = await asyncio.wait_for(queue.get(), timeout=10)
                except TimeoutError:
                    yield ": keep-alive\n\n"
                    continue
                yield f"event: {event}\ndata: {json.dumps(data)}\n\n"
                if event == "end":
                    break
        finally:
            if not task.done():
                task.cancel()
            with suppress(asyncio.CancelledError):
                await task

    return StreamingResponse(
        events(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


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
