"""Stream focused context investigations for findings in persisted scans."""

import asyncio
import json
from contextlib import suppress
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ..context.context_planner import ContextPlanner, plan_hybrid_context
from ..db.database import get_db
from ..db.models import Repository, ScanRun
from ..sandbox.policies import validate_repository_path
from ..schemas.vulnerability import ScanReport

router = APIRouter()


class ContextInvestigationRequest(BaseModel):
    scan_id: int = Field(gt=0)
    cve_id: str = Field(pattern=r"^CVE-\d{4}-\d{4,}$")
    clarification: str = Field(default="", max_length=4000)


def get_context_engine():
    return plan_hybrid_context


@router.post("/context/stream")
async def investigate_context(
    request: ContextInvestigationRequest,
    db: Annotated[Session, Depends(get_db)],
    engine: Annotated[object, Depends(get_context_engine)],
):
    run = db.get(ScanRun, request.scan_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    if not run.result or run.status in {"queued", "running"}:
        raise HTTPException(
            status_code=409,
            detail="Wait for the scan to finish before investigating context",
        )
    repository = db.get(Repository, run.repository_id)
    if repository is None:
        raise HTTPException(status_code=404, detail="Repository not found")
    try:
        path = validate_repository_path(repository.local_path)
        report = ScanReport.model_validate_json(run.result)
        planner = ContextPlanner(path, request.cve_id, report)
    except (ValueError, OSError) as exc:
        raise HTTPException(
            status_code=422, detail="Saved scan or repository clone is unavailable"
        ) from exc
    if not planner.findings:
        raise HTTPException(
            status_code=422, detail="This CVE is not a finding in the selected scan"
        )

    async def events():
        queue = asyncio.Queue()

        async def progress(event):
            await queue.put(("progress", event))

        async def work():
            try:
                packet = await engine(
                    path,
                    request.cve_id,
                    report,
                    clarification=request.clarification,
                    progress=progress,
                )
                await queue.put(("result", packet.model_dump(mode="json")))
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001 -- provider/clone error bodies can contain private data
                await queue.put(
                    (
                        "error",
                        {
                            "message": "Context investigation could not finish. Retry or inspect the saved scan."
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
