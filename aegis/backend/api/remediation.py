"""Stream focused context investigations for findings in persisted scans."""

import asyncio
import json
import shutil
import tempfile
from contextlib import suppress
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ..context.context_planner import ContextPacket, ContextPlanner, plan_hybrid_context
from ..core.config import settings
from ..core.progress import emit
from ..db.database import get_db
from ..db.models import Repository, ScanRun
from ..sandbox.docker_runner import create_sandbox
from ..sandbox.policies import validate_repository_path
from ..schemas.remediation import RemediationPlan
from ..schemas.vulnerability import ScanReport
from ..services.patch_demo import (
    DemoPatchModel,
    create_demo_repository,
    demo_packet,
    demo_plan,
)
from ..services.patch_service import patch_remediation
from ..services.remediation_service import plan_repository_remediation

router = APIRouter()


class ContextInvestigationRequest(BaseModel):
    scan_id: int = Field(gt=0)
    cve_id: str = Field(pattern=r"^CVE-\d{4}-\d{4,}$")
    clarification: str = Field(default="", max_length=4000)


class PatchRequest(BaseModel):
    scan_id: int = Field(gt=0)
    cve_id: str = Field(pattern=r"^CVE-\d{4}-\d{4,}$")
    plan: RemediationPlan
    context: ContextPacket
    model: str = Field(default="gpt-5.4", max_length=100)


def get_context_engine():
    return plan_hybrid_context


@router.post("/context/stream")
async def investigate_context(
    request: ContextInvestigationRequest,
    db: Annotated[Session, Depends(get_db)],
    engine: Annotated[object, Depends(get_context_engine)],
):
    return await _stream_operation(request, db, engine, "Context investigation")


def get_plan_engine():
    return plan_repository_remediation


@router.post("/plan/stream")
async def create_remediation_plan(
    request: ContextInvestigationRequest,
    db: Annotated[Session, Depends(get_db)],
    engine: Annotated[object, Depends(get_plan_engine)],
):
    return await _stream_operation(request, db, engine, "Remediation planning")


@router.post("/patch/stream")
async def execute_patch(
    request: PatchRequest,
    db: Annotated[Session, Depends(get_db)],
):
    run = db.get(ScanRun, request.scan_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    if request.plan.cve_id != request.cve_id or request.context.cve_id != request.cve_id:
        raise HTTPException(status_code=422, detail="Plan and context do not match the requested CVE")
    repository = db.get(Repository, run.repository_id)
    if repository is None:
        raise HTTPException(status_code=404, detail="Repository not found")
    try:
        path = validate_repository_path(repository.local_path)
    except (ValueError, OSError) as exc:
        raise HTTPException(status_code=422, detail="Saved repository clone is unavailable") from exc

    async def events():
        queue = asyncio.Queue()

        async def progress(event):
            await queue.put(("progress", event))

        async def work():
            try:
                async with await create_sandbox(path, workspace_root=settings.workspace_root) as workspace:
                    result = await patch_remediation(
                        workspace,
                        request.plan,
                        request.context,
                        model=request.model,
                        progress=progress,
                    )
                    await queue.put(("result", result.model_dump(mode="json")))
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001 -- redact sandbox/provider errors at the API boundary
                await queue.put(("error", {"message": "Sandbox patch execution could not finish"}))
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


@router.get("/demo/status")
async def patch_demo_status():
    return {
        "enabled": settings.enable_patch_demo,
        "label": "Sandbox demonstration; disposable fixture only",
    }


@router.post("/demo/patch/stream")
async def execute_patch_demo():
    if not settings.enable_patch_demo:
        raise HTTPException(status_code=404, detail="Patch sandbox demonstration is disabled")

    async def events():
        queue = asyncio.Queue()
        settings.workspace_root.mkdir(parents=True, exist_ok=True)
        # The sandbox policy requires the repository itself to be a direct
        # child of the configured workspace root.
        fixture = Path(
            tempfile.mkdtemp(prefix="aegis-patch-demo-", dir=settings.workspace_root)
        )

        async def progress(event):
            await queue.put(("progress", event))

        async def work():
            try:
                await emit(
                    progress,
                    "patch_demo",
                    "running",
                    "Creating a disposable committed repository fixture.",
                    demonstration=True,
                )
                await asyncio.to_thread(create_demo_repository, fixture)
                plan = demo_plan()
                packet = demo_packet()
                async with await create_sandbox(
                    fixture, workspace_root=settings.workspace_root
                ) as workspace:
                    result = await patch_remediation(
                        workspace,
                        plan,
                        packet,
                        model=DemoPatchModel(),
                        progress=progress,
                        demonstration=True,
                    )
                    await queue.put(("result", result.model_dump(mode="json")))
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001 -- redact fixture/sandbox details at API boundary
                await queue.put(
                    ("error", {"message": "Sandbox demonstration could not finish"})
                )
            finally:
                shutil.rmtree(fixture, ignore_errors=True)
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


async def _stream_operation(request, db, engine, label):
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
                            "message": f"{label} could not finish. Retry or inspect the saved scan."
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
