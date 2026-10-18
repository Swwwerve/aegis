"""Context stream validation, clarification, failure sanitization and cancellation."""

import asyncio
import json

from sqlalchemy import func, select
from test_vulnerabilities import api  # noqa: F401 -- shared database and clone fixture

from aegis.backend.api.remediation import (
    ContextInvestigationRequest,
    get_context_engine,
    get_plan_engine,
    investigate_context,
)
from aegis.backend.context.context_planner import ContextPacket
from aegis.backend.db.models import ScanRun
from aegis.backend.main import app
from aegis.backend.schemas.remediation import RemediationPlan

CVE = "CVE-2023-45803"


def save_scan(client):
    return client.post("/scans", json={"repository_id": 1, "use_model": False}).json()[
        "id"
    ]


def frames(response):
    return [
        (frame.splitlines()[0][7:], json.loads(frame.split("data: ", 1)[1]))
        for frame in response.text.strip().split("\n\n")
        if frame.startswith("event:")
    ]


def test_context_stream_delivers_real_progress_and_clarification(api):  # noqa: F811
    client, sessions, clone = api
    scan_id = save_scan(client)
    calls = []

    async def engine(path, cve_id, report, *, progress, clarification):
        calls.append((path, cve_id, clarification))
        await progress(
            {
                "stage": "context_investigation",
                "status": "running",
                "message": "Checking callers",
            }
        )
        return ContextPacket(
            cve_id=cve_id,
            status="partial",
            investigation_status="needs_context",
            missing_context=["Which caller is exposed?"],
            context_requests=[
                {
                    "kind": "operator",
                    "question": "Which caller is exposed?",
                    "reason": "Determines regression scope",
                }
            ],
        )

    app.dependency_overrides[get_context_engine] = lambda: engine
    response = client.post(
        "/api/remediation/context/stream",
        json={
            "scan_id": scan_id,
            "cve_id": CVE,
            "clarification": "Production uses Client",
        },
    )
    assert response.status_code == 200
    events = frames(response)
    assert (
        events[0][0] == "progress"
        and events[1][0] == "result"
        and events[-1][0] == "end"
    )
    assert events[1][1]["context_requests"][0]["question"] == "Which caller is exposed?"
    assert calls == [(clone.resolve(), CVE, "Production uses Client")]
    with sessions() as db:
        assert db.scalar(select(func.count()).select_from(ScanRun)) == 1


def test_context_api_rejects_unknown_or_unavailable_scan_inputs(api):  # noqa: F811
    client, sessions, _ = api
    scan_id = save_scan(client)
    path = "/remediation/context/stream"
    assert client.post(path, json={"scan_id": 999, "cve_id": CVE}).status_code == 404
    assert (
        client.post(
            path, json={"scan_id": scan_id, "cve_id": "CVE-2024-0000"}
        ).status_code
        == 422
    )
    assert (
        client.post(path, json={"scan_id": scan_id, "cve_id": "../secret"}).status_code
        == 422
    )
    assert (
        client.post(
            path, json={"scan_id": scan_id, "cve_id": CVE, "clarification": "a" * 4001}
        ).status_code
        == 422
    )
    with sessions() as db:
        row = db.get(ScanRun, scan_id)
        row.status = "running"
        db.commit()
    assert (
        client.post(path, json={"scan_id": scan_id, "cve_id": CVE}).status_code == 409
    )


def test_context_failure_is_sanitized(api):  # noqa: F811
    client, _, _ = api
    scan_id = save_scan(client)

    async def broken(*args, **kwargs):
        raise RuntimeError("secret provider body")

    app.dependency_overrides[get_context_engine] = lambda: broken
    response = client.post(
        "/remediation/context/stream", json={"scan_id": scan_id, "cve_id": CVE}
    )
    assert [kind for kind, _ in frames(response)] == ["error", "end"]
    assert "secret provider body" not in response.text


def test_patch_endpoint_rejects_plan_context_cve_mismatch(api):  # noqa: F811
    client, _, _ = api
    scan_id = save_scan(client)
    plan = RemediationPlan(
        cve_id=CVE,
        status="needs_context",
        summary="Incomplete plan",
        skills_used=[],
        steps=[],
        version_changes=[],
        validation=[],
        risks=[],
        missing_context=["Missing evidence"],
    ).model_dump(mode="json")
    context = ContextPacket(
        cve_id="CVE-2024-0001",
        status="partial",
        investigation_status="needs_context",
    ).model_dump(mode="json")
    response = client.post(
        "/api/remediation/patch/stream",
        json={
            "scan_id": scan_id,
            "cve_id": CVE,
            "plan": plan,
            "context": context,
        },
    )
    assert response.status_code == 422
    assert "do not match" in response.json()["detail"]


def test_patch_demo_status_is_explicitly_labeled(api):
    client, _, _ = api
    response = client.get("/api/remediation/demo/status")
    assert response.status_code == 200
    assert response.json()["label"] == "Sandbox demonstration; disposable fixture only"


def test_disconnect_cancels_context_investigation(api):  # noqa: F811
    client, sessions, _ = api
    scan_id = save_scan(client)

    async def exercise():
        cancelled = asyncio.Event()

        async def engine(*args, progress, **kwargs):
            await progress(
                {
                    "stage": "context_investigation",
                    "status": "running",
                    "message": "Started",
                }
            )
            try:
                await asyncio.Future()
            finally:
                cancelled.set()

        with sessions() as db:
            response = await investigate_context(
                ContextInvestigationRequest(scan_id=scan_id, cve_id=CVE), db, engine
            )
            first = await anext(response.body_iterator)
            assert "Started" in first
            await response.body_iterator.aclose()
            assert cancelled.is_set()

    asyncio.run(exercise())


def test_plan_endpoint_streams_proposals_without_changing_source_or_history(api):  # noqa: F811
    from aegis.backend.schemas.remediation import incomplete_plan

    client, sessions, clone = api
    scan_id = save_scan(client)
    before = {
        p.relative_to(clone).as_posix(): p.read_bytes()
        for p in clone.rglob("*")
        if p.is_file()
    }

    async def engine(path, cve_id, report, *, progress, clarification):
        await progress(
            {
                "stage": "remediation_skills",
                "status": "running",
                "message": "Selecting the required planning skill",
            }
        )
        return incomplete_plan(
            cve_id,
            "needs_context",
            "Additional caller evidence is required for the proposal",
        )

    app.dependency_overrides[get_plan_engine] = lambda: engine
    response = client.post(
        "/api/remediation/plan/stream", json={"scan_id": scan_id, "cve_id": CVE}
    )
    assert response.status_code == 200
    assert frames(response)[1][1]["status"] == "needs_context"
    assert before == {
        p.relative_to(clone).as_posix(): p.read_bytes()
        for p in clone.rglob("*")
        if p.is_file()
    }
    with sessions() as db:
        assert db.scalar(select(func.count()).select_from(ScanRun)) == 1
