"""Actual stage streaming, saved inventory and cancellation semantics."""

import asyncio
import json

import pytest
from sqlalchemy import event, select
from test_prioritization import FakeEPSS, FakeKEV
from test_vulnerabilities import FakeOSV, advisory, api  # noqa: F401 -- shared fixture

from aegis.backend.api.scans import get_scanner
from aegis.backend.db.models import ScanRun
from aegis.backend.db.models import VulnerabilityFinding as FindingRow
from aegis.backend.main import app
from aegis.backend.schemas.vulnerability import (
    ScanReport,
    ScanRequest,
    VulnerabilityFinding,
)
from aegis.backend.security.advisory_client import AdvisoryClient
from aegis.backend.security.osv_client import OSVResult
from aegis.backend.security.vulnerability_scanner import VulnerabilityScanner
from aegis.backend.services.scan_service import scan_repository


def frames(response):
    return [
        (frame.splitlines()[0][7:], json.loads(frame.split("data: ", 1)[1]))
        for frame in response.text.strip().split("\n\n")
        if frame.startswith("event:")
    ]


def test_stream_stages_preserve_inventory_and_saved_result(api):  # noqa: F811
    client, _, clone = api
    (clone / "app.py").write_text("import urllib3\nurllib3.request()")

    async def scanner():
        yield VulnerabilityScanner(
            FakeOSV([OSVResult([advisory()])]),
            advisory_client=AdvisoryClient(FakeEPSS(), FakeKEV()),
        )

    app.dependency_overrides[get_scanner] = scanner
    response = client.post(
        "/scans/stream", json={"repository_id": 1, "use_model": False}
    )
    assert response.status_code == 200 and response.headers["content-type"].startswith(
        "text/event-stream"
    )
    events = frames(response)
    progress = [data for event, data in events if event == "progress"]
    assert [x["stage"] for x in progress if x["status"] == "running"] == [
        "inventory",
        "advisories",
        "enrichment",
        "usage",
        "ranking",
        "saving",
    ]
    assert {x["stage"] for x in progress if x["status"] == "skipped"} == {
        "resolution",
        "interpretation",
    }
    inventory = next(x["analysis"] for x in progress if "analysis" in x)
    assert inventory["primary_language"] == "Python"
    result = next(data for event, data in events if event == "result")
    assert result["report"]["repository_analysis"]["primary_language"] == "Python"
    assert client.get(f"/scans/{result['id']}").json() == result
    assert events[-1] == ("end", {})


def test_stream_failure_is_saved_and_sanitized(api, monkeypatch):  # noqa: F811
    client, sessions, _ = api
    from aegis.backend.services import scan_service

    def broken(path):
        raise RuntimeError("private provider text")

    monkeypatch.setattr(scan_service, "analyze_repository", broken)
    response = client.post(
        "/scans/stream", json={"repository_id": 1, "use_model": False}
    )
    result = next(data for event, data in frames(response) if event == "result")
    assert result["status"] == "failed" and "private provider text" not in response.text
    with sessions() as db:
        assert db.get(ScanRun, result["id"]).status == "failed"
    assert client.post("/scans/stream", json={"repository_id": 999}).status_code == 404


@pytest.mark.parametrize("duplicate", [False, True])
def test_findings_save_in_bulk_and_roll_back_atomically(api, duplicate):  # noqa: F811
    client, sessions, _ = api
    findings = [
        VulnerabilityFinding(
            package="urllib3",
            installed_version="1.26.4",
            ecosystem="PyPI",
            advisory_id=f"GHSA-{i}",
            version_source="pinned",
            cve=f"CVE-2024-{1000 + i}" if i % 2 else None,
            fixed_version="2.0.0" if i % 2 else None,
        )
        for i in range(300)
    ]
    if duplicate:
        findings.append(findings[0])

    class Scanner:
        async def scan(self, *args, **kwargs):
            return ScanReport(vulnerabilities=findings)

    async def scanner():
        yield Scanner()

    app.dependency_overrides[get_scanner] = scanner
    inserts = []
    engine = sessions.kw["bind"]

    def record_insert(conn, cursor, statement, parameters, context, executemany):
        if statement.startswith("INSERT INTO vulnerability_findings"):
            inserts.append((executemany, len(parameters)))

    event.listen(engine, "before_cursor_execute", record_insert)
    try:
        response = client.post(
            "/scans/stream", json={"repository_id": 1, "use_model": False}
        )
    finally:
        event.remove(engine, "before_cursor_execute", record_insert)
    result = next(data for kind, data in frames(response) if kind == "result")
    assert inserts == [(True, len(findings))]
    with sessions() as db:
        rows = list(db.scalars(select(FindingRow)))
        if duplicate:
            assert result["status"] == "failed"
            assert rows == []
            assert db.get(ScanRun, result["id"]).status == "failed"
        else:
            assert result["status"] == "completed"
            assert len(rows) == 300
            assert [json.loads(row.data) for row in rows] == result["report"][
                "vulnerabilities"
            ]
            assert client.get(f"/scans/{result['id']}").json() == result


def test_cancelled_stage_persists_failed_run(api):  # noqa: F811
    _, sessions, _ = api

    async def run():
        started = asyncio.Event()

        async def progress(event):
            started.set()
            await asyncio.Future()

        with sessions() as db:
            task = asyncio.create_task(
                scan_repository(
                    db,
                    ScanRequest(repository_id=1, use_model=False),
                    VulnerabilityScanner(FakeOSV([])),
                    progress=progress,
                )
            )
            await started.wait()
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
            row = db.scalar(select(ScanRun))
            assert row.status == "failed" and json.loads(row.result)["errors"] == [
                "Scan cancelled"
            ]

    asyncio.run(run())


def test_same_origin_api_aliases(api):  # noqa: F811
    client, _, _ = api
    assert client.get("/api/repositories").json() == client.get("/repositories").json()
    response = client.post(
        "/api/scans/stream", json={"repository_id": 1, "use_model": False}
    )
    result = next(data for event, data in frames(response) if event == "result")
    assert client.get(f"/api/scans/{result['id']}").json() == result


def test_frontend_serving_and_unbuilt_fallback(api, monkeypatch, tmp_path):  # noqa: F811
    from importlib import import_module

    main = import_module("aegis.backend.main")
    client, _, _ = api
    monkeypatch.setattr(main, "FRONTEND_DIST", tmp_path)
    assert "Build the frontend" in client.get("/").json()["message"]
    (tmp_path / "index.html").write_text("<!doctype html><title>Aegis</title>")
    response = client.get("/")
    assert (
        response.status_code == 200 and "text/html" in response.headers["content-type"]
    )
    assert "<title>Aegis</title>" in response.text
