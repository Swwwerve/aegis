"""Step 4: provider behavior, version evidence, normalization and API persistence."""

import asyncio
import json
from itertools import permutations

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from aegis.backend.api.scans import get_scanner
from aegis.backend.db.database import Base, get_db
from aegis.backend.db.models import Repository, ScanRun
from aegis.backend.db.models import VulnerabilityFinding as FindingRow
from aegis.backend.main import app
from aegis.backend.schemas.repository import (
    Dependency,
    ProjectAnalysis,
    RepositoryAnalysis,
)
from aegis.backend.schemas.vulnerability import ScanDependency
from aegis.backend.security.osv_client import OSVClient, OSVResult
from aegis.backend.security.vulnerability_scanner import (
    VulnerabilityScanner,
    collect_dependencies,
    normalize_findings,
)


def dependency(
    name="urllib3",
    version="1.26.4",
    ecosystem="Python",
    manifest="requirements.txt",
    resolved=True,
    scope="runtime",
):
    return Dependency(
        name=name,
        version=version,
        ecosystem=ecosystem,
        manifest=manifest,
        resolved=resolved,
        scope=scope,
    )


def inventory(*dependencies):
    return RepositoryAnalysis(
        projects=[ProjectAnalysis(root=".", dependencies=list(dependencies))]
    )


def scanned(name="urllib3", version="1.26.4", ecosystem="PyPI"):
    return ScanDependency(
        package=name,
        installed_version=version,
        ecosystem=ecosystem,
        version_source="resolved",
        manifests=["requirements.txt"],
        scopes=["runtime"],
    )


def advisory(
    identifier="GHSA-example-1",
    *,
    name="urllib3",
    ecosystem="PyPI",
    aliases=None,
    fixed="1.26.18",
):
    events = [{"introduced": "0"}]
    if fixed:
        events.append({"fixed": fixed})
    return {
        "id": identifier,
        "aliases": aliases or ["CVE-2023-45803"],
        "summary": "Example advisory",
        "affected": [
            {
                "package": {"name": name, "ecosystem": ecosystem},
                "ranges": [{"type": "ECOSYSTEM", "events": events}],
            }
        ],
        "references": [{"type": "ADVISORY", "url": "https://example.org/advisory"}],
    }


def test_collect_versions_and_project_provenance():
    report = inventory(
        dependency(name="URL_lib3", version="==1.26.4", resolved=False),
        dependency(name="url-lib3", manifest="poetry.lock"),
        dependency(name="url-lib3", version=">=1.20", resolved=False),
        dependency(name="requests", version=">=2", resolved=False),
        dependency(
            name="policy-only", version="==1", resolved=False, scope="constraint"
        ),
        dependency(
            name="alias",
            version="npm:lodash@4.17.15",
            ecosystem="Node",
            resolved=False,
            manifest="package.json",
        ),
    )
    queries, skipped = collect_dependencies(report)
    assert {(q.package, q.installed_version) for q in queries} == {
        ("url-lib3", "1.26.4"),
        ("lodash", "4.17.15"),
    }
    item = next(q for q in queries if q.package == "url-lib3")
    assert item.version_source == "resolved" and item.manifests == [
        "poetry.lock",
        "requirements.txt",
    ]
    assert [d.package for d in skipped] == ["requests"]


def test_no_cross_project_range_guessing():
    report = RepositoryAnalysis(
        projects=[
            ProjectAnalysis(root="a", dependencies=[dependency()]),
            ProjectAnalysis(
                root="b", dependencies=[dependency(version=">=1.0", resolved=False)]
            ),
        ]
    )
    _, skipped = collect_dependencies(report)
    assert len(skipped) == 1


@pytest.mark.parametrize(
    "version,ecosystem",
    [
        ("^4.0.0", "Node"),
        ("1", "Node"),
        ("file:../local", "Node"),
        (">=1.2", "Python"),
        ("==1.*", "Python"),
        ("https://example.org/package", "Python"),
        ("[1.0,2.0)", "Java"),
        ("${version}", "Java"),
        ("1.+", "Java"),
    ],
)
def test_unresolved_versions_are_not_invented(version, ecosystem):
    name = "org.example:library" if ecosystem == "Java" else "library"
    queries, skipped = collect_dependencies(
        inventory(
            dependency(name=name, version=version, ecosystem=ecosystem, resolved=False)
        )
    )
    assert not queries and len(skipped) == 1


def test_alias_dedup_is_transitive_and_order_independent():
    records = [
        advisory("GHSA-a", aliases=["CVE-2023-45803"]),
        advisory("PYSEC-b", aliases=["GHSA-a"]),
        advisory("OSV-c", aliases=["PYSEC-b"]),
    ]
    for order in permutations(records):
        findings, withdrawn, warnings = normalize_findings(scanned(), list(order))
        assert len(findings) == 1 and not warnings and withdrawn == 0
        assert findings[0].advisory_ids == ["GHSA-a", "OSV-c", "PYSEC-b"]
        assert (
            findings[0].cve == "CVE-2023-45803"
            and findings[0].fixed_version == "1.26.18"
        )


def test_conflicting_alias_fixes_choose_release_safe_for_all_records():
    records = [
        advisory("GHSA-a", fixed="1.26.18"),
        advisory("PYSEC-b", fixed="1.26.17"),
    ]
    findings, _, _ = normalize_findings(scanned(), records)
    assert findings[0].fixed_version == "1.26.18"
    assert findings[0].fixed_versions == ["1.26.17", "1.26.18"]


def test_git_metadata_does_not_hide_an_explicit_release_fix():
    record = advisory("PYSEC-a")
    record["affected"][0]["ranges"].append(
        {
            "type": "GIT",
            "repo": "https://example.org/repo",
            "events": [{"introduced": "0"}, {"fixed": "a" * 40}],
        }
    )
    finding = normalize_findings(scanned(), [record, advisory("GHSA-b")])[0][0]
    assert finding.fixed_version == "1.26.18"
    assert "a" * 40 not in finding.fixed_versions


def test_branch_aware_fix_no_lexical_version_sort():
    record = advisory(fixed=None)
    record["affected"][0]["ranges"][0]["events"] = [
        {"introduced": "0"},
        {"fixed": "1.26.18"},
        {"introduced": "2.0.0"},
        {"fixed": "2.0.7"},
        {"introduced": "2.1.0"},
        {"fixed": "2.1.1"},
    ]
    assert (
        normalize_findings(scanned(version="1.26.4"), [record])[0][0].fixed_version
        == "1.26.18"
    )
    assert (
        normalize_findings(scanned(version="2.0.4"), [record])[0][0].fixed_version
        == "2.0.7"
    )
    node = advisory(name="example", ecosystem="npm", fixed="2.10.0")
    assert (
        normalize_findings(scanned("example", "2.9.0", "npm"), [node])[0][
            0
        ].fixed_version
        == "2.10.0"
    )


def test_no_fake_cve_fix_or_commit_version():
    record = advisory(aliases=[], fixed=None)
    record["aliases"] = []
    record["affected"][0]["ranges"].append(
        {"type": "GIT", "events": [{"introduced": "abc"}, {"fixed": "def"}]}
    )
    finding = normalize_findings(scanned(), [record])[0][0]
    assert (
        finding.cve is None
        and finding.fixed_version is None
        and not finding.fixed_versions
    )


def test_withdrawal_and_package_scoping():
    withdrawn = advisory("WITHDRAWN")
    withdrawn["withdrawn"] = "2025-01-01T00:00:00Z"
    wrong = advisory("OTHER-PACKAGE", name="requests")
    findings, count, warnings = normalize_findings(
        scanned(), [withdrawn, wrong, advisory()]
    )
    assert len(findings) == 1 and count == 1 and warnings


def test_last_affected_is_not_a_fix_and_java_qualifiers_are_not_guessed():
    record = advisory(fixed=None)
    record["affected"][0]["ranges"][0]["events"] = [
        {"introduced": "0"},
        {"last_affected": "1.26.5"},
    ]
    assert normalize_findings(scanned(), [record])[0][0].fixed_version is None
    java = advisory(name="org.example:library", ecosystem="Maven", fixed="2.0.Final")
    assert (
        normalize_findings(
            scanned("org.example:library", "1.0.Final", "Maven"), [java]
        )[0][0].fixed_version
        is None
    )


def test_client_paginates_each_package_and_hydrates_once():
    calls = []

    def respond(request):
        calls.append(request)
        if request.url.path.endswith("/querybatch"):
            payload = json.loads(request.content)
            if len(payload["queries"]) == 2:
                return httpx.Response(
                    200,
                    json={
                        "results": [
                            {"vulns": [{"id": "GHSA-a"}], "next_page_token": "next"},
                            {"vulns": [{"id": "GHSA-a"}]},
                        ]
                    },
                )
            assert payload["queries"][0]["page_token"] == "next"
            return httpx.Response(
                200, json={"results": [{"vulns": [{"id": "PYSEC-b"}]}]}
            )
        return httpx.Response(200, json=advisory(request.url.path.rsplit("/", 1)[-1]))

    async def exercise():
        async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as http:
            results = await OSVClient(http).query_packages(
                [scanned(), scanned(version="1.26.5")]
            )
            assert [len(result.records) for result in results] == [2, 1]
            assert all(result.complete for result in results)

    asyncio.run(exercise())
    assert len(calls) == 4
    assert all(request.url.host == "api.osv.dev" for request in calls)


@pytest.mark.parametrize("first_status", [429, 503])
def test_client_retries_transient_provider_errors(first_status):
    count = 0

    def respond(request):
        nonlocal count
        count += 1
        return (
            httpx.Response(first_status, headers={"Retry-After": "0"})
            if count == 1
            else httpx.Response(200, json={"results": [{}]})
        )

    async def exercise():
        async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as http:
            result = await OSVClient(http, backoff=0).query_packages([scanned()])
            assert result[0].complete

    asyncio.run(exercise())
    assert count == 2


@pytest.mark.parametrize(
    "payload",
    [
        {"results": []},
        {"results": [{"vulns": [{"id": "../escape"}]}]},
        {"results": [{"vulns": "wrong"}]},
    ],
)
def test_malformed_provider_results_are_not_clean(payload):
    async def exercise():
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(
                lambda request: httpx.Response(200, json=payload)
            )
        ) as http:
            result = await OSVClient(http, retries=0).query_packages([scanned()])
            assert not result[0].complete and result[0].errors

    asyncio.run(exercise())


def test_repeated_pagination_token_is_an_error():
    async def exercise():
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(
                lambda request: httpx.Response(
                    200, json={"results": [{"next_page_token": "same"}]}
                )
            )
        ) as http:
            result = await OSVClient(http).query_packages([scanned()])
            assert not result[0].complete and "pagination" in result[0].errors[0]

    asyncio.run(exercise())


def test_advisory_failure_retains_other_findings():
    def respond(request):
        if request.url.path.endswith("querybatch"):
            return httpx.Response(
                200,
                json={
                    "results": [{"vulns": [{"id": "GHSA-good"}, {"id": "GHSA-bad"}]}]
                },
            )
        return (
            httpx.Response(404)
            if request.url.path.endswith("GHSA-bad")
            else httpx.Response(200, json=advisory("GHSA-good"))
        )

    async def exercise():
        async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as http:
            result = await VulnerabilityScanner(OSVClient(http, retries=0)).scan(
                inventory(dependency())
            )
            assert (
                result.status == "partial"
                and result.errors
                and len(result.vulnerabilities) == 1
            )

    asyncio.run(exercise())


def test_response_size_limit():
    async def exercise():
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(
                lambda request: httpx.Response(200, content=b"x" * 100)
            )
        ) as http:
            result = await OSVClient(http, max_response_bytes=10).query_packages(
                [scanned()]
            )
            assert not result[0].complete and "size limit" in result[0].errors[0]

    asyncio.run(exercise())


def test_advisory_budget_keeps_partial_data_without_overfetching():
    calls = []

    def respond(request):
        calls.append(request.url.path)
        if request.url.path.endswith("querybatch"):
            return httpx.Response(
                200, json={"results": [{"vulns": [{"id": "GHSA-a"}, {"id": "GHSA-b"}]}]}
            )
        return httpx.Response(200, json=advisory("GHSA-a"))

    async def exercise():
        async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as http:
            result = await OSVClient(http, max_records=1).query_packages([scanned()])
            assert not result[0].complete and len(result[0].records) == 1

    asyncio.run(exercise())
    assert calls == ["/v1/querybatch", "/v1/vulns/GHSA-a"]


def test_invalid_json_and_transport_errors_are_reported():
    async def exercise():
        def broken(request):
            raise httpx.ConnectError("private transport body", request=request)

        for responder in (
            broken,
            lambda request: httpx.Response(200, content=b"not json"),
        ):
            async with httpx.AsyncClient(
                transport=httpx.MockTransport(responder)
            ) as http:
                results = await OSVClient(http, retries=0).query_packages([scanned()])
                assert results[0].errors and "private transport body" not in str(
                    results[0].errors
                )

    asyncio.run(exercise())


def test_scanner_deadline_is_a_failed_report():
    class Slow:
        async def query_packages(self, dependencies):
            await asyncio.sleep(0.02)

    report = asyncio.run(
        VulnerabilityScanner(Slow(), timeout_seconds=0.001).scan(
            inventory(dependency())
        )
    )
    assert report.status == "failed" and "deadline" in report.errors[0]


def test_malformed_advisory_retains_valid_findings():
    broken = advisory("BROKEN")
    broken["affected"][0]["ranges"] = "wrong"
    report = asyncio.run(
        VulnerabilityScanner(FakeOSV([OSVResult([broken, advisory()])])).scan(
            inventory(dependency())
        )
    )
    assert (
        report.status == "partial"
        and report.errors
        and len(report.vulnerabilities) == 1
    )
    assert report.packages_completed == 0


def test_stale_lock_does_not_cover_incompatible_requirement():
    _, skipped = collect_dependencies(
        inventory(dependency(version="1.0"), dependency(version=">=2", resolved=False))
    )
    assert len(skipped) == 1


def test_related_advisories_are_not_deduplicated():
    a = advisory("GHSA-a", aliases=["CVE-2025-10001"])
    b = advisory("GHSA-b", aliases=["CVE-2025-10002"])
    a["related"] = ["GHSA-b"]
    assert len(normalize_findings(scanned(), [a, b])[0]) == 2


def test_infinite_limit_does_not_hide_release_fix():
    record = advisory()
    record["affected"][0]["ranges"][0]["events"].append({"limit": "*"})
    assert normalize_findings(scanned(), [record])[0][0].fixed_version == "1.26.18"


class FakeOSV:
    def __init__(self, results):
        self.results = results

    async def query_packages(self, dependencies):
        return self.results


def test_two_versions_keep_distinct_findings_and_missing_ranges_are_partial():
    result = asyncio.run(
        VulnerabilityScanner(
            FakeOSV([OSVResult([advisory()]), OSVResult([advisory()])])
        ).scan(
            inventory(
                dependency(),
                dependency(version="1.26.5"),
                dependency(name="unknown", version=">=1", resolved=False),
            )
        )
    )
    assert result.status == "partial" and len(result.vulnerabilities) == 2
    assert {finding.installed_version for finding in result.vulnerabilities} == {
        "1.26.4",
        "1.26.5",
    }


def test_empty_inventory_is_not_clean():
    result = asyncio.run(VulnerabilityScanner(FakeOSV([])).scan(inventory()))
    assert (
        result.status == "partial" and result.warnings and result.packages_queried == 0
    )


def test_no_findings_with_complete_queries_is_completed():
    result = asyncio.run(
        VulnerabilityScanner(FakeOSV([OSVResult()])).scan(inventory(dependency()))
    )
    assert (
        result.status == "completed"
        and not result.vulnerabilities
        and result.packages_completed == 1
    )


@pytest.fixture
def api(tmp_path, monkeypatch):
    from aegis.backend.core.config import settings

    root = tmp_path / "workspaces"
    clone = root / "example"
    (clone / ".git").mkdir(parents=True)
    (clone / "requirements.txt").write_text("urllib3==1.26.4\n")
    monkeypatch.setattr(settings, "workspace_root", root)
    engine = create_engine(
        f"sqlite:///{tmp_path / 'scans.db'}", connect_args={"check_same_thread": False}
    )
    Base.metadata.create_all(engine)
    sessions = sessionmaker(bind=engine)
    with sessions() as db:
        db.add(
            Repository(
                url="https://github.com/octo/project",
                owner="octo",
                name="project",
                local_path=str(clone),
            )
        )
        db.commit()

    def override_db():
        with sessions() as db:
            yield db

    async def override_scanner():
        yield VulnerabilityScanner(
            FakeOSV([OSVResult([advisory("GHSA-a"), advisory("PYSEC-b")])])
        )

    app.dependency_overrides[get_db] = override_db
    app.dependency_overrides[get_scanner] = override_scanner
    yield TestClient(app), sessions, clone
    app.dependency_overrides.clear()
    engine.dispose()


def test_scan_api_persists_normalized_findings_and_history(api):
    client, sessions, _ = api
    response = client.post("/scans", json={"repository_id": 1, "use_model": False})
    assert response.status_code == 201
    data = response.json()
    finding = data["report"]["vulnerabilities"][0]
    assert finding["package"] == "urllib3" and finding["installed_version"] == "1.26.4"
    assert (
        finding["cve"] == "CVE-2023-45803"
        and finding["affected"] is True
        and finding["fixed_version"] == "1.26.18"
    )
    assert len(data["report"]["vulnerabilities"]) == 1
    assert client.get(f"/scans/{data['id']}").json() == data
    second = client.post("/scans", json={"repository_id": 1, "use_model": False}).json()
    history = client.get("/scans?repository_id=1").json()
    assert [run["id"] for run in history] == [second["id"], data["id"]]
    with sessions() as db:
        rows = list(db.scalars(select(FindingRow)))
        assert len(rows) == 2 and rows[0].fixed_version == "1.26.18"
        assert json.loads(rows[0].data)["advisory_ids"] == ["GHSA-a", "PYSEC-b"]
        row = rows[0]
        db.add(
            FindingRow(
                scan_run_id=row.scan_run_id,
                ecosystem=row.ecosystem,
                package=row.package,
                installed_version=row.installed_version,
                advisory_id=row.advisory_id,
                data=row.data,
            )
        )
        with pytest.raises(IntegrityError):
            db.commit()
        db.rollback()


def test_api_failures_and_validation(api):
    client, sessions, clone = api
    assert (
        client.post(
            "/scans", json={"repository_id": 999, "use_model": False}
        ).status_code
        == 404
    )
    assert client.post("/scans", json={"repository_id": 0}).status_code == 422
    assert client.get("/scans/999").status_code == 404
    assert client.get("/scans?limit=101").status_code == 422
    assert client.get("/scans?repository_id=999").status_code == 404
    from aegis.backend.core.config import settings

    previous = settings.workspace_root
    settings.workspace_root = clone.parent.parent
    try:
        assert (
            client.post(
                "/scans", json={"repository_id": 1, "use_model": False}
            ).status_code
            == 422
        )
    finally:
        settings.workspace_root = previous
    with sessions() as db:
        assert list(db.scalars(select(ScanRun))) == []


def test_unexpected_scan_error_is_persisted(api, monkeypatch):
    client, sessions, _ = api
    from aegis.backend.services import scan_service

    def explode(path):
        raise RuntimeError("private exception text")

    monkeypatch.setattr(scan_service, "analyze_repository", explode)
    data = client.post("/scans", json={"repository_id": 1, "use_model": False}).json()
    assert data["status"] == "failed" and data["report"]["errors"]
    assert "private exception text" not in json.dumps(data)
    with sessions() as db:
        assert db.get(ScanRun, data["id"]).status == "failed"
        assert not list(db.scalars(select(FindingRow)))


def test_model_interpretation_and_runtime_resolution_integrate_with_scan(
    api, monkeypatch
):
    client, _, _ = api
    from aegis.backend.services import scan_service

    async def resolved(path, report):
        report.resolution_status = "completed"
        report.projects[0].dependencies[0].resolved = True
        return report

    async def interpreted(path, *, report):
        report.inference_status = "completed"
        report.summary = 'Model-assisted repository interpretation'
        return report

    monkeypatch.setattr(scan_service, "resolve_repository_analysis", resolved)
    monkeypatch.setattr(scan_service, "analyze_with_model", interpreted)
    data = client.post(
        "/scans",
        json={"repository_id": 1, "use_model": True, "resolve_dependencies": True},
    ).json()
    assert data["report"]["analysis_inference_status"] == "completed"
    assert data['report']['analysis_summary']=='Model-assisted repository interpretation'
    assert data["report"]["analysis_resolution_status"] == "completed"
    assert data["report"]["vulnerabilities"][0]["fixed_version"] == "1.26.18"


def test_existing_database_can_add_findings_without_altering_scan_history(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'legacy.db'}")
    with engine.begin() as connection:
        connection.exec_driver_sql(
            "CREATE TABLE repositories (id INTEGER PRIMARY KEY, url VARCHAR(500), owner VARCHAR(255), name VARCHAR(255), default_branch VARCHAR(255), local_path VARCHAR(1000), created_at DATETIME)"
        )
        connection.exec_driver_sql(
            "CREATE TABLE scan_runs (id INTEGER PRIMARY KEY, repository_id INTEGER, commit_sha VARCHAR(64), status VARCHAR(32), result TEXT, created_at DATETIME)"
        )
        connection.exec_driver_sql(
            "INSERT INTO scan_runs (id,repository_id,status) VALUES (1,1,'queued')"
        )
    Base.metadata.create_all(engine)
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        assert db.get(ScanRun, 1).status == "queued"
        assert not list(db.scalars(select(FindingRow)))
    engine.dispose()
