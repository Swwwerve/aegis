"""Priority facts, outage semantics, static usage, model grounding and persistence."""

import asyncio
import json
from datetime import date, timedelta
from types import SimpleNamespace

import httpx
import pytest
from sqlalchemy import select
from test_vulnerabilities import FakeOSV, advisory, api, dependency, inventory, scanned  # noqa: F401 -- reused API fixture

from aegis.backend.api.scans import get_scanner
from aegis.backend.core.config import settings
from aegis.backend.db.models import VulnerabilityFinding as FindingRow
from aegis.backend.main import app
from aegis.backend.schemas.vulnerability import (
    AdvisoryEvidence,
    EPSSReading,
    ScanReport,
    VulnerabilityFinding,
)
from aegis.backend.security.advisory_client import (
    AdvisoryClient,
    ModelDecision,
    ModelPriorities,
    assess_priority,
    collect_cvss,
)
from aegis.backend.security.epss_client import EPSSClient
from aegis.backend.security.feed_client import FeedError
from aegis.backend.security.kev_client import KEV_MIRROR, KEV_URL, KEVClient
from aegis.backend.security.osv_client import OSVResult
from aegis.backend.security.usage_analyzer import analyze_usage
from aegis.backend.security.vulnerability_scanner import (
    VulnerabilityScanner,
    normalize_findings,
)

V3 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
V4 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"
CVE = "CVE-2021-44228"


def finding(**kwargs):
    return VulnerabilityFinding.model_validate(
        {
            "package": "urllib3",
            "installed_version": "1.26.4",
            "ecosystem": "PyPI",
            "advisory_id": CVE,
            "cve": CVE,
            "cves": [CVE],
            "version_source": "resolved",
            "manifests": ["requirements.txt"],
            "scopes": ["runtime"],
            "severity": [{"type": "CVSS_V3", "score": V3}],
            **kwargs,
        }
    )


def epss_payload(cves=(CVE,), **changes):
    return {
        "status": "OK",
        "total": len(cves),
        "offset": 0,
        "data": [
            {
                "cve": cve,
                "epss": "0.8",
                "percentile": "0.99",
                "date": date.today().isoformat(),
                **changes,
            }
            for cve in cves
        ],
    }


def kev_payload(**changes):
    return {
        "count": 1,
        "catalogVersion": "2024.01.01",
        "dateReleased": "2024-01-01T00:00:00Z",
        "vulnerabilities": [
            {
                "cveID": CVE,
                "dateAdded": "2021-12-10",
                "dueDate": "2021-12-24",
                "requiredAction": "Apply updates",
                "knownRansomwareCampaignUse": "Known",
                **changes,
            }
        ],
    }


class FakeEPSS:
    def __init__(self, fail=False, readings=None):
        self.fail, self.calls = fail, []
        self.readings = (
            readings
            if readings is not None
            else {
                CVE: EPSSReading(
                    cve=CVE,
                    probability=0.8,
                    percentile=0.99,
                    date=date.today().isoformat(),
                )
            }
        )

    async def lookup(self, cves):
        self.calls.append(cves)
        if self.fail:
            raise FeedError("secret exception content")
        return self.readings


class FakeKEV:
    def __init__(self, fail=False, entries=None):
        self.fail, self.calls = fail, 0
        self.entries = (
            entries
            if entries is not None
            else {CVE: kev_payload()["vulnerabilities"][0]}
        )

    async def catalog(self):
        self.calls += 1
        if self.fail:
            raise FeedError("secret exception content")
        return self.entries, {"kev_catalog_version": "fixture"}


class FakeModel:
    def __init__(self, decisions=None, fail=False):
        self.responses = self
        self.decisions = (
            decisions
            if decisions is not None
            else [
                ModelDecision(
                    finding_id="0",
                    adjustment=7,
                    rationale="Supplied usage and severity justify urgency; exposure unknown.",
                    evidence_fields=["usage", "cvss_score"],
                )
            ]
        )
        self.fail = fail
        self.requests = []

    async def parse(self, **kwargs):
        self.requests.append(kwargs)
        if self.fail:
            raise RuntimeError("private API exception")
        return SimpleNamespace(output_parsed=ModelPriorities(decisions=self.decisions))


def test_epss_batches_unique_cves_within_api_limits():
    requests = []

    def handler(request):
        ids = request.url.params["cve"].split(",")
        requests.append(ids)
        assert len(request.url.params["cve"]) <= 2000
        return httpx.Response(200, json=epss_payload(ids))

    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
            async with EPSSClient(http) as client:
                ids = [f"CVE-2020-{i:04d}" for i in range(205)]
                result = await client.lookup(ids + [ids[0]])
                assert len(result) == 205 and result[ids[0]].probability == 0.8
            assert not http.is_closed

    asyncio.run(run())
    assert len(requests) == 3


@pytest.mark.parametrize(
    "changes",
    [
        {"epss": "NaN"},
        {"epss": "1.1"},
        {"percentile": "-1"},
        {"date": "garbage"},
        {"date": "2999-01-01"},
        {"cve": "CVE-2000-9999"},
    ],
)
def test_invalid_epss_is_unknown_not_zero(changes):
    async def run():
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(
                lambda r: httpx.Response(200, json=epss_payload(**changes))
            )
        ) as http:
            with pytest.raises(FeedError):
                await EPSSClient(http).lookup([CVE])

    asyncio.run(run())


def test_epss_pagination_and_missing_cve():
    other = "CVE-2020-12345"

    def handler(request):
        offset = int(request.url.params["offset"])
        return httpx.Response(
            200,
            json={
                **epss_payload([CVE if offset == 0 else other]),
                "total": 2,
                "offset": offset,
            },
        )

    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
            result = await EPSSClient(http).lookup([CVE, other])
            assert len(result) == 2
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(
                lambda r: httpx.Response(200, json=epss_payload([]))
            )
        ) as http:
            assert await EPSSClient(http).lookup([CVE]) == {}

    asyncio.run(run())


def test_kev_fallback_and_metadata():
    urls = []

    def handler(request):
        urls.append(str(request.url))
        return (
            httpx.Response(403)
            if str(request.url) == KEV_URL
            else httpx.Response(200, json=kev_payload())
        )

    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
            entries, metadata = await KEVClient(http).catalog()
            assert entries[CVE]["source"] == KEV_MIRROR
            assert entries[CVE]["requiredAction"] == "Apply updates"
            assert metadata["kev_catalog_version"] == "2024.01.01"

    asyncio.run(run())
    assert urls == [KEV_URL, KEV_MIRROR]


@pytest.mark.parametrize(
    "payload",
    [
        {**kev_payload(), "count": 2},
        {**kev_payload(), "count": 0, "vulnerabilities": []},
        kev_payload(cveID="invalid"),
        kev_payload(dateAdded="not-date"),
        {
            **kev_payload(),
            "vulnerabilities": kev_payload()["vulnerabilities"] * 2,
            "count": 2,
        },
    ],
)
def test_malformed_kev_cannot_produce_false_negatives(payload):
    async def run():
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(lambda r: httpx.Response(200, json=payload))
        ) as http:
            with pytest.raises(FeedError):
                await KEVClient(http).catalog()

    asyncio.run(run())


def test_feed_retries_and_size_bound():
    calls = 0

    def handler(request):
        nonlocal calls
        calls += 1
        return (
            httpx.Response(429)
            if calls < 3
            else httpx.Response(200, json=epss_payload())
        )

    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
            assert CVE in await EPSSClient(http).lookup([CVE])
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(
                lambda r: httpx.Response(200, content=b"x" * (8 * 1024 * 1024 + 1))
            )
        ) as http:
            with pytest.raises(FeedError, match="size"):
                await EPSSClient(http).lookup([CVE])

    asyncio.run(run())
    assert calls == 3


@pytest.mark.parametrize(
    "vector,kind,score,version",
    [
        (V3, "CVSS_V3", 9.8, "3.1"),
        (V4 + "/E:U", "CVSS_V4", 10, "4.0"),
        ("AV:N/AC:L/Au:N/C:C/I:C/A:C", "CVSS_V2", 10, "2.0"),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", "CVSS_V3", 0, "3.1"),
    ],
)
def test_cvss_base_vectors(vector, kind, score, version):
    item = finding(severity=[{"type": kind, "score": vector}])
    collect_cvss(item)
    assert (item.cvss_score, item.cvss_version) == (score, version)


def test_cvss_invalid_and_newest_generation():
    item = finding(severity=[{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N"}])
    collect_cvss(item)
    assert item.cvss_score is None and item.notes
    item.severity = [{"type": "CVSS_V3", "score": V3}, {"type": "CVSS_V4", "score": V4}]
    collect_cvss(item)
    assert item.cvss_version == "4.0"
    item.severity = [{"type": "CVSS_V4", "score": V4 + "/E:INVALID"}]
    collect_cvss(item)
    assert item.cvss_score is None


def test_stale_evidence_retained_without_false_negative_kev(tmp_path):
    class StaleKEV(FakeKEV):
        async def catalog(self):
            return self.entries, {"kev_catalog_stale": "true"}

    old = EPSSReading(
        cve=CVE,
        probability=0.8,
        percentile=0.99,
        date=(date.today() - timedelta(days=30)).isoformat(),
    )
    item = finding()
    report = ScanReport(vulnerabilities=[item])
    asyncio.run(
        AdvisoryClient(FakeEPSS(readings={CVE: old}), StaleKEV(entries={})).enrich(
            report, tmp_path
        )
    )
    assert item.epss[0] == old and item.epss_probability is None
    assert item.enrichment["epss_status"] == "stale"
    assert item.kev is None and item.enrichment["kev_status"] == "stale"
    assert report.prioritization_status == "partial"
    asyncio.run(AdvisoryClient(FakeEPSS(), StaleKEV()).enrich(report, tmp_path))
    assert item.kev is True and item.priority.score >= 90


def test_score_bounds_missing_data_and_kev_floor():
    item = finding(cvss_score=10, epss_probability=1, kev=False)
    item.usage.status = "analyzed"
    item.usage.static_call_count = 100000
    assert assess_priority(item).score == 100
    item.cvss_score = 0
    item.epss_probability = 0
    item.usage.static_call_count = 0
    assert assess_priority(item).components["severity"] == 0
    item.kev = True
    item.scopes = ["dev"]
    assert assess_priority(item).score == 90
    item.kev, item.cvss_score, item.epss_probability = None, None, None
    unknown = assess_priority(item)
    assert unknown.score == 35 and set(unknown.missing_evidence) == {
        "CVSS",
        "EPSS",
        "CISA KEV",
    }
    item.fixed_version = "1.26.18"
    assert assess_priority(item).score == unknown.score


def test_usage_python_calls_not_runtime_and_affected_symbols(tmp_path):
    (tmp_path / "app.py").write_text(
        'import urllib3 as u\nfrom urllib3 import PoolManager as Pool\nu.request("GET", "example")\nPool()\n# u.request()\ntext="u.request()"\n'
    )
    item = finding(
        advisory_evidence=[
            AdvisoryEvidence(
                advisory_id=CVE,
                source="fixture",
                affected_functions=["urllib3.request"],
            )
        ]
    )
    analyze_usage(tmp_path, [item])
    assert item.usage.import_count == 2 and item.usage.static_call_count == 2
    assert item.usage.affected_function_call_count == 1
    assert item.usage.runtime_call_count is None
    assert item.usage.sites[0]["path"] == "app.py"


@pytest.mark.parametrize(
    "source",
    [
        "import urllib3 as u\nu=object()\nu.request()\n",
        "import urllib3 as u\ndef f(u):\n u.request()\n",
        "from urllib3 import request\ndef request(): pass\nrequest()\n",
        "def f():\n import urllib3 as u\ndef g():\n u.request()\n",
        "import urllib3 as u\nfrom local import thing as u\nu.request()\n",
    ],
)
def test_python_shadowing_not_attributed(source, tmp_path):
    (tmp_path / "app.py").write_text(source)
    item = finding()
    analyze_usage(tmp_path, [item])
    assert item.usage.static_call_count == 0


def test_usage_node_aliases_and_generated_files_excluded(tmp_path):
    (tmp_path / "app.ts").write_text(
        'import {merge as combine} from "lodash";\nconst l = require("lodash");\ncombine({}, {});\nl.merge({},{});\n// l.merge()\nconst s="l.merge()";\n'
    )
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "ignored.js").write_text(
        'const l=require("lodash"); l.merge();'
    )
    item = finding(package="lodash", ecosystem="npm", manifests=["package.json"])
    analyze_usage(tmp_path, [item])
    assert item.usage.import_count == 2 and item.usage.static_call_count == 2
    assert (
        item.usage.files_scanned == 1
        and item.usage.affected_function_call_count is None
    )


def test_usage_limits_projects_syntax_and_java_unknown(tmp_path):
    (tmp_path / "nested").mkdir()
    (tmp_path / "nested" / "app.py").write_text("import urllib3\nurllib3.request()")
    (tmp_path / "app.py").write_text("import urllib3\nurllib3.request()")
    root_item = finding()
    nested_item = finding(
        installed_version="1.26.5", manifests=["nested/requirements.txt"]
    )
    java_item = finding(
        ecosystem="Maven", package="org.apache.logging.log4j:log4j-core"
    )
    analyze_usage(tmp_path, [root_item, nested_item, java_item])
    assert root_item.usage.static_call_count == nested_item.usage.static_call_count == 1
    assert (
        java_item.usage.status == "unsupported"
        and java_item.usage.runtime_call_count is None
    )
    assert java_item.usage.static_call_count is None
    analyze_usage(tmp_path, [root_item], max_files=1)
    assert root_item.usage.truncated
    (tmp_path / "app.py").write_text("this is not valid python !!!")
    analyze_usage(tmp_path, [root_item])
    assert root_item.usage.status == "partial"


def test_local_python_module_shadowing(tmp_path):
    (tmp_path / "urllib3.py").write_text("def request(): pass")
    (tmp_path / "app.py").write_text("import urllib3\nurllib3.request()")
    item = finding()
    analyze_usage(tmp_path, [item])
    assert item.usage.status == "partial" and item.usage.static_call_count == 0


def test_live_enrichment_contract_multi_cve_and_single_catalog(tmp_path):
    (tmp_path / "app.py").write_text("import urllib3\nurllib3.request()")
    other = "CVE-2023-45803"
    report = ScanReport(
        vulnerabilities=[
            finding(cves=[CVE, other]),
            finding(installed_version="1.26.5"),
        ]
    )
    epss, kev = FakeEPSS(), FakeKEV()
    asyncio.run(AdvisoryClient(epss, kev).enrich(report, tmp_path))
    assert epss.calls == [[CVE, other]] and kev.calls == 1
    assert report.vulnerabilities[0].priority.score >= 90
    assert report.vulnerabilities[0].enrichment["fetched_at"]
    assert any(f.enrichment["epss_status"] == "partial" for f in report.vulnerabilities)
    assert report.prioritization_status == "partial"


def test_outages_do_not_erase_findings_or_mark_kev_false(tmp_path):
    item = finding()
    report = ScanReport(vulnerabilities=[item])
    asyncio.run(
        AdvisoryClient(FakeEPSS(fail=True), FakeKEV(fail=True)).enrich(report, tmp_path)
    )
    assert item.kev is None and item.epss_probability is None and item.cvss_score == 9.8
    assert report.status == "completed" and report.prioritization_status == "partial"
    assert "secret" not in json.dumps(report.model_dump(mode="json"))


def test_no_cve_does_not_query_feeds():
    epss, kev = FakeEPSS(), FakeKEV()
    item = finding(cve=None, cves=[], advisory_id="GHSA-example")
    asyncio.run(AdvisoryClient(epss, kev).enrich(ScanReport(vulnerabilities=[item])))
    assert not epss.calls and not kev.calls
    assert item.kev is None and item.enrichment["kev_status"] == "not_applicable"


def test_model_assessment_is_bounded_and_cannot_change_facts(tmp_path):
    item = finding()
    model = FakeModel()
    report = ScanReport(vulnerabilities=[item])
    asyncio.run(
        AdvisoryClient(FakeEPSS(), FakeKEV(entries={}), model_client=model).enrich(
            report, tmp_path, use_model=True
        )
    )
    assert item.priority.model_status == "completed"
    assert item.priority.score == item.priority.baseline_score + 7
    assert item.priority.model_evidence_fields == ["usage", "cvss_score"]
    assert item.cvss_score == 9.8 and item.affected and item.epss_probability == 0.8
    assert "untrusted" in model.requests[0]["input"][0]["content"]


def test_model_cannot_downgrade_known_exploited(tmp_path):
    model = FakeModel(
        [
            ModelDecision(
                finding_id="0",
                adjustment=-10,
                rationale="test",
                evidence_fields=["kev"],
            )
        ]
    )
    item = finding()
    asyncio.run(
        AdvisoryClient(FakeEPSS(), FakeKEV(), model_client=model).enrich(
            ScanReport(vulnerabilities=[item]), tmp_path, use_model=True
        )
    )
    assert item.priority.score >= 90 and item.priority.model_adjustment == 0


@pytest.mark.parametrize(
    "decisions",
    [
        [
            ModelDecision(
                finding_id="invalid",
                adjustment=5,
                rationale="test",
                evidence_fields=["usage"],
            )
        ],
        [
            ModelDecision(
                finding_id="0",
                adjustment=5,
                rationale="test",
                evidence_fields=["invented_runtime_exposure"],
            )
        ],
        [
            ModelDecision(
                finding_id="0", adjustment=5, rationale="test", evidence_fields=[]
            )
        ],
        [
            ModelDecision(
                finding_id="0",
                adjustment=5,
                rationale="test",
                evidence_fields=["usage"],
            )
        ]
        * 2,
    ],
)
def test_model_grounding_failure_keeps_baseline(decisions, tmp_path):
    item = finding()
    asyncio.run(
        AdvisoryClient(FakeEPSS(), FakeKEV(), model_client=FakeModel(decisions)).enrich(
            ScanReport(vulnerabilities=[item]), tmp_path, use_model=True
        )
    )
    assert item.priority.score == item.priority.baseline_score
    assert item.priority.model_status == "failed"


def test_model_unavailable_or_fails_gracefully(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "openai_api_key", None)
    for model, status in ((None, "unavailable"), (FakeModel(fail=True), "failed")):
        item = finding()
        report = ScanReport(vulnerabilities=[item])
        asyncio.run(
            AdvisoryClient(FakeEPSS(), FakeKEV(), model_client=model).enrich(
                report, tmp_path, use_model=True
            )
        )
        assert (
            item.priority.model_status == status
            and item.priority.score == item.priority.baseline_score
        )
        assert "private API" not in json.dumps(report.model_dump(mode="json"))


def test_osv_advisory_evidence_is_preserved_and_deduplicated():
    record = advisory()
    record.update(published="2023-01-01T00:00:00Z", modified="2024-01-01T00:00:00Z")
    record["affected"][0]["ecosystem_specific"] = {"functions": ["urllib3.request"]}
    items, _, _ = normalize_findings(scanned(), [record])
    evidence = items[0].advisory_evidence[0]
    assert evidence.affected_functions == ["urllib3.request"]
    assert evidence.modified == record["modified"] and evidence.ranges
    assert evidence.source.endswith(record["id"])


def test_scanner_and_api_persist_priorities(api):  # noqa: F811 -- pytest fixture import
    client, sessions, clone = api
    (clone / "app.py").write_text("import urllib3\nurllib3.request()")
    record = advisory(aliases=[CVE])
    record["severity"] = [{"type": "CVSS_V3", "score": V3}]

    async def override():
        yield VulnerabilityScanner(
            FakeOSV([OSVResult([record])]),
            advisory_client=AdvisoryClient(FakeEPSS(), FakeKEV()),
        )

    app.dependency_overrides[get_scanner] = override
    response = client.post("/scans", json={"repository_id": 1, "use_model": False})
    assert response.status_code == 201
    data = response.json()
    item = data["report"]["vulnerabilities"][0]
    assert item["priority"]["level"] == "critical" and item["kev"] is True
    assert item["usage"]["static_call_count"] == 1
    assert item["priority"]["model_status"] == "not_requested"
    assert client.get(f"/scans/{data['id']}").json() == data
    with sessions() as db:
        row = db.scalar(select(FindingRow))
        assert json.loads(row.data)["priority"] == item["priority"]


def test_old_scan_json_is_backwards_compatible():
    old = finding().model_dump(
        exclude={"priority", "usage", "epss", "kev", "advisory_evidence"}
    )
    report = ScanReport.model_validate({"schema_version": 1, "vulnerabilities": [old]})
    assert report.vulnerabilities[0].priority is None
    assert report.vulnerabilities[0].usage.runtime_call_count is None
