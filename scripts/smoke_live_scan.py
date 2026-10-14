"""Exercise Step 4 against live OSV using a disposable ingested-repository fixture."""

import argparse
import asyncio
import json
import subprocess
import tempfile
from pathlib import Path
from uuid import uuid4

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from aegis.backend.core.config import settings
from aegis.backend.db.database import Base
from aegis.backend.db.models import Repository, VulnerabilityFinding
from aegis.backend.schemas.vulnerability import ScanRequest
from aegis.backend.security.advisory_client import AdvisoryClient
from aegis.backend.security.epss_client import EPSSClient
from aegis.backend.security.kev_client import KEVClient
from aegis.backend.security.osv_client import OSVClient
from aegis.backend.security.vulnerability_scanner import VulnerabilityScanner
from aegis.backend.services.scan_service import scan_read, scan_repository


async def main(*, prioritize=False, use_model=False):
    output = Path("sandbox-smoke-results") / ("osv-" + uuid4().hex + ".json")
    output.parent.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="aegis-osv-") as temporary:
        root = Path(temporary) / "workspaces"
        clone = root / "fixture"
        clone.mkdir(parents=True)
        await asyncio.to_thread(
            subprocess.run, ["git", "init", str(clone)], check=True, capture_output=True
        )
        (clone / "requirements.txt").write_text("urllib3==1.26.4\n")
        (clone / "app.py").write_text(
            'import urllib3\nhttp = urllib3.PoolManager()\nurllib3.request("GET", "https://example.invalid")\n'
        )
        (clone / "app.js").write_text(
            'const lodash = require("lodash");\nlodash.merge({}, {});\n'
        )
        (clone / "package-lock.json").write_text(
            json.dumps(
                {
                    "lockfileVersion": 3,
                    "packages": {"node_modules/lodash": {"version": "4.17.15"}},
                }
            )
        )
        (clone / "pom.xml").write_text(
            "<project><modelVersion>4.0.0</modelVersion><groupId>invalid.aegis</groupId><artifactId>fixture</artifactId><version>1</version><dependencies><dependency><groupId>org.apache.logging.log4j</groupId><artifactId>log4j-core</artifactId><version>2.14.1</version></dependency></dependencies></project>"
        )
        await asyncio.to_thread(
            subprocess.run,
            ["git", "-C", str(clone), "add", "."],
            check=True,
            capture_output=True,
        )
        await asyncio.to_thread(
            subprocess.run,
            [
                "git",
                "-C",
                str(clone),
                "-c",
                "user.name=Aegis smoke",
                "-c",
                "user.email=smoke@example.invalid",
                "commit",
                "-m",
                "fixture",
            ],
            check=True,
            capture_output=True,
        )
        engine = create_engine(f"sqlite:///{Path(temporary) / 'smoke.db'}")
        Base.metadata.create_all(engine)
        previous = settings.workspace_root
        settings.workspace_root = root
        try:
            with Session(engine) as db:
                repository = Repository(
                    url="https://github.com/example/security-fixture",
                    owner="example",
                    name="security-fixture",
                    local_path=str(clone),
                )
                db.add(repository)
                db.commit()
                async with (
                    OSVClient() as client,
                    EPSSClient() as epss,
                    KEVClient() as kev,
                ):
                    run = await scan_repository(
                        db,
                        ScanRequest(repository_id=repository.id, use_model=use_model),
                        VulnerabilityScanner(
                            client,
                            advisory_client=AdvisoryClient(epss, kev)
                            if prioritize
                            else None,
                        ),
                    )
                result = scan_read(run)
                output.write_text(result.model_dump_json(indent=2), encoding="utf-8")
                report = result.report
                assert report.packages_completed == 3 and not report.errors, (
                    report.errors
                )
                assert {finding.ecosystem for finding in report.vulnerabilities} == {
                    "PyPI",
                    "npm",
                    "Maven",
                }
                assert any(
                    "CVE-2021-44228" in finding.cves
                    for finding in report.vulnerabilities
                )
                example = next(
                    finding
                    for finding in report.vulnerabilities
                    if "CVE-2023-45803" in finding.cves
                )
                assert (
                    example.package == "urllib3"
                    and example.installed_version == "1.26.4"
                    and example.fixed_version == "1.26.18"
                )
                stored = list(db.scalars(select(VulnerabilityFinding)))
                assert len(stored) == len(report.vulnerabilities)
                assert run.commit_sha is not None
                if prioritize:
                    log4shell = next(
                        f for f in report.vulnerabilities if "CVE-2021-44228" in f.cves
                    )
                    assert log4shell.kev is True and log4shell.priority.score >= 90
                    assert log4shell.epss_probability is not None
                    assert example.usage.static_call_count == 2
                    assert example.usage.runtime_call_count is None
                    assert all(f.priority is not None for f in report.vulnerabilities)
                    assert json.loads(stored[0].data)["priority"]
                    if use_model:
                        assert any(
                            f.priority.model_status == "completed"
                            for f in report.vulnerabilities
                        ), report.warnings
                    print(
                        f"Live priority passed: Log4Shell score={log4shell.priority.score}, KEV={log4shell.kev}, EPSS={log4shell.epss_probability}; urllib3 static calls={example.usage.static_call_count}."
                    )
                print(
                    f"Live OSV scan passed: 3 packages, {report.advisory_records} records, {len(stored)} deduplicated findings."
                )
                print(
                    json.dumps(
                        {
                            key: example.model_dump()[key]
                            for key in [
                                "package",
                                "installed_version",
                                "cve",
                                "affected",
                                "fixed_version",
                            ]
                        },
                        indent=2,
                    )
                )
                print(f"Full scan report: {output.resolve()}")
        finally:
            settings.workspace_root = previous
            engine.dispose()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--prioritize",
        action="store_true",
        help="Check live EPSS/KEV and evidence scoring",
    )
    parser.add_argument(
        "--model",
        action="store_true",
        help="Also assess priorities with OpenAI (requires OPENAI_API_KEY; implies --prioritize)",
    )
    args = parser.parse_args()
    asyncio.run(main(prioritize=args.prioritize or args.model, use_model=args.model))
