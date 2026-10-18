"""Analyze registered clones, scan live advisory data, and persist run history."""

import asyncio
import subprocess

from sqlalchemy import insert
from sqlalchemy.orm import Session

from ..analysis.repo_analyzer import analyze_repository, analyze_with_model
from ..core.progress import Progress, emit
from ..db.models import Repository, ScanRun, VulnerabilityFinding
from ..sandbox.executor import resolve_repository_analysis
from ..sandbox.policies import validate_repository_path
from ..schemas.vulnerability import ScanRead, ScanReport, ScanRequest
from ..security.vulnerability_scanner import VulnerabilityScanner


class ScanInputError(ValueError):
    pass


def scan_read(run: ScanRun) -> ScanRead:
    return ScanRead(
        id=run.id,
        repository_id=run.repository_id,
        commit_sha=run.commit_sha,
        status=run.status,
        created_at=run.created_at,
        report=ScanReport.model_validate_json(run.result) if run.result else None,
    )


async def scan_repository(
    db: Session,
    request: ScanRequest,
    scanner: VulnerabilityScanner,
    *,
    progress: Progress | None = None,
) -> ScanRun:
    repository = db.get(Repository, request.repository_id)
    if repository is None:
        raise LookupError("Repository not found")
    try:
        path = validate_repository_path(repository.local_path)
    except (ValueError, OSError) as exc:
        raise ScanInputError(
            "Registered repository clone is unavailable or outside the workspace"
        ) from exc

    def commit_sha():
        # Git metadata only; repository hooks and build scripts are not executed.
        try:
            result = subprocess.run(
                ["git", "-C", str(path), "rev-parse", "HEAD"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            sha = result.stdout.strip()
            return sha if result.returncode == 0 and len(sha) in {40, 64} else None
        except (OSError, subprocess.SubprocessError):
            return None

    run = ScanRun(
        repository_id=repository.id,
        status="running",
        commit_sha=await asyncio.to_thread(commit_sha),
    )
    db.add(run)
    db.commit()
    db.refresh(run)
    try:
        await emit(
            progress,
            "inventory",
            "running",
            "Reading source files, manifests, lockfiles, and project structure.",
            scan_id=run.id,
        )
        analysis = await asyncio.to_thread(analyze_repository, path)
        await emit(
            progress,
            "inventory",
            "completed",
            f"Examined {analysis.files_examined} files across {len(analysis.projects)} projects.",
            analysis=analysis.model_dump(mode="json"),
        )
        if request.resolve_dependencies:
            await emit(
                progress,
                "resolution",
                "running",
                "Resolving dependencies in the network-disabled Docker sandbox.",
            )
            analysis = await resolve_repository_analysis(
                path, analysis, progress=progress
            )
            await emit(
                progress,
                "resolution",
                analysis.resolution_status,
                "Dependency resolution returned its inventory and diagnostics.",
                analysis=analysis.model_dump(mode="json"),
            )
        else:
            await emit(
                progress,
                "resolution",
                "skipped",
                "Using manifest pins and lockfiles; optional sandbox resolution is off.",
            )
        if request.use_model:
            await emit(
                progress,
                "interpretation",
                "running",
                "Interpreting architecture and build/test plans with the model.",
            )
            analysis = await analyze_with_model(path, report=analysis)
            await emit(
                progress,
                "interpretation",
                analysis.inference_status,
                "Repository interpretation returned; proposed commands have not been executed.",
                analysis=analysis.model_dump(mode="json"),
            )
        else:
            await emit(
                progress,
                "interpretation",
                "skipped",
                "Model interpretation is off; using the source-backed inventory.",
            )
        report = await scanner.scan(
            analysis,
            repository_path=path,
            use_model=request.use_model,
            progress=progress,
        )
        report.repository_analysis = analysis
        await emit(
            progress,
            "saving",
            "running",
            "Saving the scan, commit snapshot, findings, and evidence.",
        )
        # No generated finding IDs are needed here. One executemany insert avoids
        # an ORM INSERT/RETURNING round trip per finding, in the same transaction
        # as the report update so failures cannot leave a partially saved scan.
        finding_rows = [
            {
                "scan_run_id": run.id,
                "ecosystem": finding.ecosystem,
                "package": finding.package,
                "installed_version": finding.installed_version,
                "advisory_id": finding.advisory_id,
                "cve": finding.cve,
                "affected": finding.affected,
                "fixed_version": finding.fixed_version,
                "data": finding.model_dump_json(),
            }
            for finding in report.vulnerabilities
        ]
        if finding_rows:
            db.execute(insert(VulnerabilityFinding.__table__), finding_rows)
        run.status = report.status
        run.result = report.model_dump_json()
        db.commit()
        await emit(
            progress,
            "saving",
            "completed",
            "Results saved. This scan is available in your history.",
        )
    except asyncio.CancelledError:
        db.rollback()
        run.status = "failed"
        run.result = ScanReport(
            status="failed", errors=["Scan cancelled"]
        ).model_dump_json()
        db.commit()
        raise
    except Exception as exc:  # noqa: BLE001 -- persist failures; never return an apparently clean scan
        db.rollback()
        run.status = "failed"
        run.result = ScanReport(
            status="failed", errors=[f"Scan execution failed ({type(exc).__name__})"]
        ).model_dump_json()
        db.commit()
    db.refresh(run)
    return run
