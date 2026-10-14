"""Database models for repository intake and scan tracking."""

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, Text, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .database import Base


class Repository(Base):
    """A validated source repository registered with Aegis."""

    __tablename__ = "repositories"

    id: Mapped[int] = mapped_column(primary_key=True)
    url: Mapped[str] = mapped_column(String(500), unique=True, index=True)
    owner: Mapped[str] = mapped_column(String(255))
    name: Mapped[str] = mapped_column(String(255))
    default_branch: Mapped[str | None] = mapped_column(String(255))
    local_path: Mapped[str] = mapped_column(String(1000))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class ScanRun(Base):
    """A scan associated with an ingested repository."""

    __tablename__ = "scan_runs"

    id: Mapped[int] = mapped_column(primary_key=True)
    repository_id: Mapped[int] = mapped_column(ForeignKey("repositories.id"))
    commit_sha: Mapped[str | None] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(32), default="queued")
    result: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    findings: Mapped[list["VulnerabilityFinding"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )


class VulnerabilityFinding(Base):
    """One deduplicated package/version/advisory finding in a historical scan."""

    __tablename__ = "vulnerability_findings"
    __table_args__ = (
        UniqueConstraint(
            "scan_run_id",
            "ecosystem",
            "package",
            "installed_version",
            "advisory_id",
            name="uq_scan_finding_identity",
        ),
    )
    id: Mapped[int] = mapped_column(primary_key=True)
    scan_run_id: Mapped[int] = mapped_column(ForeignKey("scan_runs.id"), index=True)
    ecosystem: Mapped[str] = mapped_column(String(32))
    package: Mapped[str] = mapped_column(String(512))
    installed_version: Mapped[str] = mapped_column(String(256))
    advisory_id: Mapped[str] = mapped_column(String(200))
    cve: Mapped[str | None] = mapped_column(String(64), nullable=True)
    affected: Mapped[bool] = mapped_column(default=True)
    fixed_version: Mapped[str | None] = mapped_column(String(256), nullable=True)
    data: Mapped[str] = mapped_column(Text)
    scan: Mapped[ScanRun] = relationship(back_populates="findings")
