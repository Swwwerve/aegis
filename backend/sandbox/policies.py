"""Limits and input validation for untrusted repository sandboxes."""

from dataclasses import dataclass
from pathlib import Path

from aegis.backend.core.config import settings


@dataclass(frozen=True)
class SandboxPolicy:
    image: str = "aegis-sandbox:py312"
    memory_bytes: int = 512 * 1024 * 1024
    nano_cpus: int = 1_000_000_000
    pids_limit: int = 128
    workspace_bytes: int = 256 * 1024 * 1024
    command_timeout_seconds: float = 120
    agent_timeout_seconds: float = 900
    session_timeout_seconds: float = 1200
    max_file_bytes: int = 8 * 1024 * 1024
    max_snapshot_bytes: int = 300 * 1024 * 1024


def validate_repository_path(path: str | Path, root: str | Path | None = None) -> Path:
    """Only admit a real Step 1 clone directly beneath the workspace root."""
    allowed_root = Path(root or settings.workspace_root).resolve(strict=True)
    candidate = Path(path).resolve(strict=True)
    if candidate.parent != allowed_root or not candidate.is_dir():
        raise ValueError("Repository must be a direct child of the workspace root")
    if not (candidate / ".git").exists():
        raise ValueError("Repository is missing Git metadata")
    return candidate


def repository_file(path: str | Path) -> Path:
    """Return an absolute container path confined to /workspace/repo."""
    relative = Path(path)
    if relative.is_absolute() or not relative.parts or any(part in ("..", "") for part in relative.parts):
        raise ValueError("Use a relative path inside the repository")
    return Path("/workspace/repo") / relative
