"""Repository validation, cloning, and metadata extraction."""

import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from uuid import uuid4

from pydantic import AnyHttpUrl

from ..core.config import settings

GITHUB_REPOSITORY = re.compile(
    r"^https://github\.com/(?P<owner>[A-Za-z0-9_.-]+)/"
    r"(?P<name>[A-Za-z0-9_.-]+?)(?:\.git)?/?$",
    re.IGNORECASE,
)


class RepositoryIntakeError(ValueError):
    """Raised when a repository cannot be validated or fetched."""


@dataclass(frozen=True)
class RepositoryMetadata:
    """Verified metadata produced after cloning a repository."""

    url: str
    owner: str
    name: str
    default_branch: str | None
    local_path: Path


def parse_github_url(url: AnyHttpUrl | str) -> tuple[str, str, str]:
    """Validate a public HTTPS GitHub URL and return URL, owner, and name."""

    normalized = str(url).rstrip("/")
    match = GITHUB_REPOSITORY.fullmatch(normalized)
    if match is None:
        raise RepositoryIntakeError(
            "Only public HTTPS GitHub repository URLs are supported."
        )
    owner = match.group("owner")
    name = match.group("name").removesuffix(".git")
    canonical_url = f"https://github.com/{owner}/{name}"
    return canonical_url, owner, name


def clone_repository(url: AnyHttpUrl | str) -> RepositoryMetadata:
    """Clone a validated repository into an isolated local workspace."""

    canonical_url, owner, name = parse_github_url(url)
    root = Path(settings.workspace_root)
    root.mkdir(parents=True, exist_ok=True)
    # Keep the full collision-resistant ID, without repeating metadata in paths.
    # Deep repositories can otherwise exceed Windows limits even after Git
    # checkout succeeds; owner/name remain in RepositoryMetadata and the DB.
    destination = root / uuid4().hex

    try:
        subprocess.run(
            # Git for Windows otherwise rejects deeply nested paths even when
            # Python and Windows support long filenames. Scope this setting to
            # the clone; never change the user's global Git configuration.
            [
                "git",
                "-c",
                "core.longpaths=true",
                "clone",
                "--depth",
                "1",
                canonical_url,
                str(destination),
            ],
            check=True,
            capture_output=True,
            text=True,
            timeout=300,
        )
        branch = (
            subprocess.run(
                ["git", "-C", str(destination), "symbolic-ref", "--short", "HEAD"],
                check=False,
                capture_output=True,
                text=True,
                timeout=30,
            ).stdout.strip()
            or None
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise RepositoryIntakeError("Repository could not be cloned.") from exc

    return RepositoryMetadata(
        url=canonical_url,
        owner=owner,
        name=name,
        default_branch=branch,
        local_path=destination,
    )
