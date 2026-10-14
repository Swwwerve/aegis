"""Restricted Docker sandbox and persistent OpenAI SandboxAgent workspace."""

import asyncio
import io
import json
from collections.abc import Mapping, Sequence
from importlib.metadata import version
from pathlib import Path
from typing import Any, Self

from agents import RunConfig, Runner
from agents.models.interface import Model
from agents.models.openai_responses import OpenAIResponsesModel
from agents.sandbox import Manifest, SandboxRunConfig
from agents.sandbox.entries.artifacts import LocalDir
from agents.sandbox.sandboxes.docker import (
    DockerSandboxClient,
    DockerSandboxClientOptions,
    DockerSandboxSession,
)
from docker.models.containers import Container
from openai import AsyncOpenAI

import docker
from aegis.backend.agents.remediation_agent import make_remediation_agent
from aegis.backend.core.config import settings
from aegis.backend.sandbox.policies import (
    SandboxPolicy,
    repository_file,
    validate_repository_path,
)


class SecureDockerSandboxClient(DockerSandboxClient):
    """Apply limits at the SDK's container creation point, including resume."""

    def __init__(self, docker_client: docker.DockerClient, policy: SandboxPolicy,
                workspace_root: str | Path | None = None) -> None:
        if version("openai-agents") != "0.14.8":
            raise RuntimeError("Review Docker sandbox security for this Agents SDK version")
        super().__init__(docker_client)
        self.policy = policy
        self.workspace_root = workspace_root

    def _wrap_session(self, inner: Any, *, instrumentation: Any = None) -> Any:
        # Docker Desktop's PTY transport can complete commands with empty output.
        # The built-in Shell capability uses one-shot exec when PTY is unavailable.
        if isinstance(inner, DockerSandboxSession):
            inner.supports_pty = lambda: False
        return super()._wrap_session(inner, instrumentation=instrumentation)

    async def _create_container(
        self,
        image: str,
        *,
        manifest: Manifest | None = None,
        exposed_ports: tuple[int, ...] = (),
        session_id: Any = None,
    ) -> Container:
        if image != self.policy.image or exposed_ports:
            raise ValueError("Image override and exposed ports are forbidden")
        if manifest is None or manifest.root != "/workspace":
            raise ValueError("A restricted workspace manifest is required")
        if set(manifest.entries) != {"repo"} or not isinstance(manifest.entries["repo"], LocalDir):
            raise ValueError("Only a local repository entry is permitted")
        source = manifest.entries["repo"].src
        if source is None:
            raise ValueError("Repository source is required")
        validate_repository_path(source, self.workspace_root)
        if (manifest.environment.value or manifest.extra_path_grants or manifest.users
                or manifest.groups or manifest.remote_mount_command_allowlist != Manifest().remote_mount_command_allowlist):
            raise ValueError("Extra environment, users, mounts, and grants are forbidden")
        if not self.image_exists(image):
            raise RuntimeError(f"Build the local sandbox image first: {image}")
        policy = self.policy
        return self.docker_client.containers.create(
            image=image,
            entrypoint=["tail"],
            command=["-f", "/dev/null"],
            detach=True,
            user="10001:10001",
            working_dir="/workspace",
            network_mode="none",
            read_only=True,
            tmpfs={
                "/workspace": f"rw,nosuid,nodev,size={policy.workspace_bytes},uid=10001,gid=10001,mode=0700",
                "/tmp": "rw,exec,nosuid,nodev,size=67108864,uid=10001,gid=10001,mode=1777",
            },
            mem_limit=policy.memory_bytes,
            memswap_limit=policy.memory_bytes,
            nano_cpus=policy.nano_cpus,
            pids_limit=policy.pids_limit,
            cap_drop=["ALL"],
            security_opt=["no-new-privileges:true"],
            privileged=False,
            ipc_mode="none",
            init=True,
            environment={
                "HOME": "/workspace/.aegis-home",
                "PATH": "/opt/java/openjdk/bin:/usr/share/maven/bin:/opt/gradle/bin:/usr/local/bin:/usr/bin:/bin",
                "JAVA_HOME": "/opt/java/openjdk",
                "GRADLE_USER_HOME": "/workspace/.aegis-cache/gradle",
                "MAVEN_OPTS": "-Dmaven.repo.local=/workspace/.aegis-cache/maven -Xmx384m",
                "JAVA_TOOL_OPTIONS": "-Xmx512m",
                "PIP_NO_INDEX": "1", "UV_OFFLINE": "1", "NPM_CONFIG_OFFLINE": "true",
                "NPM_CONFIG_CACHE": "/workspace/.aegis-cache/npm",
                # Yarn 4 offline candidate filtering needs a distinct mirror path.
                "YARN_CACHE_FOLDER": "/workspace/.aegis-cache/yarn-local",
                "YARN_GLOBAL_FOLDER": "/workspace/.aegis-cache/yarn",
                "YARN_ENABLE_GLOBAL_CACHE": "0",
                "YARN_ENABLE_MIRROR": "1",
                "YARN_ENABLE_NETWORK": "0",
                "YARN_ENABLE_OFFLINE_MODE": "1",
                "YARN_ENABLE_SCRIPTS": "0",
                "BUN_INSTALL_CACHE_DIR": "/workspace/.aegis-cache/bun",
                "XDG_CACHE_HOME": "/workspace/.aegis-cache",
            },
            labels={"aegis.sandbox": "true", "aegis.session": str(session_id)},
        )


class SandboxWorkspace:
    """One remediation run. Keep this object open across agent and test iterations."""

    def __init__(self, client: SecureDockerSandboxClient, session: Any, policy: SandboxPolicy,
                snapshot: str | Path | None = None) -> None:
        self.client, self.session, self.policy = client, session, policy
        self._snapshot_source = snapshot
        self._closed = False
        self._expiry_task: asyncio.Task[None] | None = None

    async def __aenter__(self) -> Self:
        try:
            await self.session.__aenter__()
            initialized = await self.exec("python", "-c", "import pathlib,shutil; home=pathlib.Path('/workspace/.aegis-home'); home.mkdir(exist_ok=True); source=pathlib.Path('/opt/aegis-cache'); target=pathlib.Path('/workspace/.aegis-cache'); shutil.copytree(source,target,dirs_exist_ok=True) if source.is_dir() else target.mkdir(exist_ok=True)")
            if initialized.exit_code:
                raise RuntimeError("Unable to initialize sandbox offline caches")
            if self._snapshot_source is not None:
                await self.restore(self._snapshot_source)
            self._expiry_task = asyncio.create_task(self._expire())
        except Exception:
            await self.client.delete(self.session)
            self._closed = True
            raise
        return self

    async def __aexit__(self, *exc: object) -> None:
        if self._expiry_task is not None:
            self._expiry_task.cancel()
            await asyncio.gather(self._expiry_task, return_exceptions=True)
        try:
            await self.client.delete(self.session)
        finally:
            self._closed = True

    async def _expire(self) -> None:
        await asyncio.sleep(self.policy.session_timeout_seconds)
        await self.client.delete(self.session)
        self._closed = True

    async def exec(self, *command: str, timeout: float | None = None) -> Any:
        """Execute an argv command in the container as the nonroot user."""
        limit = min(timeout or self.policy.command_timeout_seconds, self.policy.command_timeout_seconds)
        return await self.session.exec(*command, shell=False, timeout=limit, user="aegis")

    async def read_file(self, path: str | Path) -> bytes:
        stream = await self.session.read(repository_file(path), user="aegis")
        data = stream.read(self.policy.max_file_bytes + 1)
        if len(data) > self.policy.max_file_bytes:
            raise ValueError("File exceeds sandbox read limit")
        return data

    async def write_file(self, path: str | Path, data: bytes) -> None:
        if len(data) > self.policy.max_file_bytes:
            raise ValueError("File exceeds sandbox write limit")
        await self.session.write(repository_file(path), io.BytesIO(data), user="aegis")

    async def run_agent(
        self, prompt: str, model: str | Model = "gpt-5.4", *,
        max_turns: int = 10, hooks: Any = None,
    ) -> Any:
        client: AsyncOpenAI | None = None
        if isinstance(model, str):
            if settings.openai_api_key is None:
                raise RuntimeError("Set OPENAI_API_KEY in Aegis/.env or the process environment")
            client = AsyncOpenAI(api_key=settings.openai_api_key.get_secret_value())
            model = OpenAIResponsesModel(model=model, openai_client=client)
        try:
            agent = make_remediation_agent(model)
            return await asyncio.wait_for(
                Runner.run(
                    agent, prompt, max_turns=max_turns, hooks=hooks,
                    run_config=RunConfig(
                        sandbox=SandboxRunConfig(session=self.session), tracing_disabled=True,
                    ),
                ),
                timeout=self.policy.agent_timeout_seconds,
            )
        finally:
            if client is not None:
                await client.close()

    async def run_checks(self, checks: Mapping[str, Sequence[str]], directory: str | Path) -> dict[str, int]:
        """Run declared argv checks and save their actual output and exit codes."""
        output = Path(directory)
        output.mkdir(parents=True, exist_ok=True)
        results: dict[str, int] = {}
        for name, command in checks.items():
            if (not name.replace("_", "").replace("-", "").isalnum()
                    or not command or isinstance(command, str)):
                raise ValueError("Check names must be simple and commands nonempty")
            result = await self.exec(*command)
            results[name] = result.exit_code
            (output / f"{name}.stdout").write_bytes(result.stdout)
            (output / f"{name}.stderr").write_bytes(result.stderr)
        (output / "checks.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
        return results

    async def snapshot(self, destination: str | Path) -> Path:
        """Save workspace archive for a later secure restore."""
        target = Path(destination)
        # The SDK's Docker persist_workspace uses get_archive on a tmpfs staging
        # path, which Docker Desktop on Windows does not expose to the daemon.
        result = await self.exec("tar", "-C", "/workspace", "-cf", "-", ".")
        if result.exit_code:
            raise RuntimeError(result.stderr.decode("utf-8", errors="replace"))
        if len(result.stdout) > self.policy.max_snapshot_bytes:
            raise ValueError("Snapshot exceeds size limit")
        target.write_bytes(result.stdout)
        return target

    async def restore(self, source: str | Path) -> None:
        path = Path(source)
        if path.stat().st_size > self.policy.max_snapshot_bytes:
            raise ValueError("Snapshot exceeds size limit")
        archive = io.BytesIO(await asyncio.to_thread(path.read_bytes))
        await self.session.hydrate_workspace(archive)

    async def export_results(self, directory: str | Path) -> Path:
        """Export changed-file patch, status, container logs, and full snapshot."""
        output = Path(directory)
        output.mkdir(parents=True, exist_ok=True)
        # Intent-to-add makes new files appear in the patch without staging contents.
        await self.exec("git", "-C", "/workspace/repo", "add", "-N", ".")
        commands = {
            "patch.diff": ("git", "-C", "/workspace/repo", "diff", "--binary", "HEAD"),
            "status.txt": ("git", "-C", "/workspace/repo", "status", "--short"),
        }
        for filename, command in commands.items():
            result = await self.exec(*command)
            (output / filename).write_bytes(result.stdout + result.stderr)
        container = self.client.docker_client.containers.get(self.session.state.container_id)
        (output / "container.log").write_bytes(container.logs())
        await self.snapshot(output / "workspace.tar")
        return output


async def create_sandbox(
    repository_path: str | Path,
    *,
    workspace_root: str | Path | None = None,
    policy: SandboxPolicy | None = None,
    snapshot: str | Path | None = None,
) -> SandboxWorkspace:
    """Load a Step 1 clone in a fresh restricted container."""
    policy = policy or SandboxPolicy()
    repository = validate_repository_path(repository_path, workspace_root)
    docker_client = docker.from_env()
    client = SecureDockerSandboxClient(docker_client, policy, workspace_root)
    session = await client.create(
        manifest=Manifest(entries={"repo": LocalDir(src=repository)}),
        options=DockerSandboxClientOptions(image=policy.image),
    )
    return SandboxWorkspace(client, session, policy, snapshot)
