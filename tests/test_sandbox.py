"""Security contract and real Docker smoke test for Step 2."""

import asyncio
import subprocess
from pathlib import Path

import pytest
from agents.items import ModelResponse
from agents.models.interface import Model
from agents.sandbox import Manifest
from agents.sandbox.capabilities.tools.shell_tool import (
    ExecCommandArgs,
    ExecCommandTool,
)
from agents.sandbox.entries.artifacts import LocalDir
from agents.usage import Usage
from openai.types.responses import ResponseOutputMessage, ResponseOutputText

import docker
from aegis.backend.core.config import Settings
from aegis.backend.sandbox.docker_runner import (
    SecureDockerSandboxClient,
    create_sandbox,
)
from aegis.backend.sandbox.policies import (
    SandboxPolicy,
    repository_file,
    validate_repository_path,
)


class MockModel(Model):
    """Return one final answer while recording sandbox tools exposed by the SDK."""

    def __init__(self) -> None:
        self.tool_names: set[str] = set()

    async def get_response(self, *args, **kwargs):
        self.tool_names = {tool.name for tool in kwargs["tools"]}
        return ModelResponse(
            output=[ResponseOutputMessage(
                id="mock-message", role="assistant", status="completed", type="message",
                content=[ResponseOutputText(annotations=[], text="mock agent completed", type="output_text")],
            )],
            usage=Usage(), response_id=None,
        )

    async def stream_response(self, *args, **kwargs):
        if False:
            yield None


def test_openai_key_loads_from_dotenv_without_exposing_value(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text("OPENAI_API_KEY=test-local-key\n", encoding="utf-8")
    configured = Settings(_env_file=env_file)
    assert configured.openai_api_key.get_secret_value() == "test-local-key"
    assert "test-local-key" not in repr(configured)


def test_repository_boundary(tmp_path: Path) -> None:
    root = tmp_path / "workspaces"
    clone = root / "clone"
    clone.mkdir(parents=True)
    (clone / ".git").mkdir()
    assert validate_repository_path(clone, root) == clone
    with pytest.raises(ValueError):
        validate_repository_path(root, root)
    with pytest.raises(ValueError):
        repository_file("../escape")


def test_container_configuration_is_restricted(tmp_path: Path) -> None:
    class FakeImages:
        def get(self, image):
            return object()

    class FakeContainers:
        kwargs = None

        def create(self, **kwargs):
            self.kwargs = kwargs
            return object()

    class FakeDocker:
        images = FakeImages()
        containers = FakeContainers()

    fake = FakeDocker()
    root = tmp_path / "workspaces"
    clone = root / "clone"
    clone.mkdir(parents=True)
    (clone / ".git").mkdir()
    client = SecureDockerSandboxClient(fake, SandboxPolicy(), root)
    manifest = Manifest(entries={"repo": LocalDir(src=clone)})
    asyncio.run(client._create_container("aegis-sandbox:py312", manifest=manifest))
    args = fake.containers.kwargs
    assert args["network_mode"] == "none"
    assert args["user"] == "10001:10001"
    assert args["read_only"] is True
    assert args["cap_drop"] == ["ALL"]
    assert args["mem_limit"] > 0 and args["pids_limit"] > 0
    assert "mounts" not in args and "ports" not in args


def test_real_docker_session(tmp_path: Path) -> None:
    try:
        docker.from_env().images.get(SandboxPolicy().image)
    except (docker.errors.DockerException, OSError):
        pytest.skip("Build aegis-sandbox:py312 and start Docker for the integration test")
    root = tmp_path / "workspaces"
    clone = root / "clone"
    clone.mkdir(parents=True)
    subprocess.run(["git", "init", str(clone)], check=True, capture_output=True)
    (clone / "hello.txt").write_bytes(b"before\n")
    subprocess.run(["git", "-C", str(clone), "add", "."], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(clone), "-c", "user.name=test", "-c", "user.email=test@example.com", "commit", "-m", "initial"], check=True, capture_output=True)

    async def exercise():
        async with await create_sandbox(clone, workspace_root=root) as box:
            assert box.session.supports_pty() is False
            limits = box.client.docker_client.containers.get(box.session.state.container_id).attrs["HostConfig"]
            assert limits["NetworkMode"] == "none" and limits["ReadonlyRootfs"] is True
            container_env = box.client.docker_client.containers.get(box.session.state.container_id).attrs["Config"]["Env"]
            assert not any("OPENAI_API_KEY" in item for item in container_env)
            assert (await box.exec("id", "-u")).stdout.strip() == b"10001"
            assert (await box.exec("python", "-m", "pytest", "--version")).exit_code == 0
            assert await box.read_file("hello.txt") == b"before\n"
            shell_output = await ExecCommandTool(session=box.session).run(
                ExecCommandArgs(cmd="cat /workspace/repo/hello.txt")
            )
            assert "before" in shell_output
            await box.write_file("hello.txt", b"after\n")
            await box.write_file("new.txt", b"created\n")
            assert await box.read_file("hello.txt") == b"after\n"
            checks = await box.run_checks({"pytest": ["python", "-m", "pytest", "--version"]}, tmp_path / "checks")
            assert checks == {"pytest": 0}
            model = MockModel()
            agent_result = await box.run_agent("Inspect the repository", model=model)
            assert agent_result.final_output == "mock agent completed"
            assert "exec_command" in model.tool_names and "apply_patch" in model.tool_names
            snapshot = await box.snapshot(tmp_path / "snapshot.tar")
            export = await box.export_results(tmp_path / "export")
            assert b"after" in (export / "patch.diff").read_bytes()
            assert b"created" in (export / "patch.diff").read_bytes()
            assert snapshot.stat().st_size > 0
        async with await create_sandbox(clone, workspace_root=root, snapshot=snapshot) as resumed:
            assert await resumed.read_file("hello.txt") == b"after\n"

    asyncio.run(exercise())
