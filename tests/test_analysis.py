"""Step 3 contracts: mixed repos, hostile metadata, ambiguous plans and model fallback."""

import asyncio
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from aegis.backend.analysis.dependency_parser import parse_dependencies
from aegis.backend.analysis.repo_analyzer import analyze_repository, analyze_with_model
from aegis.backend.sandbox.executor import SandboxExecutor
from aegis.backend.schemas.repository import CommandPlan, ModelInsight


def put(root: Path, name: str, text: str) -> Path:
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def test_python_metadata_groups_and_tooling(tmp_path):
    put(
        tmp_path,
        "pyproject.toml",
        """
[project]
name = "example"
requires-python = ">=3.11"
dependencies = ["requests>=2; python_version >= '3.11'"]
[project.optional-dependencies]
test = ["pytest>=8"]
[dependency-groups]
lint = ["ruff", {include-group = "base"}]
base = ["mypy"]
[build-system]
requires = ["setuptools>=68"]
build-backend = "setuptools.build_meta"
""",
    )
    put(tmp_path, "src/example/__init__.py", "")
    put(tmp_path, "tests/test_example.py", "")
    put(tmp_path, "uv.lock", '[[package]]\nname="requests"\nversion="2.32.0"\n')
    report = analyze_repository(tmp_path)
    project = report.projects[0]
    assert report.primary_language == "Python"
    assert project.package_managers == ["uv"]
    assert project.runtime_constraints["python"] == ">=3.11"
    declared = next(
        d for d in project.dependencies if d.name == "requests" and not d.resolved
    )
    assert declared.version == ">=2" and declared.marker is not None
    assert any(
        d.name == "requests" and d.resolved and d.version == "2.32.0"
        for d in project.dependencies
    )
    assert any(
        d.name == "mypy" and d.scope == "group:lint" for d in project.dependencies
    )
    assert any(
        c.argv == ["uv", "run", "--no-sync", "python", "-m", "pytest", "-q"]
        for c in project.commands
    )
    assert {d.role for d in report.important_directories} >= {"source", "tests"}


def test_node_monorepo_manager_inheritance_and_conflicts(tmp_path):
    put(
        tmp_path,
        "package.json",
        json.dumps(
            {
                "packageManager": "pnpm@9.0.0",
                "workspaces": ["packages/*"],
                "scripts": {
                    "test": "vitest",
                    "build": "tsc",
                    "postinstall": "node script.js",
                },
            }
        ),
    )
    put(
        tmp_path,
        "package-lock.json",
        '{"lockfileVersion":3,"packages":{"node_modules/@scope/pkg":{"version":"1.2.3"}}}',
    )
    put(
        tmp_path,
        "packages/ui/package.json",
        '{"engines":{"node":">=20"},"devDependencies":{"vitest":"^2"},"scripts":{"test":"vitest run","typecheck":"tsc --noEmit"}}',
    )
    put(tmp_path, "packages/ui/src/app.ts", "")
    put(tmp_path, "node_modules/ignored/package.json", "invalid")
    report = analyze_repository(tmp_path)
    projects = {p.root: p for p in report.projects}
    assert set(projects) == {".", "packages/ui"}
    assert any("conflicts" in w for w in projects["."].warnings)
    # Explicit parent declaration wins over its stale npm lockfile.
    assert any(c.argv == ["pnpm", "run", "test"] for c in projects["."].commands)
    assert any(
        d.name == "@scope/pkg" and d.resolved for d in projects["."].dependencies
    )
    assert any("lifecycle" in w for w in projects["."].warnings)
    child = projects["packages/ui"]
    assert any(c.argv == ["pnpm", "run", "test"] for c in child.commands)
    assert child.runtime_constraints["node"] == ">=20"


def test_ambiguous_node_lockfiles_do_not_choose_arbitrary_manager(tmp_path):
    put(tmp_path, "package.json", '{"scripts":{"test":"jest"}}')
    put(tmp_path, "yarn.lock", "")
    put(tmp_path, "pnpm-lock.yaml", "")
    project = analyze_repository(tmp_path).projects[0]
    assert not project.commands
    assert any("ambiguous" in w for w in project.warnings)


def test_node_placeholder_test_not_reported_as_real_test(tmp_path):
    put(
        tmp_path,
        "package.json",
        json.dumps({"scripts": {"test": 'echo "Error: no test specified" && exit 1'}}),
    )
    assert not any(
        c.kind == "test" for c in analyze_repository(tmp_path).projects[0].commands
    )


def test_java_maven_properties_scopes_and_wrapper(tmp_path):
    put(
        tmp_path,
        "pom.xml",
        """<project xmlns="http://maven.apache.org/POM/4.0.0">
<properties><java.version>17</java.version><lib.version>1.2.3</lib.version></properties>
<dependencies><dependency><groupId>org.example</groupId><artifactId>lib</artifactId><version>${lib.version}</version><scope>test</scope></dependency></dependencies>
<dependencyManagement><dependencies><dependency><groupId>org.example</groupId><artifactId>bom</artifactId><version>${unresolved}</version></dependency></dependencies></dependencyManagement>
<modules><module>missing</module></modules></project>""",
    )
    put(tmp_path, "mvnw", "#!/bin/sh\n")
    put(tmp_path, "src/main/java/App.java", "")
    project = analyze_repository(tmp_path).projects[0]
    assert project.languages == ["Java"]
    assert project.package_managers == ["maven"]
    assert project.runtime_constraints["java.version"] == "17"
    assert any(
        d.name == "org.example:lib" and d.version == "1.2.3" and d.scope == "test"
        for d in project.dependencies
    )
    assert any(d.scope == "managed" for d in project.dependencies)
    assert any(c.argv == ["sh", "mvnw", "-o", "test"] for c in project.commands)
    assert any("Missing Maven" in w for w in project.warnings)


def test_gradle_literals_and_partial_resolution(tmp_path):
    put(
        tmp_path,
        "build.gradle.kts",
        """// Ignore this comment without swallowing the dependency block
dependencies {
implementation("org.example:core:1.2")
testImplementation("org.junit:junit:5.0")
implementation(libs.other)
}""",
    )
    project = analyze_repository(tmp_path).projects[0]
    assert {d.name for d in project.dependencies} == {
        "org.example:core",
        "org.junit:junit",
    }
    assert any("partial" in w for w in project.warnings)
    assert any(
        c.argv == ["gradle", "--offline", "--no-daemon", "test"]
        for c in project.commands
    )


def test_test_framework_imports_and_runtime_files(tmp_path):
    put(tmp_path, "tests/test_app.py", "import pytest\ndef test_app(): assert True\n")
    put(tmp_path, ".python-version", "3.12\n")
    report = analyze_repository(tmp_path)
    assert report.projects[0].runtime_constraints[".python-version"] == "3.12"
    assert any(
        c.argv == ["python", "-m", "pytest", "-q"] for c in report.projects[0].commands
    )
    put(
        tmp_path,
        "tests/test_app.py",
        "import unittest\nclass TestApp(unittest.TestCase): pass\n",
    )
    report = analyze_repository(tmp_path)
    assert any(
        c.argv == ["python", "-m", "unittest", "discover", "-s", "tests"]
        for c in report.projects[0].commands
    )


def test_unknown_framework_does_not_invent_test_command(tmp_path):
    put(tmp_path, "tests/test_app.py", "def test_app(): pass\n")
    project = analyze_repository(tmp_path).projects[0]
    assert not any(c.kind == "test" for c in project.commands)
    assert any("framework is unknown" in warning for warning in project.warnings)


def test_requirements_include_cannot_read_dotenv(tmp_path):
    path = put(tmp_path, "requirements.txt", "-r .env\n")
    put(tmp_path, ".env", "PRIVATE_TOKEN=should-never-be-read")
    deps, _, warnings = parse_dependencies(path, tmp_path)
    assert not deps
    assert "should-never-be-read" not in str(warnings)
    assert any("secret files" in warning for warning in warnings)


def test_group_cycles_and_oversized_manifest(tmp_path):
    path = put(
        tmp_path,
        "pyproject.toml",
        '[dependency-groups]\na=[{include-group="b"}]\nb=[{include-group="a"}]\n',
    )
    assert any("cyclic" in w for w in parse_dependencies(path, tmp_path)[2])
    put(tmp_path, "package.json", " " * (1024 * 1024 + 1))
    assert any(
        "limit" in warning
        for project in analyze_repository(tmp_path).projects
        for warning in project.warnings
    )


@pytest.mark.parametrize(
    "name,text,expected",
    [
        (
            "Pipfile",
            '[packages]\nrequests="*"\n[dev-packages]\npytest="*"\n',
            {"requests", "pytest"},
        ),
        (
            "Pipfile.lock",
            '{"default":{"requests":{"version":"==2.32.0"}},"develop":{"pytest":{"version":"==8.0"}}}',
            {"requests", "pytest"},
        ),
        (
            "setup.cfg",
            "[options]\ninstall_requires =\n    requests>=2\n[options.extras_require]\ntest =\n    pytest\n",
            {"requests", "pytest"},
        ),
        (
            "pyproject.toml",
            '[tool.poetry.dependencies]\npython="^3.12"\nrequests="^2"\n[tool.poetry.group.dev.dependencies]\npytest="^8"\n',
            {"requests", "pytest"},
        ),
    ],
)
def test_other_python_manifest_formats(tmp_path, name, text, expected):
    path = put(tmp_path, name, text)
    dependencies, _, warnings = parse_dependencies(path, tmp_path)
    assert {d.name for d in dependencies} == expected
    assert not warnings


def test_requirements_includes_markers_constraints_cycles_and_escape(tmp_path):
    path = put(
        tmp_path,
        "requirements.txt",
        "-r deps/base.in\n-c deps/pins.in\n-r ../outside.txt\n",
    )
    put(
        tmp_path,
        "deps/base.in",
        "httpx[http2]>=0.27; python_version >= '3.11'\n-r ../requirements.txt\n",
    )
    put(tmp_path, "deps/pins.in", "httpx==0.28.1 --hash=sha256:abc\n")
    deps, _, warnings = parse_dependencies(path, tmp_path)
    assert any(d.name == "httpx" and d.scope == "runtime" and d.marker for d in deps)
    assert any(d.scope == "constraint" and d.version == "==0.28.1" for d in deps)
    assert any("cycle" in w for w in warnings)
    assert any("outside" in w for w in warnings)


@pytest.mark.parametrize(
    "name,text",
    [
        ("package.json", "{"),
        ("package.json", '{"engines":[]}'),
        ("package.json", "[]"),
        ("pyproject.toml", 'project="wrong"'),
        ("pyproject.toml", "not valid toml"),
        ("pom.xml", '<!DOCTYPE x [<!ENTITY x "bad">]><project>&x;</project>'),
    ],
)
def test_bad_manifest_does_not_abort_analysis(tmp_path, name, text):
    put(tmp_path, name, text)
    assert analyze_repository(tmp_path).projects[0].warnings


def test_python_executable_metadata_never_runs_on_host(tmp_path):
    marker = tmp_path / "owned"
    put(
        tmp_path,
        "setup.py",
        f"from pathlib import Path\nPath({str(marker)!r}).touch()\n",
    )
    assert analyze_repository(tmp_path).projects[0].warnings
    assert not marker.exists()


def test_inventory_limits_ignored_artifacts_ci_and_docs(tmp_path):
    put(tmp_path, "src/app.py", "")
    put(tmp_path, "node_modules/a/a.js", "")
    put(tmp_path, ".venv/foo.py", "")
    put(tmp_path, ".github/workflows/test.yml", "run: pytest")
    put(tmp_path, "README.md", "Run pytest")
    put(tmp_path, "docker/Dockerfile", "FROM python:3.12")
    report = analyze_repository(tmp_path)
    assert report.languages == {"Python": 1}
    assert report.ci_files == [".github/workflows/test.yml"]
    assert report.documentation == ["README.md"]
    assert report.container_files == ["docker/Dockerfile"]
    assert analyze_repository(tmp_path, max_files=2).truncated
    assert analyze_repository(tmp_path, max_depth=0).truncated


def test_symlink_not_read(tmp_path):
    outside = tmp_path.parent / f"{tmp_path.name}-external.json"
    outside.write_text('{"dependencies":{"secret":"1"}}')
    try:
        (tmp_path / "package.json").symlink_to(outside)
    except OSError:
        pytest.skip("Symlink creation unavailable")
    report = analyze_repository(tmp_path)
    assert not report.projects[0].dependencies
    assert any("symlink" in w for w in report.warnings)


class FakeClient:
    def __init__(self, insight=None, error=None):
        self.insight, self.error = insight, error
        self.responses = self
        self.input = None

    async def parse(self, **kwargs):
        self.input = kwargs["input"]
        if self.error:
            raise self.error
        return SimpleNamespace(output_parsed=self.insight)


def test_model_inference_grounding_and_secret_exclusion(tmp_path):
    put(tmp_path, "README.md", "Test using python -m unittest discover")
    put(tmp_path, "app.py", "")
    put(tmp_path, ".env", "SECRET=do-not-send")
    good = CommandPlan(
        kind="test", argv=["python", "-m", "unittest", "discover"], source="README.md"
    )
    bad = CommandPlan(kind="test", argv=["nonsense"], source="invented.txt")
    client = FakeClient(
        ModelInsight(summary="Python application", commands=[good, bad])
    )
    result = asyncio.run(analyze_with_model(tmp_path, client=client))
    assert result.inference_status == "completed"
    assert result.projects[0].commands[0].origin == "model"
    assert len(result.projects[0].commands) == 1
    assert "do-not-send" not in json.dumps(client.input)
    assert any("ungrounded" in w for w in result.warnings)


def test_model_failure_keeps_inventory(tmp_path):
    put(tmp_path, "app.py", "")
    result = asyncio.run(
        analyze_with_model(
            tmp_path, client=FakeClient(error=RuntimeError("private failure body"))
        )
    )
    assert result.inference_status == "failed"
    assert result.primary_language == "Python"
    assert "private failure body" not in result.model_dump_json()


def test_model_without_key_falls_back(tmp_path, monkeypatch):
    from aegis.backend.core.config import settings

    monkeypatch.setattr(settings, "openai_api_key", None)
    result = asyncio.run(analyze_with_model(tmp_path))
    assert result.inference_status == "unavailable"


@pytest.mark.parametrize("cwd", ["../outside", "/tmp", "C:/outside", "a\\..\\outside"])
def test_command_cwd_confined(cwd):
    with pytest.raises(ValidationError):
        CommandPlan(kind="test", argv=["pytest"], source="README.md", cwd=cwd)


class FakeWorkspace:
    def __init__(self, *, present=True, exit_code=0, error=None):
        self.present, self.exit_code, self.error = present, exit_code, error
        self.calls = []

    async def exec(self, *args, **kwargs):
        self.calls.append(args)
        if self.error:
            raise self.error
        if len(self.calls) == 1:
            return SimpleNamespace(
                exit_code=0, stdout=json.dumps(self.present).encode(), stderr=b""
            )
        return SimpleNamespace(
            exit_code=self.exit_code, stdout=b"123456789", stderr=b""
        )


@pytest.mark.parametrize("code,status", [(0, "passed"), (1, "failed")])
def test_executor_cwd_and_results(code, status):
    workspace = FakeWorkspace(exit_code=code)
    plan = CommandPlan(
        kind="test",
        argv=["python", "-m", "pytest"],
        cwd="packages/ui",
        source="package.json",
    )
    result = asyncio.run(SandboxExecutor(workspace, max_output_bytes=4).execute(plan))
    assert result.status == status and result.exit_code == code
    assert result.stdout == "1234" and result.reason == "Output truncated"
    assert workspace.calls[1][3:] == ("packages/ui", "python", "-m", "pytest")


def test_executor_missing_tool_network_and_timeout():
    plan = CommandPlan(kind="test", argv=["npm", "test"], source="package.json")
    assert (
        asyncio.run(SandboxExecutor(FakeWorkspace(present=False)).execute(plan)).status
        == "skipped"
    )
    assert (
        asyncio.run(
            SandboxExecutor(FakeWorkspace(error=TimeoutError())).execute(plan)
        ).status
        == "timeout"
    )
    workspace = FakeWorkspace()
    plan.requires_network = True
    assert asyncio.run(SandboxExecutor(workspace).execute(plan)).status == "skipped"
    assert not workspace.calls
