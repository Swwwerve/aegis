"""Real offline toolchain execution plus regressions for formerly unsupported formats."""

import asyncio
import json
from pathlib import Path

import pytest

import docker
from aegis.backend.analysis.dependency_parser import parse_dependencies
from aegis.backend.analysis.repo_analyzer import analyze_repository
from aegis.backend.sandbox.docker_runner import create_sandbox
from aegis.backend.sandbox.executor import SandboxExecutor
from aegis.backend.sandbox.policies import SandboxPolicy
from aegis.backend.schemas.repository import (
    CommandPlan,
    ExecutionResult,
    ProjectAnalysis,
)


def put(root, relative, text):
    target = root / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")
    return target


@pytest.mark.parametrize(
    "name,text,expected",
    [
        (
            "pnpm-lock.yaml",
            "lockfileVersion: '9.0'\npackages:\n  '@scope/a@1.2.3': {}\n  b@2.0.0(peer@1.0.0): {}\n",
            {("@scope/a", "1.2.3"), ("b", "2.0.0")},
        ),
        (
            "pnpm-lock.yaml",
            "lockfileVersion: 5.4\npackages:\n  /@scope/a/1.2.3: {}\n  /b/2.0.0: {}\n",
            {("@scope/a", "1.2.3"), ("b", "2.0.0")},
        ),
        (
            "yarn.lock",
            '# yarn lockfile v1\n"@scope/a@^1.0", "@scope/a@~1.2":\n  version "1.2.3"\n\nb@^2:\n  version "2.0.0"\n',
            {("@scope/a", "1.2.3"), ("b", "2.0.0")},
        ),
        (
            "yarn.lock",
            '__metadata:\n  version: 8\n"a@npm:^1":\n  version: 1.2.3\n  resolution: "a@npm:1.2.3"\n',
            {("a", "1.2.3")},
        ),
        (
            "bun.lock",
            '{// jsonc lock\n"lockfileVersion":1,"packages":{"a":["a@1.2.3","",{},"sha512-x"],},}',
            {("a", "1.2.3")},
        ),
        (
            "gradle.lockfile",
            "# Gradle lock\norg.example:library:1.2.3=compileClasspath,testRuntimeClasspath\nempty=annotationProcessor\n",
            {("org.example:library", "1.2.3")},
        ),
    ],
)
def test_locked_inventories(tmp_path, name, text, expected):
    dependencies, _, warnings = parse_dependencies(put(tmp_path, name, text), tmp_path)
    assert {(d.name, d.version) for d in dependencies} == expected
    assert all(d.resolved for d in dependencies)
    assert not warnings


def test_gradle_catalogs_belong_to_build_project(tmp_path):
    put(tmp_path, "build.gradle", 'plugins { id "java" }')
    put(
        tmp_path,
        "gradle/libs.versions.toml",
        '[versions]\njunit="4.13.2"\n[libraries]\njunit={module="junit:junit",version.ref="junit"}\n',
    )
    report = analyze_repository(tmp_path)
    assert len(report.projects) == 1
    assert report.projects[0].languages == ["Java"]
    assert any(
        d.name == "junit:junit" and d.version == "4.13.2"
        for d in report.projects[0].dependencies
    )


def test_yaml_aliases_are_rejected(tmp_path):
    dependencies, _, warnings = parse_dependencies(
        put(tmp_path, "pnpm-lock.yaml", "a: &bomb [1,2,3]\npackages: *bomb\n"), tmp_path
    )
    assert not dependencies and any("aliases" in warning for warning in warnings)


def test_binary_lockfile_is_not_decoded_as_utf8(tmp_path):
    path = tmp_path / "bun.lockb"
    path.write_bytes(b"\xff\xfe\x00")
    _, _, warnings = parse_dependencies(path, tmp_path)
    assert any("sandbox Bun decoding" in warning for warning in warnings)
    assert not any("Unicode" in warning for warning in warnings)


def test_local_yarn_reference_is_not_an_exact_registry_version(tmp_path):
    dependencies, _, _ = parse_dependencies(
        put(tmp_path, "yarn.lock", 'local@file:local:\n  version "local"\n'), tmp_path
    )
    assert not dependencies[0].resolved


def test_python_extras_are_followed_in_sandbox_environment():
    class Reports(SandboxExecutor):
        async def _run_resolution(self, project, argv, source):
            data = {
                "name": "root",
                "requires": ["example[feature]>=1"],
                "installed": {
                    "example": {
                        "version": "1.0",
                        "requires": [
                            "child==2; extra == 'feature'",
                            "windows-only; sys_platform == 'win32'",
                        ],
                    },
                    "child": {"version": "2", "requires": []},
                },
                "environment": {"sys_platform": "linux"},
            }
            return ExecutionResult(
                command=CommandPlan(kind="build", argv=["python"], source=source),
                status="passed",
                stdout="AEGIS_JSON:" + json.dumps(data),
            )

    output = asyncio.run(
        Reports(None).resolve_project(ProjectAnalysis(root=".", manifests=["setup.py"]))
    )
    assert output[0].status == "completed"
    assert any(d.name == "child" and d.resolved for d in output[0].dependencies)
    assert not any(d.name == "windows-only" for d in output[0].dependencies)


def test_unavailable_sandbox_retains_static_analysis(tmp_path, monkeypatch):
    from aegis.backend.sandbox import docker_runner
    from aegis.backend.sandbox.executor import resolve_repository_analysis

    put(tmp_path, "package.json", "{}")

    async def unavailable(*args, **kwargs):
        raise RuntimeError("not running")

    monkeypatch.setattr(docker_runner, "create_sandbox", unavailable)
    report = asyncio.run(resolve_repository_analysis(tmp_path))
    assert report.resolution_status == "unavailable"
    assert report.projects[0].languages == ["Node"]


def test_offline_cache_miss_has_explicit_status():
    result = SandboxExecutor._failure(
        ExecutionResult(
            command=CommandPlan(kind="build", argv=["npm"], source="package.json"),
            status="failed",
            stderr="npm ERR! ENOTCACHED",
        ),
        "Node",
        "npm-installed-tree",
    )
    assert result.status == "unavailable" and result.diagnostics


def test_real_polyglot_resolution_and_execution(tmp_path):
    try:
        docker.from_env().images.get("aegis-sandbox:polyglot")
    except (docker.errors.DockerException, OSError):
        pytest.skip("Build docker/Dockerfile.polyglot and start Docker")
    root = tmp_path / "workspaces"
    repo = root / "fixture"
    (repo / ".git").mkdir(parents=True)
    put(
        repo,
        "node/package.json",
        json.dumps(
            {
                "scripts": {
                    "test": "node --test",
                    "postinstall": "node -e \"require('fs').writeFileSync('should-not-exist','bad')\"",
                },
                "dependencies": {"is-odd": "3.0.1"},
            }
        ),
    )
    put(
        repo,
        "node/example.test.js",
        "const {test}=require('node:test'); const assert=require('node:assert/strict'); const odd=require('is-odd'); test('addition',()=>assert.equal(odd(2+3),true));",
    )
    for manager in ("pnpm", "yarn", "yarnclassic", "bunpm"):
        put(
            repo,
            manager + "/package.json",
            json.dumps(
                {
                    "name": "aegis-" + manager + "-fixture",
                    "private": True,
                    "dependencies": {"is-odd": "3.0.1"},
                    "scripts": {
                        "test": "node --test",
                        "postinstall": "node -e \"require('fs').writeFileSync('should-not-exist','bad')\"",
                    },
                }
            ),
        )
        put(
            repo,
            manager + "/example.test.js",
            (repo / "node/example.test.js").read_text(),
        )
        if manager == "yarnclassic":
            package = json.loads((repo / manager / "package.json").read_text())
            package["packageManager"] = "yarn@1.22.22"
            put(repo, manager + "/package.json", json.dumps(package))
    put(
        repo,
        "python/setup.py",
        "from setuptools import setup\nfrom pathlib import Path\nsetup(name='dynamic-example',version='1.0',install_requires=Path('deps.txt').read_text().splitlines())\n",
    )
    put(
        repo,
        "python/deps.txt",
        "packaging>=25\naegis-nonexistent-on-windows; sys_platform == 'win32'\n",
    )
    (repo / "bun").mkdir()
    (repo / "bun/bun.lockb").write_bytes(Path("tests/fixtures/bun.lockb").read_bytes())
    put(
        repo,
        "python-missing/setup.py",
        "from setuptools import setup\nsetup(name='missing-example',version='1',install_requires=['aegis-nonexistent-dependency==1'])\n",
    )
    seed = Path("docker/cache-seed/pom.xml").read_text()
    parent = seed.replace(
        "<artifactId>offline-cache-seed</artifactId>", "<artifactId>parent</artifactId>"
    ).replace(
        "<version>1</version>", "<version>1</version><packaging>pom</packaging>", 1
    )
    put(repo, "parent/pom.xml", parent)
    put(
        repo,
        "maven/pom.xml",
        "<project><modelVersion>4.0.0</modelVersion><parent><groupId>invalid.aegis</groupId><artifactId>parent</artifactId><version>1</version><relativePath>../parent/pom.xml</relativePath></parent><artifactId>child</artifactId></project>",
    )
    put(
        repo,
        "maven/src/test/java/SmokeTest.java",
        Path("docker/cache-seed/src/test/java/SmokeTest.java").read_text(),
    )
    put(repo, "gradle/settings.gradle", "rootProject.name='computed-example'\n")
    put(
        repo,
        "gradle/gradle/libs.versions.toml",
        '[versions]\njunit="4.13.2"\n[libraries]\njunit={module="junit:junit",version.ref="junit"}\n',
    )
    put(
        repo,
        "gradle/build.gradle",
        "plugins { id 'java' }\nrepositories { maven { url = uri('/workspace/.aegis-cache/maven') } }\ndef chosenVersion = '1.' + '3'\ndependencies { testImplementation(libs.junit); implementation(\"org.hamcrest:hamcrest-core:${chosenVersion}\") }\n",
    )
    put(
        repo,
        "gradle/src/test/java/ArithmeticTest.java",
        "import org.junit.Test; import static org.junit.Assert.assertEquals; public class ArithmeticTest { @Test public void addition(){ assertEquals(5,2+3); } }",
    )

    async def exercise():
        async with await create_sandbox(
            repo, workspace_root=root, policy=SandboxPolicy.polyglot()
        ) as box:
            executor = SandboxExecutor(box, max_output_bytes=1024 * 1024)
            config = box.client.docker_client.containers.get(
                box.session.state.container_id
            ).attrs
            assert config["HostConfig"]["NetworkMode"] == "none"
            assert (
                config["HostConfig"]["ReadonlyRootfs"]
                and config["Config"]["User"] == "10001:10001"
            )
            assert not any(
                "OPENAI_API_KEY" in entry for entry in config["Config"]["Env"]
            )
            for tool in [
                "node",
                "npm",
                "pnpm",
                "yarn",
                "bun",
                "java",
                "javac",
                "mvn",
                "gradle",
            ]:
                output = await box.exec(
                    "python",
                    "-c",
                    "import shutil,sys; assert shutil.which(sys.argv[1])",
                    tool,
                )
                assert output.exit_code == 0, tool
            npm = await executor.resolve_project(
                ProjectAnalysis(
                    root="node",
                    manifests=["node/package.json"],
                    package_managers=["npm"],
                )
            )
            assert npm[0].status == "completed", npm[0].model_dump()
            assert any(
                d.name == "is-number" and d.version == "6.0.0"
                for d in npm[0].dependencies
            )
            assert any(
                edge.parent == "is-odd@3.0.1" and edge.child == "is-number@6.0.0"
                for edge in npm[0].edges
            )
            assert (
                await box.exec(
                    "test", "!", "-f", "/workspace/repo/node/should-not-exist"
                )
            ).exit_code == 0
            for manager, directory in [
                ("pnpm", "pnpm"),
                ("yarn", "yarn"),
                ("yarn", "yarnclassic"),
                ("bun", "bunpm"),
            ]:
                resolved = await executor.resolve_project(
                    ProjectAnalysis(
                        root=directory,
                        manifests=[directory + "/package.json"],
                        package_managers=[manager],
                        runtime_constraints={"packageManager": "yarn@1.22.22"}
                        if directory == "yarnclassic"
                        else {},
                    )
                )
                assert resolved[0].status == "completed", resolved[0].model_dump_json()
                assert any(
                    d.name == "is-number" and d.version == "6.0.0"
                    for d in resolved[0].dependencies
                ), resolved[0].model_dump()
                verified = await executor.execute(
                    CommandPlan(
                        kind="test",
                        argv=[manager, "run", "test"],
                        cwd=directory,
                        source=directory + "/package.json",
                    )
                )
                assert verified.status == "passed", verified.model_dump()
                assert (
                    await box.exec(
                        "test",
                        "!",
                        "-f",
                        "/workspace/repo/" + directory + "/should-not-exist",
                    )
                ).exit_code == 0
            bun = await executor.resolve_project(
                ProjectAnalysis(root="bun", lockfiles=["bun/bun.lockb"])
            )
            assert bun[0].status == "completed", bun[0].model_dump()
            assert any(
                d.name == "is-odd" and d.version == "3.0.1" for d in bun[0].dependencies
            ), bun[0].model_dump()
            node = await executor.execute(
                CommandPlan(
                    kind="test",
                    argv=["npm", "run", "test"],
                    cwd="node",
                    source="node/package.json",
                )
            )
            assert node.status == "passed", node.model_dump()
            dynamic = await executor.resolve_project(
                ProjectAnalysis(root="python", manifests=["python/setup.py"])
            )
            assert dynamic[0].status == "completed", dynamic[0].model_dump()
            assert any(
                d.name == "packaging" and d.resolved for d in dynamic[0].dependencies
            )
            missing = await executor.resolve_project(
                ProjectAnalysis(
                    root="python-missing", manifests=["python-missing/setup.py"]
                )
            )
            assert missing[0].status == "partial" and missing[0].diagnostics
            maven = await executor.resolve_project(
                ProjectAnalysis(root="maven", manifests=["maven/pom.xml"])
            )
            assert maven[0].status == "completed", maven[0].model_dump()
            assert any(
                d.name == "org.junit.jupiter:junit-jupiter-api"
                and d.version == "5.10.2"
                for d in maven[0].dependencies
            )
            assert any(
                edge.child == "org.hamcrest:hamcrest-core@1.3"
                for edge in maven[0].edges
            )
            mvn_test = await executor.execute(
                CommandPlan(
                    kind="test",
                    argv=["mvn", "-B", "-o", "test"],
                    cwd="maven",
                    source="maven/pom.xml",
                )
            )
            assert mvn_test.status == "passed" and "Tests run: 1" in mvn_test.stdout, (
                mvn_test.model_dump()
            )
            gradle = await executor.resolve_project(
                ProjectAnalysis(root="gradle", manifests=["gradle/build.gradle"])
            )
            assert gradle[0].status == "completed", gradle[0].model_dump()
            assert any(
                d.name == "junit:junit" and d.version == "4.13.2"
                for d in gradle[0].dependencies
            )
            assert any(
                d.name == "org.hamcrest:hamcrest-core" and d.version == "1.3"
                for d in gradle[0].dependencies
            )
            gradle_test = await executor.execute(
                CommandPlan(
                    kind="test",
                    argv=[
                        "gradle",
                        "--offline",
                        "--no-daemon",
                        "--max-workers=1",
                        "-Dorg.gradle.jvmargs=-Xmx384m",
                        "test",
                    ],
                    cwd="gradle",
                    source="gradle/build.gradle",
                )
            )
            assert gradle_test.status == "passed", gradle_test.model_dump()
            await box.write_file(
                "gradle/build.gradle",
                b"plugins { id 'java' }\nrepositories { mavenCentral() }\ndependencies { implementation 'aegis.nonexistent:missing:1' }\n",
            )
            unresolved = await executor.resolve_project(
                ProjectAnalysis(root="gradle", manifests=["gradle/build.gradle"])
            )
            assert unresolved[0].status == "partial" and unresolved[0].diagnostics, (
                unresolved[0].model_dump()
            )
        assert (repo / "python/setup.py").read_text().startswith("from setuptools")
        assert not list(repo.rglob(".aegis-*"))
        from aegis.backend.sandbox.executor import resolve_repository_analysis

        pipeline = root / "pipeline"
        (pipeline / ".git").mkdir(parents=True)
        put(
            pipeline,
            "setup.py",
            "from setuptools import setup\nsetup(name='pipeline',version='1',install_requires=['packaging>=25'])\n",
        )
        report = await resolve_repository_analysis(pipeline, workspace_root=root)
        assert report.resolution_status == "completed", report.model_dump_json()
        assert report.projects[0].resolutions[0].method == "build-backend-metadata"
        assert any(
            dependency.name == "packaging" and dependency.resolved
            for dependency in report.projects[0].dependencies
        )
        assert not list(pipeline.rglob(".aegis-*"))

    asyncio.run(exercise())
