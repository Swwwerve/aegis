"""Explicitly execute analysis proposals inside an existing restricted sandbox.

No host subprocesses, package downloads, or implicit execution during intake.
Even an npm test script can be hostile: the Docker boundary remains essential.
"""

import json
from uuid import uuid4

from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name

from ..schemas.repository import (
    CommandPlan,
    Dependency,
    DependencyEdge,
    DependencyResolution,
    ExecutionResult,
    ProjectAnalysis,
)
from .docker_runner import SandboxWorkspace
from .resolution_scripts import GRADLE_INSPECT, NODE_TREE, PYTHON_METADATA, YARN_PNP

_LAUNCH = """import os,sys
from pathlib import Path
root=Path('/workspace/repo').resolve()
cwd=(root/sys.argv[1]).resolve()
if not cwd.is_relative_to(root) or not cwd.is_dir():
    print('Invalid repository working directory', file=sys.stderr)
    sys.exit(125)
os.chdir(cwd)
if sys.argv[2] == 'yarn':
    import json
    package=json.loads((cwd/'package.json').read_text()) if (cwd/'package.json').is_file() else {}
    declared=package.get('packageManager','')
    lock=(cwd/'yarn.lock').read_text() if (cwd/'yarn.lock').is_file() else ''
    if declared.startswith('yarn@1.') or (not declared and lock and '__metadata:' not in lock):
        sys.argv[2]='yarn1'
        os.environ['YARN_CACHE_FOLDER']='/workspace/.aegis-cache/yarn1'
os.execvp(sys.argv[2], sys.argv[2:])
"""
_PROBE = """import json,shutil,sys
print(json.dumps(bool(shutil.which(sys.argv[1]))))
"""


class SandboxExecutor:
    def __init__(self, workspace: SandboxWorkspace, *, max_output_bytes: int = 65536):
        if max_output_bytes < 1:
            raise ValueError("Output limit must be positive")
        self.workspace = workspace
        self.max_output_bytes = max_output_bytes

    async def remediate_with_context(
        self,
        repository_path,
        cve_id,
        scan_report,
        *,
        analysis=None,
        model="gpt-5.4",
        limits=None,
        max_turns: int = 10,
        investigator_model=None,
        progress=None,
        clarification="",
    ):
        """Plan focused evidence, then feed only that packet to the sandbox agent.

        Partial context remains reviewable but cannot automatically trigger edits.
        Existing run_agent callers remain unchanged.
        """
        from ..context.context_planner import plan_hybrid_context
        from .policies import validate_repository_path

        path = validate_repository_path(repository_path)
        packet = await plan_hybrid_context(
            path,
            cve_id,
            scan_report,
            analysis=analysis,
            model=model,
            limits=limits,
            investigator_model=investigator_model,
            progress=progress,
            clarification=clarification,
        )
        result = None
        if packet.status == "completed":
            import hashlib

            for snippet in packet.snippets:
                try:
                    raw = await self.workspace.read_file(snippet.path)
                    lines = raw.decode("utf-8-sig").splitlines(keepends=True)
                    current = "".join(lines[snippet.start - 1 : snippet.end])
                    if hashlib.sha256(current.encode()).hexdigest() != snippet.sha256:
                        raise ValueError("Selected snippet changed")
                except (ValueError, OSError):
                    packet.status = "partial"
                    packet.missing_context.append(
                        f"Sandbox source differs from selected context: {snippet.path}"
                    )
                    return packet, None
            result = await self.workspace.run_agent(
                packet.remediation_prompt(), model=model, max_turns=max_turns
            )
        return packet, result

    async def execute(
        self, command: CommandPlan, *, timeout: float | None = None
    ) -> ExecutionResult:
        # Revalidate even if a caller mutated a model instance after construction.
        command = CommandPlan.model_validate(command.model_dump())
        if command.requires_network:
            return ExecutionResult(
                command=command,
                status="skipped",
                reason="Network/install preparation is not supported in the offline sandbox",
            )
        try:
            probe = await self.workspace.exec(
                "python", "-c", _PROBE, command.argv[0], timeout=timeout
            )
            if probe.exit_code != 0:
                return ExecutionResult(
                    command=command,
                    status="error",
                    reason="Could not inspect sandbox toolchain",
                )
            if not json.loads(probe.stdout):
                return ExecutionResult(
                    command=command,
                    status="skipped",
                    reason=f"Tool is absent from sandbox image: {command.argv[0]}",
                )
            output = await self.workspace.exec(
                "python", "-c", _LAUNCH, command.cwd, *command.argv, timeout=timeout
            )
            clipped = (
                len(output.stdout) > self.max_output_bytes
                or len(output.stderr) > self.max_output_bytes
            )
            return ExecutionResult(
                command=command,
                status="passed" if output.exit_code == 0 else "failed",
                exit_code=output.exit_code,
                stdout=output.stdout[: self.max_output_bytes].decode(
                    "utf-8", errors="replace"
                ),
                stderr=output.stderr[: self.max_output_bytes].decode(
                    "utf-8", errors="replace"
                ),
                reason="Output truncated" if clipped else "",
            )
        except TimeoutError:
            return ExecutionResult(
                command=command,
                status="timeout",
                reason="Sandbox command timeout exceeded",
            )
        except Exception as exc:  # noqa: BLE001 -- turn provider errors into per-command results
            return ExecutionResult(
                command=command,
                status="error",
                reason=f"Sandbox execution failed ({type(exc).__name__})",
            )

    async def execute_many(
        self, commands: list[CommandPlan], *, timeout: float | None = None
    ) -> list[ExecutionResult]:
        return [await self.execute(command, timeout=timeout) for command in commands]

    async def resolve_project(
        self, project: ProjectAnalysis
    ) -> list[DependencyResolution]:
        """Evaluate build metadata and dependency graphs using sandbox toolchains.

        Each resolver reports partial or unavailable results instead of treating
        an empty/error report as a successfully resolved dependency graph.
        """
        results = []
        names = {
            source.rsplit("/", 1)[-1]: source
            for source in project.manifests + project.lockfiles
        }
        if any(name in names for name in ("pyproject.toml", "setup.py", "setup.cfg")):
            results.append(await self._python_metadata(project, names))
        if "pom.xml" in names:
            results.append(await self._maven(project, names["pom.xml"]))
        if any(name in names for name in ("build.gradle", "build.gradle.kts")):
            results.append(
                await self._gradle(
                    project, names.get("build.gradle", names.get("build.gradle.kts"))
                )
            )
        if "bun.lockb" in names:
            results.append(await self._bun_binary(project, names["bun.lockb"]))
        if "package.json" in names:
            candidates = [
                manager
                for manager in project.package_managers
                if manager in {"npm", "pnpm", "yarn", "bun"}
            ]
            declared = project.runtime_constraints.get("packageManager", "").split(
                "@", 1
            )[0]
            if declared in {"npm", "pnpm", "yarn", "bun"}:
                manager = declared
            elif len(candidates) <= 1:
                manager = candidates[0] if candidates else "npm"
            else:
                manager = None
            if manager:
                results.append(
                    await self._npm(project, names["package.json"], manager=manager)
                )
            else:
                results.append(
                    DependencyResolution(
                        ecosystem="Node",
                        method="package-manager-selection",
                        status="unavailable",
                        diagnostics=[
                            "Conflicting package managers; no installer selected"
                        ],
                    )
                )
        return results

    async def _run_resolution(self, project, argv, source):
        return await self.execute(
            CommandPlan(
                kind="build",
                argv=argv,
                cwd=project.root,
                source=source,
                reason="Offline dependency inspection",
            )
        )

    @staticmethod
    def _failure(output, ecosystem, method):
        status = (
            "unavailable"
            if output.status == "skipped"
            else "timeout"
            if output.status == "timeout"
            else "failed"
        )
        diagnostics = output.reason or (output.stderr or output.stdout)[-4000:]
        if any(
            phrase in diagnostics.lower()
            for phrase in (
                "offline mode",
                "no cached version",
                "has not been downloaded",
                "enotcached",
                "err_pnpm_no_offline_meta",
                "err_pnpm_no_offline_tarball",
                "has been blocked because of your configuration settings",
                "no candidates found",
                "no cached manifest",
                "no cached package",
            )
        ):
            status = "unavailable"
        return DependencyResolution(
            ecosystem=ecosystem,
            method=method,
            status=status,
            diagnostics=[diagnostics],
        )

    @staticmethod
    def _json_output(output):
        if output.reason == "Output truncated":
            raise ValueError("Dependency report exceeded output limit")
        records = [
            line[len("AEGIS_JSON:") :]
            for line in output.stdout.splitlines()
            if line.startswith("AEGIS_JSON:")
        ]
        if not records:
            raise ValueError("Missing structured dependency report")
        return json.loads(records[-1])

    async def _python_metadata(self, project, names):
        source = next(
            names[name]
            for name in ("pyproject.toml", "setup.py", "setup.cfg")
            if name in names
        )
        directory = "/workspace/.aegis-report-" + uuid4().hex
        output = await self._run_resolution(
            project, ["python", "-c", PYTHON_METADATA, directory], source
        )
        if output.status != "passed":
            return self._failure(output, "Python", "build-backend-metadata")
        result = DependencyResolution(
            ecosystem="Python", method="build-backend-metadata", status="completed"
        )
        try:
            data = self._json_output(output)
            installed = {canonicalize_name(k): v for k, v in data["installed"].items()}
            seen = set()
            pending = [
                (data.get("name") or project.root, item, frozenset())
                for item in data["requires"]
            ]
            inventory_names = set()
            while pending and len(seen) < 10000:
                parent, raw, active_extras = pending.pop()
                requirement = Requirement(raw)
                marker = str(requirement.marker) if requirement.marker else None
                scope = "optional" if marker and "extra" in marker else "runtime"
                if parent == (data.get("name") or project.root):
                    result.dependencies.append(
                        Dependency(
                            name=requirement.name,
                            version=requirement.url
                            or str(requirement.specifier)
                            or None,
                            ecosystem="Python",
                            scope=scope,
                            manifest=source,
                            marker=marker,
                        )
                    )
                if requirement.marker and not any(
                    requirement.marker.evaluate(data["environment"] | {"extra": extra})
                    for extra in active_extras | {""}
                ):
                    continue
                name = canonicalize_name(requirement.name)
                item = installed.get(name)
                if (
                    item is None
                    or not requirement.specifier.contains(
                        item["version"], prereleases=True
                    )
                    or requirement.url
                ):
                    result.diagnostics.append(
                        f"Not installed or incompatible: {requirement}"
                    )
                    result.status = "partial"
                    continue
                version = item["version"]
                result.edges.append(
                    DependencyEdge(
                        parent=parent, child=f"{name}@{version}", scope=scope
                    )
                )
                context = (name, frozenset(requirement.extras))
                if context in seen:
                    continue
                seen.add(context)
                if name not in inventory_names:
                    inventory_names.add(name)
                    result.dependencies.append(
                        Dependency(
                            name=name,
                            version=version,
                            ecosystem="Python",
                            scope="installed",
                            manifest=source,
                            resolved=True,
                        )
                    )
                pending.extend(
                    (f"{name}@{version}", raw, frozenset(requirement.extras))
                    for raw in item["requires"]
                )
            if pending:
                result.status = "partial"
                result.diagnostics.append("Python dependency traversal limit reached")
        except (ValueError, TypeError, KeyError, InvalidRequirement) as exc:
            result.status = "failed"
            result.diagnostics.append(
                f"Invalid Python metadata report: {type(exc).__name__}"
            )
        return result

    async def _maven(self, project, source):
        # Both goals use explicit versions seeded in the image, not plugin prefix lookup.
        report = ".aegis-maven-tree-" + uuid4().hex + ".json"
        output = await self._run_resolution(
            project,
            [
                "mvn",
                "-B",
                "-o",
                "org.apache.maven.plugins:maven-dependency-plugin:3.8.1:tree",
                "-DoutputType=json",
                "-DoutputFile=" + report,
            ],
            source,
        )
        if output.status != "passed":
            return self._failure(output, "Java", "maven-dependency-tree")
        result = DependencyResolution(
            ecosystem="Java", method="maven-dependency-tree", status="completed"
        )
        try:
            # A reactor can write one report per module; gather every generated report.
            script = "import json,pathlib,sys; root=pathlib.Path('.').resolve(); reports=[];\nfor p in root.rglob(sys.argv[1]):\n if not p.is_symlink() and p.resolve().is_relative_to(root): reports.append(json.loads(p.read_text()))\nprint('AEGIS_JSON:'+json.dumps(reports))"
            gathered = await self._run_resolution(
                project, ["python", "-c", script, report], source
            )
            if gathered.status != "passed":
                return self._failure(gathered, "Java", "maven-dependency-tree")
            reports = self._json_output(gathered)
            if not reports:
                raise ValueError("Maven produced no module reports")

            def visit(node, parent=None, depth=0):
                if depth > 100 or len(result.dependencies) > 10000:
                    raise ValueError("Maven graph traversal limit reached")
                name = f"{node['groupId']}:{node['artifactId']}"
                identity = f"{name}@{node['version']}"
                if parent is not None:
                    scope = node.get("scope") or "compile"
                    result.dependencies.append(
                        Dependency(
                            name=name,
                            version=node["version"],
                            ecosystem="Java",
                            scope=scope,
                            manifest=source,
                            resolved=True,
                        )
                    )
                    result.edges.append(
                        DependencyEdge(parent=parent, child=identity, scope=scope)
                    )
                for child in node.get("children", []):
                    visit(child, identity, depth + 1)

            for tree in reports:
                visit(tree)
        except (ValueError, TypeError, KeyError) as exc:
            result.status = "failed"
            result.diagnostics.append(f"Invalid Maven report: {type(exc).__name__}")
        return result

    async def _gradle(self, project, source):
        name = ".aegis-init-" + uuid4().hex + ".gradle"
        path = name if project.root == "." else project.root + "/" + name
        await self.workspace.write_file(path, GRADLE_INSPECT.encode())
        output = await self._run_resolution(
            project,
            [
                "gradle",
                "--offline",
                "--no-daemon",
                "--console=plain",
                "--max-workers=1",
                "-Dorg.gradle.jvmargs=-Xmx384m",
                "--init-script",
                name,
                "aegisInspectDependencies",
            ],
            source,
        )
        if output.status != "passed":
            return self._failure(output, "Java", "gradle-resolution-result")
        result = DependencyResolution(
            ecosystem="Java", method="gradle-resolution-result", status="completed"
        )
        try:
            data = self._json_output(output)
            result.dependencies = [
                Dependency(**item, ecosystem="Java", manifest=source, resolved=True)
                for item in data["dependencies"]
            ]
            result.edges = [DependencyEdge(**item) for item in data["edges"]]
            result.diagnostics = data["errors"]
            if result.diagnostics:
                result.status = "partial"
        except (ValueError, TypeError, KeyError) as exc:
            result.status = "failed"
            result.diagnostics.append(f"Invalid Gradle report: {type(exc).__name__}")
        return result

    async def _bun_binary(self, project, source):
        from ..analysis.dependency_parser import parse_yarn_lock

        output = await self._run_resolution(project, ["bun", "bun.lockb"], source)
        if output.status != "passed":
            return self._failure(output, "Node", "bun-binary-lock")
        if output.reason == "Output truncated":
            return DependencyResolution(
                ecosystem="Node",
                method="bun-binary-lock",
                status="failed",
                diagnostics=["Binary lock report exceeded output limit"],
            )
        dependencies = parse_yarn_lock(output.stdout, source)
        uncertain = any(not dependency.resolved for dependency in dependencies)
        return DependencyResolution(
            ecosystem="Node",
            method="bun-binary-lock",
            status="partial" if uncertain else "completed",
            dependencies=dependencies,
            diagnostics=[
                "Local or non-registry lock references are not exact registry versions"
            ]
            if uncertain
            else [],
        )

    async def _npm(self, project, source, *, manager="npm"):
        lockfiles = {path.rsplit("/", 1)[-1] for path in project.lockfiles}
        classic = manager == "yarn" and (
            project.runtime_constraints.get("packageManager", "").startswith("yarn@1.")
            or project.runtime_constraints.get("yarn_lock_format") == "classic"
        )
        commands = {
            "npm": [
                "npm",
                "ci"
                if lockfiles & {"package-lock.json", "npm-shrinkwrap.json"}
                else "install",
                "--offline",
                "--ignore-scripts",
                "--no-audit",
                "--no-fund",
            ],
            "pnpm": [
                "pnpm",
                "install",
                "--offline",
                "--ignore-scripts",
                "--frozen-lockfile"
                if "pnpm-lock.yaml" in lockfiles
                else "--no-frozen-lockfile",
                "--store-dir",
                "/workspace/.aegis-cache/pnpm",
            ],
            "yarn": ["yarn", "install", "--mode=skip-build"]
            + (["--immutable"] if "yarn.lock" in lockfiles else []),
            "bun": ["bun", "install", "--offline", "--ignore-scripts"]
            + (["--frozen-lockfile"] if lockfiles & {"bun.lock", "bun.lockb"} else []),
        }
        method = manager + "-installed-tree"
        if classic:
            commands["yarn"] = [
                "yarn1",
                "install",
                "--offline",
                "--ignore-scripts",
                "--cache-folder",
                "/workspace/.aegis-cache/yarn1",
            ] + (["--frozen-lockfile"] if "yarn.lock" in lockfiles else [])
        installation = await self._run_resolution(
            project,
            commands[manager],
            source,
        )
        if installation.status != "passed":
            return self._failure(installation, "Node", method)
        if manager == "yarn" and not classic:
            pnp = await self._run_resolution(
                project, ["yarn", "node", "-e", YARN_PNP], source
            )
            if any(line.startswith("AEGIS_JSON:") for line in pnp.stdout.splitlines()):
                try:
                    data = self._json_output(pnp)
                    return DependencyResolution(
                        ecosystem="Node",
                        method="yarn-pnp-graph",
                        status="partial" if data["errors"] else "completed",
                        dependencies=[
                            Dependency(
                                **item, ecosystem="Node", manifest=source, resolved=True
                            )
                            for item in data["dependencies"]
                        ],
                        edges=[DependencyEdge(**edge) for edge in data["edges"]],
                        diagnostics=data["errors"],
                    )
                except (ValueError, TypeError, KeyError):
                    return DependencyResolution(
                        ecosystem="Node",
                        method="yarn-pnp-graph",
                        status="failed",
                        diagnostics=["Invalid Yarn PnP graph"],
                    )
        output = await self._run_resolution(project, ["node", "-e", NODE_TREE], source)
        if output.status != "passed":
            return self._failure(output, "Node", method)
        result = DependencyResolution(
            ecosystem="Node",
            method=method,
            status="completed" if output.status == "passed" else "partial",
        )
        try:
            if output.reason == "Output truncated":
                raise ValueError("npm graph exceeded output limit")
            data = self._json_output(output)
            result.dependencies = [
                Dependency(**item, ecosystem="Node", manifest=source, resolved=True)
                for item in data["dependencies"]
            ]
            result.edges = [DependencyEdge(**item) for item in data["edges"]]
            result.diagnostics = data["errors"]
            if result.diagnostics:
                result.status = "partial"

        except (ValueError, TypeError, KeyError) as exc:
            result.status = "failed"
            result.diagnostics.append(f"Invalid npm tree: {type(exc).__name__}")
        return result


async def resolve_repository_analysis(
    repository_path, report=None, *, workspace_root=None, policy=None
):
    """Resolve an existing clone in one disposable sandbox without host edits."""
    import asyncio

    from ..analysis.repo_analyzer import analyze_repository
    from .docker_runner import create_sandbox
    from .policies import SandboxPolicy

    if report is None:
        report = await asyncio.to_thread(analyze_repository, repository_path)
    try:
        async with await create_sandbox(
            repository_path,
            workspace_root=workspace_root,
            policy=policy or SandboxPolicy.polyglot(),
        ) as workspace:
            executor = SandboxExecutor(workspace, max_output_bytes=1024 * 1024)
            for project in report.projects[:20]:
                project.resolutions = await executor.resolve_project(project)
                for resolution in project.resolutions:
                    project.dependencies.extend(resolution.dependencies)
            if len(report.projects) > 20:
                report.truncated = True
                report.warnings.append("Runtime resolution limited to 20 projects")
            resolutions = [
                resolution
                for project in report.projects
                for resolution in project.resolutions
            ]
            report.resolution_status = (
                "completed"
                if resolutions
                and all(r.status == "completed" for r in resolutions)
                and len(report.projects) <= 20
                else "partial"
                if resolutions
                else "unavailable"
            )
            if not resolutions:
                report.warnings.append(
                    "No supported runtime dependency resolver found for this repository"
                )
    except Exception as exc:  # noqa: BLE001 -- sandbox availability must not discard static analysis
        report.resolution_status = (
            "partial"
            if any(project.resolutions for project in report.projects)
            else "unavailable"
        )
        report.warnings.append(
            f"Sandbox dependency resolution unavailable ({type(exc).__name__}); static inventory retained"
        )
    return report
