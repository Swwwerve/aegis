"""Read manifests as data. Never import setup.py or execute Gradle/build scripts.

Declared constraints and resolved lock entries are deliberately separate.
Dynamic expressions remain unresolved, rather than becoming invented versions.
"""

import configparser
import json
import re
import tomllib
import xml.etree.ElementTree as ET
from pathlib import Path

import json5
import yaml
from packaging.requirements import InvalidRequirement, Requirement

from ..schemas.repository import Dependency

MANIFESTS = {
    "pyproject.toml",
    "Pipfile",
    "setup.cfg",
    "setup.py",
    "package.json",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "libs.versions.toml",
}
LOCKFILES = {
    "poetry.lock",
    "uv.lock",
    "Pipfile.lock",
    "package-lock.json",
    "npm-shrinkwrap.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "bun.lock",
    "bun.lockb",
    "gradle.lockfile",
}
MAX_MANIFEST_BYTES = 1024 * 1024


def is_manifest(name: str) -> bool:
    return name in MANIFESTS or bool(
        re.fullmatch(r"(?:requirements|constraints)(?:[._-].*)?\.txt", name)
    )


def read_text(path: Path) -> str:
    with path.open("rb") as stream:
        data = stream.read(MAX_MANIFEST_BYTES + 1)
    if len(data) > MAX_MANIFEST_BYTES:
        raise ValueError("file exceeds 1 MiB analysis limit")
    return data.decode("utf-8-sig")


def parse_dependencies(
    path: Path,
    root: Path,
    *,
    _seen: set[Path] | None = None,
    _depth: int = 0,
    _requirements: bool = False,
    _constraint: bool = False,
) -> tuple[list[Dependency], dict, list[str]]:
    """Return dependency inventory, parsed metadata, and actionable warnings."""
    source = path.relative_to(root).as_posix()
    dependencies: list[Dependency] = []
    warnings: list[str] = []
    metadata: dict = {}
    seen = set() if _seen is None else _seen

    def add(
        name,
        version=None,
        *,
        ecosystem="Python",
        scope="runtime",
        marker=None,
        resolved=False,
    ):
        if len(dependencies) >= 10000:
            if "Dependency inventory limited to 10000 entries" not in warnings:
                warnings.append("Dependency inventory limited to 10000 entries")
            return
        dependencies.append(
            Dependency(
                name=str(name),
                version=str(version) if version is not None else None,
                ecosystem=ecosystem,
                scope=scope,
                manifest=source,
                marker=marker,
                resolved=resolved,
            )
        )

    def requirement(value, scope):
        if not isinstance(value, str):
            warnings.append(f"{source}: unsupported requirement {value!r}")
            return
        try:
            parsed = Requirement(value)
            add(
                parsed.name,
                parsed.url or str(parsed.specifier) or None,
                scope=scope,
                marker=str(parsed.marker) if parsed.marker else None,
            )
        except InvalidRequirement:
            warnings.append(f"{source}: unresolved requirement {value[:200]!r}")

    try:
        resolved = path.resolve(strict=True)
        if path.name.startswith(".env") or ".git" in path.relative_to(root).parts:
            raise ValueError(
                "secret files and Git metadata cannot be requirements includes"
            )
        if not resolved.is_relative_to(root.resolve()) or any(
            p.is_symlink() for p in [path, *path.parents] if p != root.parent
        ):
            raise ValueError("manifest path escapes repository or uses symlink")
        if resolved in seen or _depth > 20 or len(seen) >= 100:
            raise ValueError("requirements include cycle or traversal limit")
        seen.add(resolved)
        name = path.name
        if name == "bun.lockb":
            return [], {}, [f"{source}: binary lockfile requires sandbox Bun decoding"]
        text = read_text(path)
        if name == "gradle.lockfile":
            for line in text.splitlines():
                if line.strip() and not line.startswith(("#", "empty=")):
                    coordinate, _, configurations = line.partition("=")
                    parts = coordinate.split(":")
                    if len(parts) == 3:
                        add(
                            ":".join(parts[:2]),
                            parts[2],
                            ecosystem="Java",
                            scope=configurations or "locked",
                            resolved=True,
                        )
                    else:
                        warnings.append(f"{source}: invalid Gradle lock entry")
        elif name == "pnpm-lock.yaml":
            metadata = load_yaml(text)
            for key, item in metadata.get("packages", {}).items():
                item = item or {}
                coordinate = str(key).lstrip("/").split("(", 1)[0]
                match = re.match(r"^(.+)@([^@/]+)$", coordinate) or re.match(
                    r"^(.+)/([^/]+)$", coordinate
                )
                if match:
                    add(
                        item.get("name") or match[1],
                        item.get("version") or match[2],
                        ecosystem="Node",
                        scope="locked",
                        resolved=True,
                    )
                else:
                    warnings.append(
                        f"{source}: non-registry pnpm entry needs package-manager evaluation: {key}"
                    )
        elif name == "yarn.lock":
            metadata["format"] = "berry" if "__metadata:" in text else "classic"
            dependencies.extend(parse_yarn_lock(text, source))
        elif name == "bun.lock":
            metadata = json5.loads(text)
            for alias, item in metadata.get("packages", {}).items():
                coordinate = item[0] if isinstance(item, list) and item else ""
                match = re.match(r"^(.+)@([^@]+)$", coordinate)
                if match and not match[2].startswith(("workspace:", "file:", "link:")):
                    add(
                        match[1],
                        match[2],
                        ecosystem="Node",
                        scope="locked",
                        resolved=True,
                    )
                else:
                    warnings.append(
                        f"{source}: local or unsupported Bun entry: {alias}"
                    )
        elif name == "bun.lockb":
            warnings.append(f"{source}: binary lockfile requires sandbox Bun decoding")
        elif name == "libs.versions.toml":
            metadata = tomllib.loads(text)
            versions = metadata.get("versions", {})
            for alias, item in metadata.get("libraries", {}).items():
                if isinstance(item, str):
                    parts = item.split(":")
                    add(
                        ":".join(parts[:2]),
                        parts[2] if len(parts) > 2 else None,
                        ecosystem="Java",
                        scope=f"catalog:{alias}",
                    )
                elif isinstance(item, dict):
                    module = (
                        item.get("module")
                        or f"{item.get('group', '')}:{item.get('name', '')}"
                    )
                    version = item.get("version")
                    if isinstance(version, dict):
                        version = (
                            versions.get(version.get("ref"))
                            or version.get("strictly")
                            or version.get("require")
                            or version.get("prefer")
                        )
                    if isinstance(version, dict):
                        version = (
                            version.get("strictly")
                            or version.get("require")
                            or version.get("prefer")
                        )
                    add(module, version, ecosystem="Java", scope=f"catalog:{alias}")
        elif name in {"pyproject.toml", "Pipfile", "uv.lock", "poetry.lock"}:
            metadata = tomllib.loads(text)
            if name == "pyproject.toml":
                for section in ("project", "build-system", "tool", "dependency-groups"):
                    if section in metadata and not isinstance(metadata[section], dict):
                        raise ValueError(f"{section} must be a table")
            if name == "pyproject.toml":
                project = metadata.get("project", {})
                for item in project.get("dependencies", []):
                    requirement(item, "runtime")
                for group, items in project.get("optional-dependencies", {}).items():
                    for item in items:
                        requirement(item, f"optional:{group}")
                groups = metadata.get("dependency-groups", {})
                expanded: set[tuple[str, str]] = set()

                def expand(group, trail, original):
                    if len(expanded) >= 10000:
                        warning = f"{source}: dependency group expansion limit reached"
                        if warning not in warnings:
                            warnings.append(warning)
                        return
                    if group in trail:
                        warnings.append(f"{source}: cyclic dependency group {group}")
                        return
                    if len(trail) > 20:
                        warnings.append(
                            f"{source}: dependency group depth limit reached"
                        )
                        return
                    if (group, original) in expanded:
                        return
                    expanded.add((group, original))
                    if group not in groups:
                        warnings.append(f"{source}: missing dependency group {group}")
                    for item in groups.get(group, []):
                        if isinstance(item, dict) and "include-group" in item:
                            expand(item["include-group"], trail | {group}, original)
                        else:
                            requirement(item, f"group:{original}")

                for group in groups:
                    expand(group, set(), group)
                for item in metadata.get("build-system", {}).get("requires", []):
                    requirement(item, "build")
                poetry = metadata.get("tool", {}).get("poetry", {})
                for group, items in [
                    ("runtime", poetry.get("dependencies", {})),
                    ("dev", poetry.get("dev-dependencies", {})),
                ] + [
                    (f"group:{group}", data.get("dependencies", {}))
                    for group, data in poetry.get("group", {}).items()
                ]:
                    for dep, value in items.items():
                        if dep.lower() != "python":
                            add(
                                dep,
                                value.get("version")
                                or value.get("git")
                                or value.get("path")
                                if isinstance(value, dict)
                                else value,
                                scope=group,
                                marker=value.get("markers")
                                if isinstance(value, dict)
                                else None,
                            )
                if project.get("dynamic"):
                    warnings.append(
                        f"{source}: dynamic metadata requires sandbox evaluation: {project['dynamic']}"
                    )
            elif name == "Pipfile":
                if not isinstance(metadata.get("requires", {}), dict):
                    raise ValueError("Pipfile requires must be a table")
                for section in ("packages", "dev-packages"):
                    for dep, value in metadata.get(section, {}).items():
                        add(
                            dep,
                            value.get("version") if isinstance(value, dict) else value,
                            scope="dev" if section == "dev-packages" else "runtime",
                        )
            else:
                for item in metadata.get("package", []):
                    add(
                        item["name"], item.get("version"), scope="locked", resolved=True
                    )
        elif name in {
            "package.json",
            "package-lock.json",
            "npm-shrinkwrap.json",
            "Pipfile.lock",
        }:
            metadata = json.loads(text)
            if not isinstance(metadata, dict):
                raise ValueError("manifest must be an object")
            if name == "package.json":
                for section in (
                    "dependencies",
                    "devDependencies",
                    "peerDependencies",
                    "optionalDependencies",
                    "scripts",
                    "engines",
                ):
                    if section in metadata and not isinstance(metadata[section], dict):
                        raise ValueError(f"{section} must be an object")
                for section, scope in (
                    ("dependencies", "runtime"),
                    ("devDependencies", "dev"),
                    ("peerDependencies", "peer"),
                    ("optionalDependencies", "optional"),
                ):
                    for dep, version in metadata.get(section, {}).items():
                        add(dep, version, ecosystem="Node", scope=scope)
            elif name == "Pipfile.lock":
                for section in ("default", "develop"):
                    for dep, value in metadata.get(section, {}).items():
                        add(
                            dep,
                            value.get("version"),
                            scope="dev" if section == "develop" else "runtime",
                            marker=value.get("markers"),
                            resolved=True,
                        )
            elif "packages" in metadata:
                for location, item in metadata["packages"].items():
                    if "node_modules/" in location and not item.get("link"):
                        add(
                            item.get("name") or location.rsplit("node_modules/", 1)[1],
                            item.get("version"),
                            ecosystem="Node",
                            scope="locked",
                            resolved=True,
                        )
            else:

                def locked(items):
                    for dep, item in items.items():
                        add(
                            dep,
                            item.get("version"),
                            ecosystem="Node",
                            scope="locked",
                            resolved=True,
                        )
                        locked(item.get("dependencies", {}))

                locked(metadata.get("dependencies", {}))
        elif name == "setup.cfg":
            cfg = configparser.ConfigParser(interpolation=None)
            cfg.read_string(text)
            metadata = {section: dict(cfg[section]) for section in cfg.sections()}
            for item in cfg.get(
                "options", "install_requires", fallback=""
            ).splitlines():
                if item.strip():
                    requirement(item.strip(), "runtime")
            if cfg.has_section("options.extras_require"):
                for group, items in cfg["options.extras_require"].items():
                    for item in items.splitlines():
                        if item.strip():
                            requirement(item.strip(), f"optional:{group}")
        elif _requirements or name.startswith(("requirements", "constraints")):
            metadata["includes"] = []
            for line in text.replace("\\\n", "").splitlines():
                line = re.split(r"\s+#", line, 1)[0].strip()
                if not line or line.startswith("#"):
                    continue
                match = re.match(
                    r"^(?:-r\s*|--requirement(?:=|\s+)|-c\s*|--constraint(?:=|\s+))(.+)$",
                    line,
                )
                if match:
                    metadata["includes"].append(match[1].strip())
                    target = path.parent / match[1].strip()
                    child_deps, _, child_warnings = parse_dependencies(
                        target,
                        root,
                        _seen=seen,
                        _depth=_depth + 1,
                        _requirements=True,
                        _constraint=_constraint
                        or line.startswith(("-c", "--constraint")),
                    )
                    dependencies.extend(child_deps)
                    warnings.extend(child_warnings)
                elif line.startswith("-"):
                    warnings.append(
                        f"{source}: installer option or editable requirement not evaluated: {line[:200]}"
                    )
                else:
                    requirement(
                        line.split(" --hash=", 1)[0],
                        "constraint"
                        if _constraint or name.startswith("constraints")
                        else "runtime",
                    )
        elif name == "pom.xml":
            if re.search(r"<!\s*(?:DOCTYPE|ENTITY)", text, re.IGNORECASE):
                raise ValueError("XML entities and DTDs are forbidden")
            tree = ET.fromstring(text)
            for element in tree.iter():
                element.tag = element.tag.split("}")[-1]
            properties = {
                item.tag: item.text or "" for item in tree.findall("./properties/*")
            }

            def interpolate(value):
                for _ in range(10):
                    updated = re.sub(
                        r"\$\{([^}]+)\}", lambda m: properties.get(m[1], m[0]), value
                    )
                    if updated == value:
                        break
                    value = updated
                return value

            metadata["modules"] = [
                item.text for item in tree.findall("./modules/module")
            ]
            metadata["properties"] = properties
            for section, scope in (
                ("./dependencies/dependency", "compile"),
                ("./dependencyManagement/dependencies/dependency", "managed"),
            ):
                for item in tree.findall(section):
                    dep = f"{interpolate(item.findtext('groupId', ''))}:{item.findtext('artifactId', '')}"
                    version = interpolate(item.findtext("version", "")) or None
                    add(
                        dep,
                        version,
                        ecosystem="Java",
                        scope=scope
                        if scope == "managed"
                        else item.findtext("scope", scope),
                    )
                    if version is None or "${" in version:
                        warnings.append(
                            f"{source}: {dep} version requires parent/BOM/property resolution"
                        )
        elif name.startswith("build.gradle"):
            # Literal coordinates only. Gradle is executable code; this is not a resolver.
            clean = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
            clean = re.sub(r"^\s*//[^\n]*", "", clean, flags=re.MULTILINE)
            for match in re.finditer(
                r"\b(implementation|api|compileOnly|runtimeOnly|testImplementation|testRuntimeOnly|classpath)\s*\(?\s*['\"]([^'\"]+)['\"]",
                clean,
            ):
                pieces = match[2].split(":")
                if len(pieces) >= 2:
                    add(
                        ":".join(pieces[:2]),
                        pieces[2] if len(pieces) > 2 else None,
                        ecosystem="Java",
                        scope=match[1],
                    )
            warnings.append(
                f"{source}: Gradle inventory is partial; catalogs, plugins and computed dependencies need sandbox resolution"
            )
        elif name == "setup.py":
            warnings.append(
                f"{source}: executable metadata not evaluated on host; use pyproject.toml or sandbox inspection"
            )
        else:
            warnings.append(
                f"{source}: lockfile detected; resolved inventory is not supported for this format"
            )
    except (
        ValueError,
        OSError,
        UnicodeError,
        TypeError,
        KeyError,
        AttributeError,
        RecursionError,
        configparser.Error,
        ET.ParseError,
        yaml.YAMLError,
    ) as exc:
        metadata = {}
        warnings.append(
            f"{source}: cannot fully parse manifest ({type(exc).__name__}: {str(exc)[:200]})"
        )
    return dependencies, metadata, warnings


def load_yaml(text: str) -> dict:
    """Do not allow YAML alias amplification or arbitrary object construction."""
    if any(isinstance(token, yaml.tokens.AliasToken) for token in yaml.scan(text)):
        raise ValueError("YAML aliases are not supported in lockfiles")
    data = yaml.safe_load(text) or {}
    if not isinstance(data, dict):
        raise TypeError("Lockfile must contain a mapping")
    return data


def parse_yarn_lock(text: str, source: str) -> list[Dependency]:
    """Yarn Classic and Berry npm resolutions, including scoped/aliased packages."""
    entries = []
    if "__metadata:" in text:
        data = load_yaml(text)
        for key, item in data.items():
            if key == "__metadata" or not isinstance(item, dict):
                continue
            resolution = item.get("resolution", "")
            match = re.match(r"^(.+)@npm:(.+)$", resolution)
            if match:
                entries.append((match[1], str(item.get("version") or match[2])))
    else:
        selectors = None
        for line in text.splitlines():
            if (
                line
                and not line[0].isspace()
                and line.endswith(":")
                and not line.startswith("#")
            ):
                selectors = line[:-1]
            elif selectors is not None:
                match = re.match(r'\s+version\s+["\']?([^"\'\s]+)', line)
                if match:
                    selector = selectors.split(", ", 1)[0].strip("\"'")
                    name = selector.rsplit("@", 1)[0]
                    if name:
                        entries.append((name, match[1]))
                    selectors = None
    return [
        Dependency(
            name=name,
            version=version,
            ecosystem="Node",
            scope="locked",
            manifest=source,
            resolved=bool(
                re.fullmatch(r"\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.+-]+)?", version)
            ),
        )
        for name, version in dict.fromkeys(entries)
    ]
