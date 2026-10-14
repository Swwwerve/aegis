"""Bounded static usage evidence; never equates package calls with exploitation."""

import ast
import os
import re
from pathlib import Path

from ..schemas.vulnerability import UsageEvidence, VulnerabilityFinding

IGNORED = {
    ".git",
    ".venv",
    "venv",
    "node_modules",
    ".yarn",
    "__pycache__",
    "dist",
    "build",
    "target",
    "vendor",
    "coverage",
    "workspaces",
    ".gradle",
}
MODULES = {
    "pyyaml": "yaml",
    "beautifulsoup4": "bs4",
    "scikit-learn": "sklearn",
    "pillow": "PIL",
    "python-dateutil": "dateutil",
}


def _symbol(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        root = _symbol(node.value)
        return f"{root}.{node.attr}" if root else None
    return None


def _python_sites(text, module):
    tree = ast.parse(text)
    parents = {
        child: parent
        for parent in ast.walk(tree)
        for child in ast.iter_child_nodes(parent)
    }

    def module_import(node):
        # Exclude local/class imports rather than assuming they bind globally.
        parent = parents.get(node)
        while parent is not None:
            if isinstance(
                parent, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
            ):
                return False
            parent = parents.get(parent)
        return True

    bindings = {}
    imports = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import) and module_import(node):
            for alias in node.names:
                if alias.name == module or alias.name.startswith(module + "."):
                    local = alias.asname or alias.name.split(".")[0]
                    bindings.setdefault(local, set()).add(
                        alias.name if alias.asname else module
                    )
                    imports.append((node.lineno, alias.name))
        elif (
            isinstance(node, ast.ImportFrom)
            and module_import(node)
            and node.level == 0
            and node.module
            and (node.module == module or node.module.startswith(module + "."))
        ):
            for alias in node.names:
                if alias.name != "*":
                    bindings.setdefault(alias.asname or alias.name, set()).add(
                        f"{node.module}.{alias.name}"
                    )
                    imports.append((node.lineno, f"{node.module}.{alias.name}"))
    # Conservative: an alias assigned/shadowed anywhere in the file is ambiguous.
    # Do not attribute it to a dependency, even outside that shadowing scope.
    ambiguous = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            ambiguous.add(node.id)
        elif isinstance(node, ast.arg):
            ambiguous.add(node.arg)
        elif (
            isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
            or isinstance(node, ast.ExceptHandler)
            and node.name
        ):
            ambiguous.add(node.name)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if not (alias.name == module or alias.name.startswith(module + ".")):
                    ambiguous.add(alias.asname or alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom) and (
            node.level
            or not node.module
            or not (node.module == module or node.module.startswith(module + "."))
        ):
            ambiguous.update(a.asname or a.name for a in node.names)
    calls = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = _symbol(node.func)
            if not name:
                continue
            root, _, tail = name.partition(".")
            if root in bindings and root not in ambiguous and len(bindings[root]) == 1:
                qualified = next(iter(bindings[root])) + ("." + tail if tail else "")
                calls.append((node.lineno, qualified))
    return imports, calls


def _node_sites(text, package):
    # Lightweight evidence only: exports, dynamic imports and runtime aliasing
    # need a language server or instrumentation and are explicitly not inferred.
    imports = []
    bindings = {}
    pattern = r"(?:\bimport\s+([^;\n]+?)\s+from\s*|\b(?:const|let|var)\s+(\w+)\s*=\s*require\s*\()(['\"])([^'\"]+)\3"
    # Reject imports inside comments/strings by comparing to lexical code mask.
    mask = _code_mask(text)
    for match in re.finditer(pattern, text):
        if not mask[match.start() : match.start() + 6].strip():
            continue
        target = match[4]
        if target != package and not target.startswith(package + "/"):
            continue
        line = text.count("\n", 0, match.start()) + 1
        imports.append((line, target))
        clause = (match[1] or match[2]).strip()
        if match[2] or re.fullmatch(r"\w+", clause):
            bindings[clause] = target
        elif clause.startswith("* as "):
            bindings[clause[5:].strip()] = target
        elif clause.startswith("{") and clause.endswith("}"):
            for item in clause[1:-1].split(","):
                pieces = re.split(r"\s+as\s+", item.strip())
                if all(re.fullmatch(r"\w+", p) for p in pieces):
                    bindings[pieces[-1]] = f"{target}.{pieces[0]}"
    calls = []
    for local, qualified in bindings.items():
        for match in re.finditer(
            r"(?<![\w$.])" + re.escape(local) + r"((?:\s*\.\s*\w+)*)\s*\(", mask
        ):
            suffix = re.sub(r"\s", "", match[1])
            calls.append((text.count("\n", 0, match.start()) + 1, qualified + suffix))
    return imports, calls


def _code_mask(text):
    # Preserve offsets/newlines while masking comments, strings and templates.
    return re.sub(
        r"//[^\n]*|/\*[\s\S]*?\*/|'(?:\\.|[^'\\])*'|\"(?:\\.|[^\"\\])*\"|`(?:\\.|[^`\\])*`",
        lambda m: re.sub(r"[^\n]", " ", m[0]),
        text,
    )


def analyze_usage(
    root: Path,
    findings: list[VulnerabilityFinding],
    *,
    max_files=2000,
    max_bytes=8_000_000,
):
    root = root.resolve()
    for finding in findings:
        finding.usage = UsageEvidence(
            status="analyzed",
            import_count=0,
            static_call_count=0,
            method="python_ast_import_aliases"
            if finding.ecosystem == "PyPI"
            else "node_lexical_imports",
            limitations=[
                "Static package call sites are not vulnerable-function reachability or runtime frequency.",
                "Dynamic calls, wrappers, vendored/transitive code and import aliases may be missed.",
            ],
        )
        if finding.ecosystem == "Maven":
            finding.usage.status = "unsupported"
            finding.usage.import_count, finding.usage.static_call_count = None, None
            finding.usage.method = "unsupported_maven_namespace_mapping"
            finding.usage.limitations.append(
                "Maven coordinates do not reliably identify Java namespaces; calls are unknown."
            )
        elif finding.ecosystem == "npm":
            finding.usage.limitations.append(
                "Node call counts are lexical heuristics; shadowing, regex literals and re-exports may affect counts."
            )
        else:
            finding.usage.limitations.append(
                "Python shadowed/reassigned aliases are excluded conservatively; distribution-to-module mapping is heuristic."
            )
    used_bytes = files = 0
    truncated = False
    for directory_index, (directory, dirs, names) in enumerate(
        os.walk(root, followlinks=False)
    ):
        if files >= max_files or used_bytes >= max_bytes or directory_index >= 10000:
            truncated = True
            break
        dirs[:] = sorted(
            d
            for d in dirs
            if d not in IGNORED
            and not (Path(directory) / d).is_symlink()
            and not getattr(Path(directory) / d, "is_junction", lambda: False)()
        )
        for name in sorted(names):
            path = Path(directory) / name
            extension = path.suffix
            if extension not in {".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}:
                continue
            if path.is_symlink() or not path.resolve().is_relative_to(root):
                continue
            if files >= max_files or used_bytes >= max_bytes:
                truncated = True
                break
            try:
                size = path.stat().st_size
                if size > 250_000 or size + used_bytes > max_bytes:
                    truncated = True
                    continue
                text = path.read_text(encoding="utf-8")
            except (OSError, UnicodeError):
                truncated = True
                continue
            files += 1
            used_bytes += size
            relative = path.relative_to(root).as_posix()
            cache = {}
            for finding in findings:
                if (extension == ".py") != (
                    finding.ecosystem == "PyPI"
                ) or finding.ecosystem == "Maven":
                    continue
                # Attribute source only to projects containing this version.
                roots = [Path(m).parent.as_posix() for m in finding.manifests] or ["."]
                if not any(path.is_relative_to(root / project) for project in roots):
                    continue
                candidates = {
                    Path(m).parent.as_posix()
                    for other in findings
                    if other.package == finding.package
                    and other.ecosystem == finding.ecosystem
                    for m in other.manifests
                    if path.is_relative_to(root / Path(m).parent)
                }
                if (
                    candidates
                    and max(candidates, key=lambda p: len(Path(p).parts)) not in roots
                ):
                    continue
                finding.usage.files_scanned += 1
                if finding.ecosystem == "PyPI":
                    module = MODULES.get(
                        finding.package, finding.package.replace("-", "_")
                    )
                    if any(
                        (root / project / (module + ".py")).exists()
                        or (root / project / module / "__init__.py").exists()
                        for project in roots
                    ):
                        finding.usage.truncated = True
                        finding.usage.limitations.append(
                            "Local module shadows the dependency import name; source attribution is unknown."
                        )
                        continue
                try:
                    if (finding.ecosystem, finding.package) not in cache:
                        cache[finding.ecosystem, finding.package] = (
                            _python_sites(
                                text,
                                MODULES.get(
                                    finding.package, finding.package.replace("-", "_")
                                ),
                            )
                            if extension == ".py"
                            else _node_sites(text, finding.package)
                        )
                    imports, calls = cache[finding.ecosystem, finding.package]
                except (SyntaxError, RecursionError, ValueError):
                    finding.usage.truncated = True
                    continue
                finding.usage.import_count += len(imports)
                finding.usage.static_call_count += len(calls)
                functions = {
                    f for e in finding.advisory_evidence for f in e.affected_functions
                }
                if functions and finding.ecosystem == "PyPI":
                    if finding.usage.affected_function_call_count is None:
                        finding.usage.affected_function_call_count = 0
                    finding.usage.affected_function_call_count += sum(
                        symbol in functions for _, symbol in calls
                    )
                for kind, rows in (("import", imports), ("call", calls)):
                    for line, symbol in rows:
                        if len(finding.usage.sites) < 100:
                            finding.usage.sites.append(
                                {
                                    "path": relative,
                                    "line": line,
                                    "symbol": symbol,
                                    "kind": kind,
                                }
                            )
    for finding in findings:
        finding.usage.truncated |= truncated
        if finding.usage.truncated:
            finding.usage.status = "partial"
        elif finding.usage.status != "unsupported" and not finding.usage.import_count:
            finding.usage.status = "no_static_evidence"
        elif finding.usage.static_call_count and any(
            other.package == finding.package
            and other.ecosystem == finding.ecosystem
            and other.installed_version != finding.installed_version
            and {Path(m).parent for m in other.manifests}
            & {Path(m).parent for m in finding.manifests}
            for other in findings
        ):
            finding.usage.status = "version_ambiguous"
            finding.usage.limitations.append(
                "Multiple versions share this project; package call sites cannot be attributed to a specific version."
            )
