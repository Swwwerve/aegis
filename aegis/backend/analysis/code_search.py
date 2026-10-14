"""Read-only, bounded repository retrieval using ripgrep and Tree-sitter.

Paths are inventoried first; ignored directories, symlinks and non-context files
are never handed to ripgrep. Repository scripts are never executed on the host.
"""

import importlib
import json
import re
import shutil
import subprocess
import threading
import time
from pathlib import Path, PurePosixPath

from .dependency_parser import LOCKFILES, is_manifest
from .repo_analyzer import EXTENSIONS, inventory_repository_files


class RetrievalError(ValueError):
    pass


def _context_file(path: Path) -> bool:
    lower = path.name.lower()
    return (
        path.suffix.lower() in EXTENSIONS
        or is_manifest(path.name)
        or path.name in LOCKFILES
        or path.suffix.lower() in {".md", ".rst", ".adoc"}
        or lower.startswith("readme")
    ) and lower not in {"bun.lockb"}


def _is_test(path: str) -> bool:
    p = PurePosixPath(path)
    return any(
        part.lower() in {"test", "tests", "__tests__", "spec"} for part in p.parts[:-1]
    ) or bool(re.search(r"(^test_|_test\.|\.test\.|\.spec\.|Test\.|Tests\.)", p.name))


class CodeSearch:
    def __init__(
        self,
        root: str | Path,
        *,
        max_files: int = 20000,
        max_matches: int = 40,
        max_file_bytes: int = 1024 * 1024,
        max_lines: int = 120,
        timeout: float = 5,
    ):
        if min(max_files, max_matches, max_file_bytes, max_lines) < 1 or timeout <= 0:
            raise ValueError("Retrieval limits must be positive")
        self.root = Path(root).resolve(strict=True)
        files, self.warnings = inventory_repository_files(
            self.root, max_files=max_files
        )
        self.files = {
            p.relative_to(self.root).as_posix(): p for p in files if _context_file(p)
        }
        self.max_matches, self.max_file_bytes = max_matches, max_file_bytes
        self.max_lines, self.timeout = max_lines, timeout
        self.rg = shutil.which("rg")

    def _path(self, path: str) -> Path:
        relative = PurePosixPath(path)
        if (
            relative.is_absolute()
            or ".." in relative.parts
            or "\\" in path
            or ":" in path
        ):
            raise RetrievalError("Use an inventoried repository-relative path")
        file = self.files.get(relative.as_posix())
        if file is None:
            raise RetrievalError(
                "Path is not an inventoried code, dependency or documentation file"
            )
        for parent in [file, *file.parents]:
            if parent == self.root:
                break
            if parent.is_symlink() or (
                hasattr(parent, "is_junction") and parent.is_junction()
            ):
                raise RetrievalError("Symlinks and junctions are not readable")
        if (
            not file.resolve(strict=True).is_relative_to(self.root)
            or not file.is_file()
        ):
            raise RetrievalError("Path escapes the repository")
        return file

    def _bytes(self, path: str) -> bytes:
        with self._path(path).open("rb") as stream:
            content = stream.read(self.max_file_bytes + 1)
        if len(content) > self.max_file_bytes:
            raise RetrievalError("File exceeds retrieval byte limit")
        if b"\0" in content:
            raise RetrievalError("Binary files cannot be context")
        return content

    def read_file(self, path: str, start: int = 1, end: int | None = None) -> dict:
        """Read an inclusive, one-based line range; never silently return a whole file."""
        if start < 1 or (end is not None and end < start):
            raise RetrievalError("Invalid line range")
        lines = self._bytes(path).decode("utf-8-sig").splitlines(keepends=True)
        if start > len(lines):
            raise RetrievalError("Start line is beyond the file")
        requested_end = end if end is not None else len(lines)
        actual_end = min(requested_end, start + self.max_lines - 1, len(lines))
        content = "".join(lines[start - 1 : actual_end])
        clipped = len(content) > 12000
        content = content[:12000]
        if clipped:
            actual_end = start + len(content.splitlines()) - 1
        return {
            "path": path,
            "start": start,
            "end": actual_end,
            "content": content,
            "truncated": clipped or actual_end < min(requested_end, len(lines)),
        }

    def search_code(self, query: str, *, candidates: list[str] | None = None) -> dict:
        """Literal ripgrep search with bounded matches and no repository configuration."""
        if not query.strip() or len(query) > 300 or "\n" in query or "\0" in query:
            raise RetrievalError(
                "Use a nonempty single-line query of at most 300 characters"
            )
        if not self.rg:
            raise RetrievalError("ripgrep (rg) is required but was not found on PATH")
        paths = sorted(self.files if candidates is None else candidates)
        matches, diagnostics = [], list(self.warnings)
        deadline = time.monotonic() + self.timeout
        for offset in range(0, len(paths), 32):
            batch = []
            for path in paths[offset : offset + 32]:
                try:
                    if self._path(path).stat().st_size <= self.max_file_bytes:
                        batch.append(path)
                    else:
                        diagnostics.append(f"Skipped oversized file: {path}")
                except (OSError, RetrievalError):
                    diagnostics.append(f"Skipped unavailable/unsafe file: {path}")
            if not batch:
                continue
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RetrievalError("ripgrep search deadline exceeded")
            try:
                process = subprocess.Popen(
                    [
                        self.rg,
                        "--no-config",
                        "--no-ignore",
                        "--hidden",
                        "--threads",
                        "1",
                        "--json",
                        "--fixed-strings",
                        "--only-matching",
                        "--max-count",
                        str(self.max_matches + 1),
                        "--",
                        query,
                        *batch,
                    ],
                    cwd=self.root,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                )
                timer = threading.Timer(remaining, process.kill)
                timer.start()
                try:
                    with process.stdout:
                        output = process.stdout.read(1024 * 1024 + 1)
                    if len(output) > 1024 * 1024:
                        raise RetrievalError(
                            "ripgrep output exceeded byte limit; narrow the query"
                        )
                    returncode = process.wait()
                finally:
                    timer.cancel()
                    if process.poll() is None:
                        process.kill()
                    process.wait()
            except (OSError, subprocess.TimeoutExpired) as exc:
                raise RetrievalError(
                    f"ripgrep unavailable or timed out ({type(exc).__name__})"
                ) from exc
            if returncode not in {0, 1}:
                raise RetrievalError("ripgrep could not complete the search")
            for line in output.splitlines():
                row = json.loads(line)
                if row.get("type") != "match":
                    continue
                data = row["data"]
                path = data["path"].get("text")
                if path not in self.files:
                    continue
                snippet = self.read_file(path, data["line_number"], data["line_number"])
                # A minified line can fill the read budget: include coordinates,
                # not an unbounded line, in search results.
                snippet["truncated"] |= len(snippet["content"]) > 500
                snippet["content"] = snippet["content"][:500]
                matches.append(snippet)
                if len(matches) > self.max_matches:
                    return {
                        "matches": matches[: self.max_matches],
                        "truncated": True,
                        "warnings": diagnostics,
                    }
        return {
            "matches": matches,
            "truncated": bool(diagnostics),
            "warnings": diagnostics,
        }

    def find_symbol(self, name: str) -> dict:
        """Find actual declarations, including enclosing symbol/import coordinates."""
        if not re.fullmatch(r"[A-Za-z_$][\w$]*", name):
            raise RetrievalError("Use an unqualified function, method or class name")
        candidates = self.search_code(
            name,
            candidates=[p for p in self.files if Path(p).suffix.lower() in EXTENSIONS],
        )
        declarations, diagnostics = [], []
        grammars = {
            ".py": ("python", "language"),
            ".pyi": ("python", "language"),
            ".js": ("javascript", "language"),
            ".jsx": ("javascript", "language"),
            ".mjs": ("javascript", "language"),
            ".cjs": ("javascript", "language"),
            ".ts": ("typescript", "language_typescript"),
            ".tsx": ("typescript", "language_tsx"),
            ".java": ("java", "language"),
        }
        from tree_sitter import Language, Parser

        for path in dict.fromkeys(m["path"] for m in candidates["matches"]):
            grammar = grammars.get(Path(path).suffix.lower())
            if grammar is None:
                diagnostics.append(f"No Tree-sitter grammar for {path}")
                continue
            module = importlib.import_module("tree_sitter_" + grammar[0])
            content = self._bytes(path)
            tree = Parser(Language(getattr(module, grammar[1])())).parse(content)
            pending = [tree.root_node]
            while pending:
                node = pending.pop()
                pending.extend(reversed(node.named_children))
                if node.type not in {
                    "function_definition",
                    "class_definition",
                    "function_declaration",
                    "class_declaration",
                    "method_definition",
                    "method_declaration",
                    "constructor_declaration",
                    "interface_declaration",
                    "variable_declarator",
                }:
                    continue
                identifier = node.child_by_field_name("name")
                if (
                    not identifier
                    or content[identifier.start_byte : identifier.end_byte].decode()
                    != name
                ):
                    continue
                if node.type == "variable_declarator":
                    value = node.child_by_field_name("value")
                    if value is None or value.type not in {
                        "arrow_function",
                        "function_expression",
                    }:
                        continue
                end = node.end_point.row + (1 if node.end_point.column else 0)
                snippet = self.read_file(path, node.start_point.row + 1, end)
                snippet.update(
                    kind=node.type, name=name, parse_errors=tree.root_node.has_error
                )
                enclosing = []
                parent = node.parent
                while parent is not None:
                    parent_name = parent.child_by_field_name("name")
                    if parent_name:
                        enclosing.append(
                            content[
                                parent_name.start_byte : parent_name.end_byte
                            ].decode()
                        )
                    parent = parent.parent
                snippet["enclosing_symbols"] = list(reversed(enclosing))
                snippet["import_ranges"] = [
                    {"start": child.start_point.row + 1, "end": child.end_point.row + 1}
                    for child in tree.root_node.named_children
                    if child.type
                    in {
                        "import_statement",
                        "import_from_statement",
                        "import_declaration",
                    }
                ][:20]
                declarations.append(snippet)
                if len(declarations) >= self.max_matches:
                    return {
                        "symbols": declarations,
                        "truncated": True,
                        "warnings": diagnostics,
                    }
        return {
            "symbols": declarations,
            "truncated": candidates["truncated"],
            "warnings": candidates["warnings"] + diagnostics,
        }

    def find_related_tests(self, path: str) -> dict:
        """Naming/layout candidates plus literal module references; association is evidence, not proof."""
        self._path(path)
        source = PurePosixPath(path)
        tests = [p for p in self.files if _is_test(p) and p != path]
        stem = source.stem
        names = {
            f"test_{stem}",
            f"{stem}_test",
            f"{stem}.test",
            f"{stem}.spec",
            f"{stem}Test",
            f"{stem}Tests",
        }
        related = {
            p: "matching test filename" for p in tests if PurePosixPath(p).stem in names
        }
        references = self.search_code(stem, candidates=tests)
        for match in references["matches"]:
            related.setdefault(
                match["path"], "literal module/path reference (candidate only)"
            )
        return {
            "tests": [
                {"path": p, "reason": reason} for p, reason in sorted(related.items())
            ][: self.max_matches],
            "truncated": len(related) > self.max_matches or references["truncated"],
            "warnings": references["warnings"],
        }
