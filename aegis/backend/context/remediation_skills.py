"""Evidence-scoped eligibility and lazy loading of trusted skill bodies."""

import json
import re
from pathlib import Path

import yaml
from agents import function_tool

from ..core.progress import emit

SKILL_ROOT = Path(__file__).resolve().parents[1] / "skills"
SKILL_NAMES = (
    "vulnerability-triage",
    "python-remediation",
    "npm-remediation",
    "maven-remediation",
    "gradle-remediation",
    "regression-testing",
    "security-review",
    "injection-remediation",
    "deserialization-remediation",
)


class RemediationSkills:
    def __init__(self, packet, *, progress=None):
        self.packet, self.progress = packet, progress
        self.loaded: dict[str, str] = {}
        self.errors: list[str] = []
        self.eligible = self._eligible()
        self.catalog = []
        for name in SKILL_NAMES:
            if name not in self.eligible:
                continue
            with (SKILL_ROOT / name / "SKILL.md").open(encoding="utf-8") as source:
                if source.readline().strip() != "---":
                    raise ValueError("Invalid skill frontmatter")
                header = []
                for line in source:
                    if line.strip() == "---":
                        break
                    header.append(line)
                    if sum(map(len, header)) > 3000:
                        raise ValueError("Skill header is oversized")
                metadata = yaml.safe_load("".join(header))
            if metadata.get("name") != name or not isinstance(
                metadata.get("description"), str
            ):
                raise ValueError("Skill metadata does not match the trusted catalog")
            self.catalog.append({"name": name, "description": metadata["description"]})

    def _eligible(self):
        findings = self.packet.advisories.get("findings", [])
        ecosystems = {f["ecosystem"] for f in findings}
        eligible = set()
        if "PyPI" in ecosystems:
            eligible.add("python-remediation")
        if "npm" in ecosystems:
            eligible.add("npm-remediation")
        projects = [
            p for info in self.packet.dependencies for p in info.get("projects", [])
        ]
        if "Maven" in ecosystems:
            manifests = [path for p in projects for path in p.get("manifests", [])]
            if any(Path(path).name == "pom.xml" for path in manifests):
                eligible.add("maven-remediation")
            if any(
                Path(path).name in {"build.gradle", "build.gradle.kts"}
                for path in manifests
            ):
                eligible.add("gradle-remediation")
        if any(not f.get("fixed_version") for f in findings) or not eligible:
            eligible.add("vulnerability-triage")
        if any(p.get("test_commands") for p in projects) or any(
            re.search(r"(^|/)(tests?|__tests__)/|(^|/)(test_)|\.(test|spec)\.", s.path)
            for s in self.packet.snippets
        ):
            eligible.add("regression-testing")
        text = " ".join(f.get("summary", "") for f in findings).lower()
        if re.search(r"injection|\bsqli\b|\bxss\b|command execution", text):
            eligible.update({"injection-remediation", "security-review"})
        if re.search(r"deserializ|deserialis|pickle|yaml.*load", text):
            eligible.update({"deserialization-remediation", "security-review"})
        if re.search(
            r"ssrf|traversal|authentication bypass|authorization bypass", text
        ):
            eligible.add("security-review")
        return eligible

    async def load(self, name: str) -> str:
        if name not in self.eligible:
            self.errors.append("An inapplicable skill was requested")
            return json.dumps(
                {"error": "Skill is not eligible for this CVE and repository"}
            )
        if name not in self.loaded:
            file = SKILL_ROOT / name / "SKILL.md"
            if file.is_symlink() or not file.resolve().is_relative_to(
                SKILL_ROOT.resolve()
            ):
                raise ValueError("Skill path is not trusted")
            text = file.read_text(encoding="utf-8")
            if len(text) > 10000:
                raise ValueError("Skill body exceeds the planning budget")
            self.loaded[name] = text.split("---", 2)[2].strip()
            await emit(
                self.progress,
                "remediation_skills",
                "running",
                f"Loaded {name} for the remediation plan.",
                skill=name,
            )
        return json.dumps({"name": name, "instructions": self.loaded[name]})

    def tool(self):
        @function_tool
        async def load_skill(name: str) -> str:
            """Load one eligible trusted planning skill when its scope is necessary."""
            return await self.load(name)

        return load_skill
