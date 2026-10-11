"""OpenAI agent whose shell and file tools target an Aegis sandbox."""

from agents.models.interface import Model
from agents.sandbox import SandboxAgent
from agents.sandbox.capabilities.filesystem import Filesystem
from agents.sandbox.capabilities.shell import Shell


def make_remediation_agent(model: str | Model = "gpt-5.4") -> SandboxAgent:
    return SandboxAgent(
        name="Aegis remediation",
        model=model,
        capabilities=[Shell(), Filesystem()],
        instructions=(
            "You are fixing a repository inside /workspace/repo. The sandbox tool "
            "working directory is /workspace. For shell commands, use absolute "
            "paths or cd /workspace/repo. For apply_patch, prefix every repository "
            "path with repo/ (for example repo/calculator.py). Use the sandbox "
            "shell and filesystem tools to inspect and edit files. Run the declared "
            "checks. Keep all edits inside /workspace/repo. Report changed files, "
            "checks, and failures."
        ),
    )
