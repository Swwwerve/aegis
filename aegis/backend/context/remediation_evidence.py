"""Read-only tools over the bounded Context Planner remediation packet."""

import json

from agents import function_tool


class RemediationEvidenceTools:
    """Expose only evidence already selected by Context Planner."""

    def __init__(self, packet):
        self.packet = packet
        self._snippets = {snippet.path: snippet for snippet in packet.snippets}

    def tools(self):
        @function_tool
        async def search_code(query: str) -> str:
            """Search selected source snippets; no repository access is performed."""
            needle = query.casefold()
            return json.dumps(
                [
                    snippet.model_dump(mode="json")
                    for snippet in self.packet.snippets
                    if needle in snippet.content.casefold()
                ]
            )

        @function_tool
        async def read_file(path: str, start: int, end: int) -> str:
            """Read a line range from one selected source snippet."""
            snippet = self._snippets.get(path)
            if snippet is None or start < snippet.start or end > snippet.end or start > end:
                return json.dumps({"error": "Path or line range is outside the context packet"})
            return json.dumps(
                {
                    "path": path,
                    "start": start,
                    "end": end,
                    "content": "\n".join(
                        snippet.content.splitlines()[start - snippet.start : end - snippet.start + 1]
                    ),
                    "snippet_id": snippet.snippet_id,
                    "sha256": snippet.sha256,
                }
            )

        @function_tool
        async def get_dependency_info(package: str) -> str:
            """Inspect the selected dependency inventory for a package."""
            matches = [
                info
                for info in self.packet.dependencies
                if any(
                    dependency.get("name") == package
                    for project in info.get("projects", [])
                    for dependency in project.get("dependencies", [])
                )
            ]
            return json.dumps(matches or {"error": "Package is not in the context packet"})

        @function_tool
        async def get_advisory(cve_id: str) -> str:
            """Retrieve the verified advisory finding for the target CVE only."""
            if cve_id != self.packet.cve_id:
                return json.dumps({"error": "Only the target vulnerability is available"})
            return json.dumps(self.packet.advisories, ensure_ascii=False)

        return [search_code, read_file, get_dependency_info, get_advisory]
