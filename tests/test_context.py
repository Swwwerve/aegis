"""Real retrieval tools and an offline model-driven planning round trip."""

import asyncio
import json
from types import SimpleNamespace

import pytest
from agents.items import ModelResponse
from agents.models.interface import Model
from agents.usage import Usage
from openai.types.responses import (
    ResponseFunctionToolCall,
    ResponseOutputMessage,
    ResponseOutputText,
)

from aegis.backend.analysis.code_search import CodeSearch, RetrievalError
from aegis.backend.analysis.repo_analyzer import analyze_repository, get_dependency_info
from aegis.backend.context.context_planner import (
    ContextLimits,
    ContextPlanner,
    ContextSelection,
)
from aegis.backend.core.config import settings
from aegis.backend.sandbox.executor import SandboxExecutor
from aegis.backend.schemas.vulnerability import (
    AdvisoryEvidence,
    ScanReport,
    VulnerabilityFinding,
)

CVE = "CVE-2024-1234"


def put(root, name, text):
    file = root / name
    file.parent.mkdir(parents=True, exist_ok=True)
    file.write_text(text, encoding="utf-8", newline="")
    return file


@pytest.fixture
def repository(tmp_path):
    root = tmp_path / "workspaces" / "example"
    (root / ".git").mkdir(parents=True)
    put(root, "requirements.txt", "urllib3==1.26.4\nunrelated==1.0\n")
    put(
        root,
        "app/client.py",
        "import urllib3\n\nclass Client:\n    def danger(self):\n        return urllib3.request('GET', 'https://example.com')\n",
    )
    put(
        root,
        "tests/test_client.py",
        "from app.client import Client\n\ndef test_request():\n    assert Client()\n",
    )
    put(root, "tests/integration_test.py", "from app.client import Client\n")
    put(root, "docs/http.md", "urllib3 request behaviour and regression checks\n")
    put(root, "unrelated.py", "def other():\n    return 2\n")
    put(root, ".env", "PRIVATE_KEY=never-send\n")
    put(root, "node_modules/hidden.py", "def danger(): pass\n")
    return root


def report(root):
    finding = VulnerabilityFinding(
        package="urllib3",
        installed_version="1.26.4",
        ecosystem="PyPI",
        advisory_id="GHSA-example",
        cve=CVE,
        cves=[CVE],
        version_source="pinned",
        fixed_version="1.26.18",
        summary="Request redirect issue",
        manifests=["requirements.txt"],
        cvss_score=7.5,
        kev=False,
        advisory_evidence=[
            AdvisoryEvidence(
                advisory_id="GHSA-example",
                source="https://api.osv.dev/v1/vulns/GHSA-example",
                affected_functions=["urllib3.request"],
            )
        ],
    )
    unrelated = finding.model_copy(
        update={
            "package": "unrelated",
            "cve": "CVE-2024-9999",
            "cves": ["CVE-2024-9999"],
        }
    )
    return ScanReport(
        vulnerabilities=[finding, unrelated],
        repository_analysis=analyze_repository(root),
    )


def test_ripgrep_and_ranges_exclude_secrets_and_generated_files(repository):
    search = CodeSearch(repository)
    result = search.search_code("urllib3.request")
    assert [(m["path"], m["start"]) for m in result["matches"]] == [
        ("app/client.py", 5)
    ]
    assert search.read_file("app/client.py", 3, 5)["content"].startswith(
        "class Client:"
    )
    assert "node_modules/hidden.py" not in search.files
    for path in [
        ".env",
        "../outside.py",
        "C:/outside.py",
        "app\\client.py",
        "/app/client.py",
    ]:
        with pytest.raises(RetrievalError):
            search.read_file(path)
    for start, end in [(0, 1), (4, 2), (999, 1000)]:
        with pytest.raises(RetrievalError):
            search.read_file("app/client.py", start, end)


@pytest.mark.parametrize(
    "path,content",
    [
        ("thing.py", "class Thing:\n    def target(self):\n        return 1\n"),
        ("thing.js", "class Thing { target() { return 1; } }\n"),
        ("thing.ts", "class Thing { target(): number { return 1; } }\n"),
        ("thing.tsx", "const target = () => <div />;\n"),
        ("Thing.java", "class Thing { int target() { return 1; } }\n"),
    ],
)
def test_tree_sitter_finds_declarations_not_comments_or_calls(tmp_path, path, content):
    put(tmp_path, path, content)
    put(tmp_path, "noise.py", "# target()\nvalue = 'target'\n")
    result = CodeSearch(tmp_path).find_symbol("target")
    assert len(result["symbols"]) == 1
    symbol = result["symbols"][0]
    assert symbol["path"] == path and "target" in symbol["content"]
    assert symbol["parse_errors"] is False


def test_related_tests_have_association_evidence(repository):
    results = CodeSearch(repository).find_related_tests("app/client.py")
    assert {item["path"] for item in results["tests"]} == {
        "tests/test_client.py",
        "tests/integration_test.py",
    }
    assert all(item["reason"] for item in results["tests"])


def test_dependency_and_advisory_tools_reuse_only_matching_evidence(repository):
    saved = report(repository)
    planner = ContextPlanner(repository, CVE, saved)
    assert [
        d["name"]
        for p in get_dependency_info(saved.repository_analysis, "Urllib3")["projects"]
        for d in p["dependencies"]
    ] == ["urllib3"]
    advisory = planner.get_advisory(CVE)
    assert len(advisory["findings"]) == 1
    assert advisory["findings"][0]["cvss_score"] == 7.5
    assert planner.get_dependency_info("urllib3")["found"]
    with pytest.raises(RetrievalError):
        planner.get_dependency_info("unrelated")
    with pytest.raises(RetrievalError):
        planner.get_advisory("CVE-2024-9999")


class PlanningModel(Model):
    """Exercise the actual Agents SDK tool loop without a network/model credential."""

    def __init__(self):
        self.step = 0
        self.results = []

    async def get_response(self, *args, **kwargs):
        inputs = kwargs.get("input", args[1] if len(args) > 1 else [])
        self.results = [
            json.loads(item["output"])
            for item in inputs
            if isinstance(item, dict) and item.get("type") == "function_call_output"
        ]
        calls = [
            ("get_advisory", {"cve_id": CVE}),
            ("get_dependency_info", {"package": "urllib3"}),
            ("search_code", {"query": "urllib3.request"}),
            ("find_symbol", {"name": "danger"}),
            ("find_related_tests", {"path": "app/client.py"}),
            ("read_file", {"path": "tests/test_client.py", "start": 1, "end": 4}),
            ("read_file", {"path": "requirements.txt", "start": 1, "end": 1}),
            ("read_file", {"path": "docs/http.md", "start": 1, "end": 1}),
        ]
        if self.step < len(calls):
            name, arguments = calls[self.step]
            output = [
                ResponseFunctionToolCall(
                    type="function_call",
                    id=f"tool-{self.step}",
                    call_id=f"call-{self.step}",
                    name=name,
                    arguments=json.dumps(arguments),
                )
            ]
        else:
            # Retain only the enclosing definition, tests, target pin and docs.
            selected = [self.results[3]["symbols"][0], *self.results[5:]]
            text = json.dumps(
                {
                    "snippets": [
                        {
                            "snippet_id": s["snippet_id"],
                            "reason": "Evidence needed to change or verify the affected request API",
                        }
                        for s in selected
                    ],
                    "missing_context": [],
                }
            )
            output = [
                ResponseOutputMessage(
                    id="final",
                    role="assistant",
                    status="completed",
                    type="message",
                    content=[
                        ResponseOutputText(
                            type="output_text", text=text, annotations=[]
                        )
                    ],
                )
            ]
        self.step += 1
        return ModelResponse(output=output, usage=Usage(), response_id=None)

    async def stream_response(self, *args, **kwargs):
        if False:
            yield None


class ReviewModel(Model):
    """A separate model fixture reviews the curated draft rather than its transcript."""

    def __init__(self, *, question=None, drop_docs=False, investigate=False):
        self.question = question
        self.drop_docs = drop_docs
        self.investigate = investigate
        self.step = 0
        self.seeds = []
        self.tool_names = []
        self.tool_results = []

    async def get_response(self, *args, **kwargs):
        inputs = kwargs.get("input", args[1] if len(args) > 1 else [])
        tools = kwargs.get("tools", args[3] if len(args) > 3 else [])
        self.tool_names = [tool.name for tool in tools]
        self.tool_results = [
            json.loads(item["output"])
            for item in inputs
            if isinstance(item, dict) and item.get("type") == "function_call_output"
        ]
        user = next(
            item
            for item in inputs
            if isinstance(item, dict) and item.get("role") == "user"
        )
        content = user["content"]
        if isinstance(content, list):
            content = "".join(part.get("text", "") for part in content)
        seed = json.loads(content)
        self.seeds.append(seed)
        if self.investigate and self.step == 0:
            output = [
                ResponseFunctionToolCall(
                    type="function_call",
                    id="review-tool",
                    call_id="review-call",
                    name="find_symbol",
                    arguments=json.dumps({"name": "danger"}),
                )
            ]
        else:
            snippets = [
                s
                for s in seed["draft"]["snippets"]
                if not (self.drop_docs and s["path"].startswith("docs/"))
            ]
            if (
                self.investigate
                and self.tool_results
                and self.tool_results[0].get("symbols")
            ):
                affected = next(
                    s
                    for s in self.tool_results[0]["symbols"]
                    if "urllib3.request" in s["content"]
                )
                snippets = [
                    s
                    for s in snippets
                    if not s["path"].endswith(".py") or s["path"].startswith("tests/")
                ]
                snippets.append(
                    {
                        **affected,
                        "reason": "Confirmed affected caller rather than the unrelated namesake",
                    }
                )
            requests = (
                [
                    {
                        "kind": "operator",
                        "question": self.question,
                        "reason": "The answer determines which caller needs regression coverage",
                    }
                ]
                if self.question and not seed["operator_clarification"]
                else []
            )
            text = json.dumps(
                {
                    "snippets": [
                        {"snippet_id": s["snippet_id"], "reason": s["reason"]}
                        for s in snippets
                    ],
                    "context_requests": requests,
                    "resolved_ambiguities": []
                    if requests
                    else ["app/client.py:4-5 identifies the affected caller"],
                    "ready_for_remediation": not bool(requests),
                    "clarification_ranges": [
                        {
                            "start": 0,
                            "end": len(seed["operator_clarification"].split("\n")[0]),
                            "reason": "Operator identifies which caller is exposed",
                        }
                    ]
                    if self.question and seed["operator_clarification"]
                    else [],
                }
            )
            output = [
                ResponseOutputMessage(
                    id="review-final",
                    role="assistant",
                    status="completed",
                    type="message",
                    content=[
                        ResponseOutputText(
                            type="output_text", text=text, annotations=[]
                        )
                    ],
                )
            ]
        self.step += 1
        return ModelResponse(output=output, usage=Usage(), response_id=None)

    async def stream_response(self, *args, **kwargs):
        if False:
            yield None


def test_model_driven_plan_contains_only_selected_grounded_context(repository):
    planner = ContextPlanner(repository, CVE, report(repository))
    packet = asyncio.run(planner.plan(model=PlanningModel()))
    assert packet.status == "completed", packet.model_dump()
    assert packet.tool_calls == 8
    assert {s.path for s in packet.snippets} == {
        "app/client.py",
        "tests/test_client.py",
        "requirements.txt",
        "docs/http.md",
    }
    assert "unrelated==" not in packet.model_dump_json()
    assert "PRIVATE_KEY" not in packet.model_dump_json()
    assert "unrelated.py" not in packet.model_dump_json()
    with pytest.raises(ValueError, match="pass investigation"):
        packet.remediation_prompt()
    assert len(packet.model_dump_json()) <= planner.limits.max_context_chars


def test_invented_snippets_and_budgets_are_explicit(repository):
    async def exercise():

        planner = ContextPlanner(
            repository, CVE, report(repository), limits=ContextLimits(max_tool_calls=1)
        )
        planner.search = CodeSearch(repository)
        actual = await planner._invoke(
            "read_file", {"path": "requirements.txt", "start": 1, "end": 1}
        )
        assert "snippet_id" in actual
        assert "error" in await planner._invoke("search_code", {"query": "urllib3"})
        packet = planner._packet(
            ContextSelection(
                snippets=[{"snippet_id": "invented", "reason": "Not retrieved"}],
                missing_context=[],
            )
        )
        assert packet.status == "partial" and not packet.snippets
        assert any("invented" in d for d in packet.diagnostics)
        tiny = ContextPlanner(
            repository, CVE, report(repository), limits=ContextLimits(max_tool_chars=10)
        )
        tiny.search = CodeSearch(repository)
        assert "error" in await tiny._invoke(
            "read_file", {"path": "requirements.txt", "start": 1, "end": 1}
        )
        assert not tiny.ledger

    asyncio.run(exercise())


def test_unavailable_model_and_unknown_cve_do_not_guess(repository, monkeypatch):
    monkeypatch.setattr(settings, "openai_api_key", None)
    assert (
        asyncio.run(ContextPlanner(repository, CVE, report(repository)).plan()).status
        == "unavailable"
    )
    assert (
        asyncio.run(
            ContextPlanner(repository, "CVE-2024-0000", report(repository)).plan(
                model=PlanningModel()
            )
        ).status
        == "unavailable"
    )


def test_large_lines_are_clipped_and_missing_rg_uses_fallback(repository):
    put(repository, "huge.py", "x" * 15000)
    search = CodeSearch(repository, max_lines=1)
    assert search.read_file("huge.py")["truncated"]
    assert search.read_file("app/client.py", 1, 5)["end"] == 1
    search.rg = None
    result = search.search_code("danger")
    assert result["matches"][0]["path"] == "app/client.py"
    assert any("Python search fallback" in warning for warning in result["warnings"])


def test_model_failure_timeout_and_final_budget_are_bounded(repository):
    class Broken(Model):
        async def get_response(self, *args, **kwargs):
            raise RuntimeError("private-provider-body")

        async def stream_response(self, *args, **kwargs):
            if False:
                yield None

    class Slow(Broken):
        async def get_response(self, *args, **kwargs):
            await asyncio.Future()

    failed = asyncio.run(
        ContextPlanner(repository, CVE, report(repository)).plan(model=Broken())
    )
    assert (
        failed.status == "failed"
        and "private-provider-body" not in failed.model_dump_json()
    )
    timed_out = asyncio.run(
        ContextPlanner(
            repository,
            CVE,
            report(repository),
            limits=ContextLimits(timeout_seconds=0.1),
        ).plan(model=Slow())
    )
    assert (
        timed_out.status == "failed" and "TimeoutError" in timed_out.missing_context[0]
    )
    oversized = asyncio.run(
        ContextPlanner(
            repository,
            CVE,
            report(repository),
            limits=ContextLimits(max_context_chars=100),
        ).plan(model=PlanningModel())
    )
    assert oversized.status == "failed" and not oversized.snippets


def test_inventory_does_not_follow_external_symlinks(repository, tmp_path):
    outside = put(tmp_path, "external.py", "def danger(): return 'private'\n")
    link = repository / "linked.py"
    try:
        link.symlink_to(outside)
    except OSError:
        pytest.skip("Creating symlinks requires Windows developer mode or privilege")
    search = CodeSearch(repository)
    assert "linked.py" not in search.files
    with pytest.raises(RetrievalError):
        search.read_file("linked.py")


def test_sandbox_gets_selected_packet_and_rejects_stale_source(repository, monkeypatch):
    monkeypatch.setattr(settings, "workspace_root", repository.parent)

    class Workspace:
        def __init__(self):
            self.prompts = []
            self.stale = False

        async def read_file(self, path):
            return b"changed" if self.stale else (repository / path).read_bytes()

        async def run_agent(self, prompt, **kwargs):
            self.prompts.append(prompt)
            return SimpleNamespace(final_output="done")

    async def exercise():
        from test_remediation_planning import PlanModel

        workspace = Workspace()
        executor = SandboxExecutor(workspace)
        packet, result = await executor.remediate_with_context(
            repository,
            CVE,
            report(repository),
            model=PlanningModel(),
            investigator_model=ReviewModel(),
            planner_model=PlanModel(),
        )
        assert packet.status == "completed" and result.status == "ready"
        assert workspace.prompts == []
        workspace.stale = True
        packet, result = await executor.remediate_with_context(
            repository,
            CVE,
            report(repository),
            model=PlanningModel(),
            investigator_model=ReviewModel(),
        )
        assert packet.status == "partial" and result is None
        assert workspace.prompts == []

    asyncio.run(exercise())


def test_hybrid_investigator_resolves_candidates_and_prunes_context(repository):
    from aegis.backend.context.context_planner import plan_hybrid_context

    put(
        repository,
        "app/unrelated.py",
        "class Other:\n    def danger(self):\n        return 0\n",
    )
    review = ReviewModel(drop_docs=True, investigate=True)
    events = []

    async def progress(event):
        events.append(event)

    packet = asyncio.run(
        plan_hybrid_context(
            repository,
            CVE,
            report(repository),
            model=PlanningModel(),
            investigator_model=review,
            progress=progress,
        )
    )
    assert packet.status == "completed", packet.model_dump()
    assert set(review.tool_names) == {"search_code", "read_file", "find_symbol"}
    assert len(review.tool_results[0]["symbols"]) == 2
    assert len(packet.snippets) == 3
    prompt = packet.remediation_prompt()
    for omitted in [
        "docs/http.md",
        "app/unrelated.py",
        "cvss_score",
        "epss_probability",
        "retrieved_chars",
        "resolved_ambiguities",
        "diagnostics",
        "tool_calls",
    ]:
        assert omitted not in prompt
    assert "transcript" not in review.seeds[0]
    assert packet.tool_calls == 9
    assert [event["stage"] for event in events if event["status"] == "completed"] == [
        "context_retrieval",
        "context_investigation",
        "context_selection",
    ]


def test_missing_context_is_requested_and_answer_is_curated(repository):
    from aegis.backend.context.context_planner import plan_hybrid_context

    question = "Which caller is exposed in production?"
    events = []

    async def progress(event):
        events.append(event)

    packet = asyncio.run(
        plan_hybrid_context(
            repository,
            CVE,
            report(repository),
            model=PlanningModel(),
            investigator_model=ReviewModel(question=question),
            progress=progress,
        )
    )
    assert packet.status == "partial" and packet.investigation_status == "needs_context"
    assert packet.context_requests[0]["question"] == question
    assert any(event["stage"] == "context_request" for event in events)
    with pytest.raises(ValueError, match="Unresolved"):
        packet.remediation_prompt()
    clarified = asyncio.run(
        plan_hybrid_context(
            repository,
            CVE,
            report(repository),
            model=PlanningModel(),
            investigator_model=ReviewModel(question=question),
            clarification="Client.danger handles production requests.\nUnrelated personal background.",
        )
    )
    assert clarified.status == "completed" and not clarified.context_requests
    assert (
        clarified.clarifications[0]["content"]
        == "Client.danger handles production requests."
    )
    assert "production requests" in clarified.remediation_prompt()
    assert "personal background" not in clarified.remediation_prompt()


def test_overlapping_selected_ranges_are_not_repeated(repository):
    async def exercise():
        planner = ContextPlanner(repository, CVE, report(repository))
        planner.search = CodeSearch(repository)
        a = await planner._invoke(
            "read_file", {"path": "app/client.py", "start": 1, "end": 4}
        )
        b = await planner._invoke(
            "read_file", {"path": "app/client.py", "start": 4, "end": 5}
        )
        packet = planner._packet(
            ContextSelection(
                snippets=[
                    {
                        "snippet_id": item["snippet_id"],
                        "reason": "Affected request implementation",
                    }
                    for item in [a, b]
                ],
                missing_context=[],
            )
        )
        assert packet.status == "completed" and len(packet.snippets) == 1
        assert (
            packet.snippets[0].content
            == (repository / "app/client.py").read_bytes().decode()
        )
        assert packet.snippets[0].start == 1 and packet.snippets[0].end == 5
        reviewed = planner._packet(
            ContextSelection(
                snippets=[
                    {
                        "snippet_id": packet.snippets[0].snippet_id,
                        "reason": "Merged affected caller evidence",
                    }
                ],
                missing_context=[],
            ),
            reviewed=True,
        )
        assert (
            reviewed.status == "completed"
            and reviewed.snippets[0].content == packet.snippets[0].content
        )

    asyncio.run(exercise())


def test_review_budget_and_provider_failure_never_allow_unreviewed_remediation(
    repository,
):
    from aegis.backend.context.context_planner import plan_hybrid_context

    packet = asyncio.run(
        plan_hybrid_context(
            repository,
            CVE,
            report(repository),
            model=PlanningModel(),
            investigator_model=ReviewModel(investigate=True),
            limits=ContextLimits(max_tool_calls=8),
        )
    )
    assert packet.status == "partial" and packet.tool_calls == 8
    with pytest.raises(ValueError):
        packet.remediation_prompt()

    class BrokenReview(ReviewModel):
        async def get_response(self, *args, **kwargs):
            raise RuntimeError("private review contents")

    failed = asyncio.run(
        plan_hybrid_context(
            repository,
            CVE,
            report(repository),
            model=PlanningModel(),
            investigator_model=BrokenReview(),
        )
    )
    assert failed.status == "failed" and failed.investigation_status == "failed"
    assert "private review contents" not in failed.model_dump_json()
