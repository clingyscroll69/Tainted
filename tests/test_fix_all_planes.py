"""`fix` across all four shapes, and the different loop each one requires.

The organizing question is the one the design starts from: what does the correct fix depend on
that the code doesn't contain? Nothing (write it, re-prove it), user intent about structure
(interview, then re-analyse and prove fresh), or user intent about correctness (ask, never
auto-assert). Each branch is asserted here, including the two failure modes that only the right
loop can catch.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tainted import fix as core_fix
from tainted.fix.interview import (
    InterviewAnswer,
    ToolRemediation,
    resolve_tool_plane_fix,
    tool_plane_interview,
)
from tainted.fix.reverify import reverify_tool_plane
from tainted.fix.tool_plane_fix import generate_tool_plane_fix
from tainted.models import (
    Candidate,
    Check,
    Finding,
    FindingStatus,
    FixResult,
    Plane,
    SourceLocation,
)

CONFIGS = str(Path(__file__).parent / "fixtures" / "agent_configs")


def tool_candidate(scope="email_assistant") -> Candidate:
    return Candidate(
        check=Check.AGENT_INJECTION,
        plane=Plane.TOOL,
        title=f"Confused-deputy exposure in `{scope}`",
        location=SourceLocation(file="email_assistant.mcp.json", line=0),
        source="read_email",
        sink="send_email",
        metadata={"scope": scope, "kind": "mcp", "coded": False},
    )


# --------------------------------------------------------------------------- #
# The interview decides; it does not guess
# --------------------------------------------------------------------------- #
def test_tool_plane_fix_refuses_to_run_without_answers():
    """Guessing at a decision that isn't the code's to make is the failure being prevented."""
    with pytest.raises(ValueError, match="underdetermined"):
        core_fix(Finding(candidate=tool_candidate()))


@pytest.mark.parametrize(
    "answers,expected",
    [
        ({"needs_both": "no"}, ToolRemediation.SCOPE_SPLIT),
        ({"needs_both": "yes", "human_available": "yes"}, ToolRemediation.MEDIATION),
        (
            {"needs_both": "yes", "human_available": "no", "latency_ok": "yes"},
            ToolRemediation.SINK_CONFIRMATION,
        ),
        (
            {"needs_both": "yes", "human_available": "no", "latency_ok": "no"},
            ToolRemediation.PROVENANCE,
        ),
    ],
)
def test_every_interview_leaf_reaches_a_distinct_remediation(answers, expected):
    resolved = resolve_tool_plane_fix(
        [InterviewAnswer(key=k, choice=v) for k, v in answers.items()]
    )
    assert resolved is expected


def test_interview_questions_cover_the_facts_only_the_developer_holds():
    keys = {q.key for q in tool_plane_interview(tool_candidate())}
    assert keys == {"needs_both", "human_available", "latency_ok"}


# --------------------------------------------------------------------------- #
# Each remediation writes something applicable
# --------------------------------------------------------------------------- #
def test_scope_split_produces_a_source_only_and_a_sink_only_agent():
    edits, note = generate_tool_plane_fix(tool_candidate(), ToolRemediation.SCOPE_SPLIT)
    manifests = {e.file: json.loads(e.replacement) for e in edits}
    assert len(manifests) == 2

    tools_per_agent = [
        {t["name"] for t in m["tools"]} for m in manifests.values()
    ]
    assert {"read_email"} in tools_per_agent
    assert {"send_email"} in tools_per_agent
    # No manifest holds both — the co-location is what the split removes.
    assert not any({"read_email", "send_email"} <= t for t in tools_per_agent)
    assert "scope split" in note.lower()


def test_mediation_shows_the_approver_what_caused_the_call():
    edits, note = generate_tool_plane_fix(tool_candidate(), ToolRemediation.MEDIATION)
    config = json.loads(edits[0].replacement)["mediation"]
    assert config["require_human_approval"] == ["send_email"]
    # An approver shown only the call cannot see they are approving an injection.
    assert "originating_content_excerpt" in config["approval_payload"]
    assert config["deny_on_timeout"] is True


def test_provenance_propagates_through_summarization():
    """A summary of tainted content is still tainted; forgetting that is a laundering path."""
    edits, _ = generate_tool_plane_fix(tool_candidate(), ToolRemediation.PROVENANCE)
    config = json.loads(edits[0].replacement)["provenance"]
    assert "summarization" in config["propagate_through"]


# --------------------------------------------------------------------------- #
# The tool plane's loop: re-analyse, then prove fresh
# --------------------------------------------------------------------------- #
def _fix_result(scope="email_assistant") -> FixResult:
    return FixResult(finding=Finding(candidate=tool_candidate(scope)))


def test_reverify_passes_when_the_colocation_is_gone_from_the_graph(tmp_path):
    """The fixed repo holds a reader and a sender; neither scope has both."""
    (tmp_path / "reader.json").write_text(
        json.dumps({"name": "email_assistant", "tools": [{"name": "read_email"}]})
    )
    (tmp_path / "sender.json").write_text(
        json.dumps({"name": "email_actor", "tools": [{"name": "send_email"}]})
    )

    result = reverify_tool_plane(_fix_result(), str(tmp_path))
    assert result.resulting_status is FindingStatus.FIXED
    names = {a.name: a.passed for a in result.assertions}
    assert names["pairing_gone"] is True
    assert names["hole_did_not_relocate"] is True


def test_reverify_catches_a_split_that_relocated_the_hole(tmp_path):
    """The failure a re-prove would never catch: the bug moved rather than closed."""
    (tmp_path / "reader.json").write_text(
        json.dumps({"name": "email_assistant", "tools": [{"name": "read_email"}]})
    )
    # The "fix" handed both capabilities to a new agent. Secure-looking, identically broken.
    (tmp_path / "helper.json").write_text(
        json.dumps(
            {
                "name": "email_helper",
                "tools": [{"name": "read_email"}, {"name": "send_email"}],
            }
        )
    )

    result = reverify_tool_plane(_fix_result(), str(tmp_path))
    relocated = [a for a in result.assertions if a.name == "hole_did_not_relocate"][0]
    assert relocated.passed is False
    assert "email_helper" in relocated.detail
    assert result.resulting_status is not FindingStatus.FIXED


def _answered(needs_both="no", human="yes", latency="yes"):
    return [
        InterviewAnswer(key="needs_both", choice=needs_both),
        InterviewAnswer(key="human_available", choice=human),
        InterviewAnswer(key="latency_ok", choice=latency),
    ]


def test_the_graph_is_rechecked_before_the_fix_is_applied(tmp_path):
    """The fix writes new files the developer has not applied. Re-reading the repository would
    re-find the unfixed agent; the re-check has to build the graph the edits leave instead."""
    (tmp_path / "email_assistant.mcp.json").write_text(
        json.dumps(
            {"name": "email_assistant", "tools": [{"name": "read_email"}, {"name": "send_email"}]}
        )
    )
    result = core_fix(
        Finding(candidate=tool_candidate()), answers=_answered(), repo_path=str(tmp_path)
    )
    assert result.resulting_status is FindingStatus.FIXED
    assert all(a.passed for a in result.assertions)
    assert "any agent in the repository" in result.assertions[-1].detail


def test_the_recheck_needs_no_model_and_no_repository():
    """Analysis already labelled these tools, so the website and the demo re-check too."""
    result = core_fix(Finding(candidate=tool_candidate()), answers=_answered())
    assert result.resulting_status is FindingStatus.FIXED
    assert "no repository was given" in result.assertions[-1].detail
    assert "did not re-check" not in result.notes


def test_a_gate_that_keeps_the_pairing_is_reported_not_fixed():
    """Complete on paper is not proven in execution: the sandbox cannot run your gate."""
    result = core_fix(
        Finding(candidate=tool_candidate()), answers=_answered(needs_both="yes", human="yes")
    )
    names = {a.name: a.passed for a in result.assertions}
    assert names == {"gate_covers_every_sink": True, "hole_did_not_relocate": True}
    assert result.resulting_status is FindingStatus.REPORTED


def test_a_gate_that_misses_a_sink_fails():
    candidate = tool_candidate()
    fix = FixResult(
        finding=Finding(candidate=candidate.model_copy(update={"sink": "send_email, run_shell"})),
        metadata={"remediation": ToolRemediation.MEDIATION.value},
    )
    fix.edits, _ = generate_tool_plane_fix(candidate, ToolRemediation.MEDIATION)
    result = reverify_tool_plane(fix)
    gate = [a for a in result.assertions if a.name == "gate_covers_every_sink"][0]
    assert gate.passed is False
    assert "run_shell" in gate.detail
    assert result.resulting_status is not FindingStatus.FIXED


def test_a_split_that_hands_both_tools_to_one_new_agent_is_caught():
    """The split's own edits are in the graph, so a bad split cannot hide in them."""
    candidate = tool_candidate()
    fix = FixResult(
        finding=Finding(candidate=candidate),
        metadata={"remediation": ToolRemediation.SCOPE_SPLIT.value},
    )
    fix.edits, _ = generate_tool_plane_fix(candidate, ToolRemediation.SCOPE_SPLIT)
    fix.edits[1].replacement = json.dumps(
        {"name": "email_actor", "tools": [{"name": "read_email"}, {"name": "send_email"}]}
    )
    result = reverify_tool_plane(fix)
    relocated = [a for a in result.assertions if a.name == "hole_did_not_relocate"][0]
    assert relocated.passed is False
    assert "email_actor" in relocated.detail


# --------------------------------------------------------------------------- #
# Test integrity: the fix is a question
# --------------------------------------------------------------------------- #
def test_test_integrity_fix_never_writes_a_test():
    """Auto-asserting a test from the code manufactures the disease the check diagnoses."""
    finding = Finding(
        candidate=Candidate(
            check=Check.TEST_INTEGRITY,
            title="No test watches src/a.py:12",
            location=SourceLocation(file="src/a.py", line=12),
            metadata={"mutator": "AOR"},
        )
    )
    result = core_fix(finding)
    assert result.edits == []
    assert result.resulting_status is FindingStatus.REPORTED
    assert "Tainted will not write that test for you" in result.notes


# --------------------------------------------------------------------------- #
# Classic injection: deterministic, and dialect-aware
# --------------------------------------------------------------------------- #
def test_order_by_fix_whitelists_rather_than_binds():
    """You cannot bind a column name — which is why this injection outlives parameterization."""
    finding = Finding(
        candidate=Candidate(
            check=Check.CLASSIC_INJECTION,
            title="Dynamic ORDER BY",
            location=SourceLocation(
                file="api/list.ts", line=4, snippet="`... ORDER BY ${req.query.sort}`"
            ),
            metadata={"kind": "sql"},
        )
    )
    result = core_fix(finding)
    assert "SORTABLE" in result.edits[0].replacement
    assert "can't be parameterized" in result.notes


def test_command_injection_fix_removes_the_shell_instead_of_filtering_input():
    finding = Finding(
        candidate=Candidate(
            check=Check.CLASSIC_INJECTION,
            title="exec",
            location=SourceLocation(file="a.js", line=1, snippet="exec(`convert ${f}`)"),
            metadata={"kind": "command"},
        )
    )
    result = core_fix(finding)
    assert "execFile" in result.edits[0].replacement


# --------------------------------------------------------------------------- #
# The remediation has to be in the language of the file it is fixing
#
# Every injection snippet was JavaScript. A Flask repo — the most common shape of the thing
# Tainted is for — got `await db.query(...)` with `//` comments as the fix for its Python.
# The advice was right and the reader could not use it.
# --------------------------------------------------------------------------- #
def _injection_candidate(path: str, kind: str = "sql", snippet: str = "") -> Candidate:
    from tainted.models import SourceLocation

    return Candidate(
        check=Check.CLASSIC_INJECTION,
        title="raw query",
        location=SourceLocation(file=path, line=1, snippet=snippet),
        metadata={"kind": kind},
    )


def test_a_python_file_gets_a_python_sql_fix():
    from tainted.fix.deterministic import generate_injection_fix

    edits, _ = generate_injection_fix(_injection_candidate("app.py"))
    body = edits[0].replacement
    assert "await db.query" not in body
    assert not body.lstrip().startswith("//")
    assert "execute(" in body and "%s" in body


def test_a_typescript_file_still_gets_the_javascript_sql_fix():
    from tainted.fix.deterministic import generate_injection_fix

    edits, _ = generate_injection_fix(_injection_candidate("route.ts"))
    assert "await db.query" in edits[0].replacement


def test_a_python_command_injection_fix_does_not_recommend_execFile():
    from tainted.fix.deterministic import generate_injection_fix

    edits, _ = generate_injection_fix(_injection_candidate("worker.py", kind="command"))
    body = edits[0].replacement
    assert "execFile" not in body
    assert "subprocess.run" in body
