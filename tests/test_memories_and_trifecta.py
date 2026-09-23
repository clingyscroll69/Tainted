"""Triage memories (A5) and the lethal-trifecta third leg (List A extra)."""

from __future__ import annotations

import json

from tainted.memories import (
    MemoryStore,
    reconcile_findings,
    suppressed_candidates,
)
from tainted.models import (
    Candidate,
    Check,
    Finding,
    FindingStatus,
    Severity,
    SourceLocation,
)
from tainted.static.tools import AgentScope, ToolSpec
from tainted.trifecta import assess


def _cand(check=Check.BOLA, title="t"):
    return Candidate(check=check, title=title, location=SourceLocation(file="a.py", line=1),
                     severity=Severity.HIGH)


def _write_memory(tmp_path, finding_id, reason="intentionally public"):
    d = tmp_path / ".tainted"
    d.mkdir()
    (d / "memories.json").write_text(
        json.dumps({"memories": [{"finding_id": finding_id, "reason": reason}]})
    )


# ------------------------------ memories (A5) -------------------------------- #
def test_a_memory_suppresses_a_matching_candidate(tmp_path):
    c = _cand()
    _write_memory(tmp_path, c.id)
    store = MemoryStore.load(str(tmp_path))
    _, applied = suppressed_candidates([c], store)
    assert len(applied) == 1 and applied[0].honoured is True


def test_a_memory_cannot_suppress_a_proven_finding(tmp_path):
    c = _cand()
    _write_memory(tmp_path, c.id)
    store = MemoryStore.load(str(tmp_path))
    proven = Finding(candidate=c, status=FindingStatus.PROVEN)
    shown, applied = reconcile_findings([proven], store)
    assert proven in shown  # evidence is never hidden
    assert applied and applied[0].honoured is False
    assert "cannot suppress a fired exploit" in applied[0].conflict


def test_a_memory_may_suppress_a_reported_finding(tmp_path):
    c = _cand()
    _write_memory(tmp_path, c.id)
    store = MemoryStore.load(str(tmp_path))
    reported = Finding(candidate=c, status=FindingStatus.REPORTED)
    _, applied = reconcile_findings([reported], store)
    assert applied and applied[0].honoured is True


def test_a_missing_or_corrupt_file_means_no_memories(tmp_path):
    assert MemoryStore.load(str(tmp_path)).memories == {}
    (tmp_path / ".tainted").mkdir()
    (tmp_path / ".tainted" / "memories.json").write_text("{ not json")
    assert MemoryStore.load(str(tmp_path)).memories == {}


# ------------------------------ trifecta ------------------------------------- #
def test_egress_sink_closes_the_third_leg():
    scope = AgentScope(name="a", kind="mcp", source_file="x", tools=[
        ToolSpec("read_email", role="source"),
        ToolSpec("send_email", role="sink"),
    ])
    v = assess(scope)
    assert v.complete is True and v.can_exfiltrate is True
    assert "send_email" in v.egress_tools


def test_local_only_sink_is_one_leg_short():
    scope = AgentScope(name="a", kind="mcp", source_file="x", tools=[
        ToolSpec("read_file", role="source", description="reads a local file"),
        ToolSpec("write_db", role="sink", description="writes a row to the local database"),
    ])
    v = assess(scope)
    assert v.reads_untrusted and v.can_act
    assert v.can_exfiltrate is False and v.complete is False


def test_egress_detected_by_description_not_just_name():
    scope = AgentScope(name="a", kind="mcp", source_file="x", tools=[
        ToolSpec("read_email", role="source"),
        ToolSpec("run", role="sink", description="post the result to an external webhook"),
    ])
    assert assess(scope).can_exfiltrate is True
