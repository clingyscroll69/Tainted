"""Reproducer generation (A9) and the prove budget (A10)."""

from __future__ import annotations

import pytest

from tainted.budget import Budget, BudgetOutcome, parse_budget
from tainted.models import (
    Candidate,
    Check,
    Exploit,
    Finding,
    FindingStatus,
    ProbeResult,
    Severity,
    SourceLocation,
)
from tainted.repro import NotReproducible, curl_for, reproducer_dict, reproducer_for


def _proven_finding(executed=True, url="http://localhost:3000/api/invoices/42"):
    c = Candidate(check=Check.BOLA, title="leak", location=SourceLocation(file="r.ts", line=1),
                  severity=Severity.HIGH, metadata={"seed_id": "42"})
    exploit = Exploit(
        description="B requested A's record", method="GET", url=url,
        headers={"Authorization": "Bearer abc123def456ghi789", "Accept": "application/json"},
        executed=executed,
    )
    return Finding(candidate=c, status=FindingStatus.PROVEN,
                   proof=ProbeResult(succeeded=True, kind="route_bola", exploit=exploit))


# ------------------------------ reproducers ---------------------------------- #
def test_curl_scrubs_the_bearer_token():
    curl, scrubbed = curl_for(_proven_finding().proof.exploit)
    assert scrubbed is True
    assert "abc123def456ghi789" not in curl  # the real token must never appear
    assert "TAINTED_REPLAY_TOKEN" in curl
    assert "curl" in curl and "/api/invoices/42" in curl


def test_replay_script_is_standalone_and_carries_no_secret():
    r = reproducer_for(_proven_finding())
    assert "import tainted" not in r.script  # no engine dependency
    assert "abc123def456ghi789" not in r.script
    assert "TAINTED_REPLAY_TOKEN" in r.script
    assert r.filename.startswith("replay_") and r.filename.endswith(".py")


def test_demonstrated_but_not_executed_has_no_reproducer():
    with pytest.raises(NotReproducible):
        reproducer_for(_proven_finding(executed=False))


def test_reproducer_dict_reports_absence_gracefully():
    c = Candidate(check=Check.CLASSIC_INJECTION, title="cmd",
                  location=SourceLocation(file="x.py", line=1), severity=Severity.CRITICAL)
    f = Finding(candidate=c, status=FindingStatus.REPORTED,
                proof=ProbeResult(succeeded=False, kind="command_injection"))
    d = reproducer_dict(f)
    assert d["available"] is False and d["reason"]


# ------------------------------ budget --------------------------------------- #
def test_candidate_cap_stops_between_candidates():
    b = Budget(max_candidates=2).start()
    assert b.exhausted() is None
    b.note_attempt(); b.note_attempt()
    assert b.exhausted() is not None and "candidate cap" in b.exhausted()


def test_time_cap_is_reported():
    b = Budget(max_seconds=10).start(now=100.0)
    assert b.exhausted(now=105.0) is None
    assert "time cap" in b.exhausted(now=111.0)


def test_parse_budget_treats_zero_as_no_limit():
    assert parse_budget(0, 0) is None
    b = parse_budget(5, None)
    assert b is not None and b.max_seconds == 300.0


def test_budget_outcome_note_names_the_unreached():
    out = BudgetOutcome(stopped_early=True, reason="time cap", attempted=3, skipped=7,
                        elapsed_seconds=60.0)
    assert "not reached" in out.note() and "not the whole repository" in out.note()


def test_a_completed_run_says_no_cap_was_hit():
    out = BudgetOutcome(stopped_early=False, reason="ran to completion", attempted=5,
                        skipped=0, elapsed_seconds=3.0)
    assert "no budget cap hit" in out.note()


def test_prove_honours_a_candidate_budget(tmp_path, monkeypatch):
    """The prove loop stops between candidates when the budget is spent (A10, end to end)."""
    from tainted import prove
    from tainted.models import AnalysisResult, Candidate, Check, Plane, Severity, SourceLocation
    from tainted.dynamic.target import Account, ProveSetup, Target

    cands = [
        Candidate(check=Check.BOLA, plane=Plane.REQUEST, title=f"c{i}",
                  location=SourceLocation(file=f"r{i}.ts", line=1), severity=Severity.HIGH,
                  metadata={"route_path": f"/api/x{i}/[id]", "method": "GET"})
        for i in range(5)
    ]
    analysis = AnalysisResult(repo_path=str(tmp_path), candidates=cands)
    setup = ProveSetup(
        target=Target(url="http://localhost:9/"),  # unreachable: every probe returns REPORTED
        account_a=Account(label="A"), account_b=Account(label="B"),
    )
    budget = Budget(max_candidates=2)
    findings = prove(analysis, setup, ownership_verified=True, budget=budget)
    assert budget.attempted == 2
    assert len(findings) == 2  # only the two it reached before the cap
