"""Composed operations: preflight/positive-control (A2/B7), regression gate (A7),
completion gate (B8), pairing diff (B5), and reprove classification (A1/B2)."""

from __future__ import annotations

import httpx

from tainted.dynamic.replay import SupabaseReplay
from tainted.dynamic.route_probes import RouteProber
from tainted.dynamic.target import Account, ProveSetup, SeedRecord, Target

from tainted.models import (
    AnalysisResult,
    Candidate,
    Check,
    FileEdit,
    Finding,
    FindingStatus,
    Plane,
    Severity,
    SourceLocation,
)
from tainted.operations import (
    completion_gate,
    pairing_diff,
    regression_check,
    reprove,
)


def _cand(check=Check.AGENT_INJECTION, scope="agent", title="t"):
    return Candidate(check=check, plane=Plane.TOOL, title=title,
                     location=SourceLocation(file="a.py", line=1),
                     severity=Severity.HIGH, metadata={"scope": scope})


# ------------------------------ completion gate (B8) ------------------------- #
def test_a_proven_high_blocks_completion():
    f = Finding(candidate=_cand(Check.BOLA), status=FindingStatus.PROVEN)
    g = completion_gate([f])
    assert g.passed is False and len(g.blocking) == 1


def test_a_static_candidate_does_not_block():
    f = Finding(candidate=_cand(Check.BOLA), status=FindingStatus.REPORTED)
    assert completion_gate([f]).passed is True


def test_a_proven_low_does_not_block_a_high_gate():
    c = Candidate(check=Check.BOLA, title="t", location=SourceLocation(file="a.py", line=1),
                  severity=Severity.LOW)
    f = Finding(candidate=c, status=FindingStatus.PROVEN)
    assert completion_gate([f], fail_on=Severity.HIGH).passed is True


# ------------------------------ pairing diff (B5) ---------------------------- #
def test_a_new_co_location_is_flagged():
    base = AnalysisResult(repo_path=".", candidates=[_cand(scope="mailer")])
    head = AnalysisResult(repo_path=".", candidates=[_cand(scope="mailer"), _cand(scope="assistant")])
    diff = pairing_diff(base, head)
    assert diff.introduced_danger is True
    assert diff.new_pairings[0]["scope"] == "assistant"


def test_no_new_pairing_is_clean():
    base = AnalysisResult(repo_path=".", candidates=[_cand(scope="mailer")])
    head = AnalysisResult(repo_path=".", candidates=[_cand(scope="mailer")])
    assert pairing_diff(base, head).introduced_danger is False


# ------------------------------ regression gate (A7) ------------------------- #
def test_no_test_command_skips_rather_than_assumes_green(tmp_path):
    r = regression_check(str(tmp_path), [], test_cmd=None)
    assert r.ran is False and r.regressed is False


def test_a_patch_that_breaks_the_suite_is_a_regression(tmp_path):
    from tainted.checks.test_integrity import CommandResult

    (tmp_path / "app.py").write_text("VALUE = 1\n")
    edit = FileEdit(file="app.py", replacement="VALUE = 2\n")
    # Runner: suite passes on the original text, fails once the edit is applied.
    def runner(cmd, cwd):
        text = (tmp_path / "app.py").read_text()
        return CommandResult(returncode=0 if "VALUE = 1" in text else 1)
    r = regression_check(str(tmp_path), [edit], test_cmd=["pytest"], runner=runner)
    assert r.ran and r.regressed is True
    # And the file is restored afterwards.
    assert (tmp_path / "app.py").read_text() == "VALUE = 1\n"


def test_a_patch_that_keeps_the_suite_green_is_not_a_regression(tmp_path):
    from tainted.checks.test_integrity import CommandResult

    (tmp_path / "app.py").write_text("VALUE = 1\n")
    edit = FileEdit(file="app.py", replacement="VALUE = 2\n")
    r = regression_check(str(tmp_path), [edit], test_cmd=["pytest"],
                         runner=lambda c, w: CommandResult(returncode=0))
    assert r.ran and r.regressed is False


# ------------------------------ reprove (A1/B2) ------------------------------ #
def _route_finding(method="GET"):
    c = Candidate(check=Check.BOLA, title="invoice by id", severity=Severity.HIGH,
                  location=SourceLocation(file="app.py", line=1),
                  metadata={"route_path": "/api/invoices/<id>", "method": method})
    return Finding(candidate=c, status=FindingStatus.PROVEN)


def _reprove(finding, handler):
    s = ProveSetup(
        target=Target(url="http://localhost:3000", anon_key="anon"),
        account_a=Account(label="A", access_token="tok-a"),
        account_b=Account(label="B", access_token="tok-b"),
        seed=SeedRecord(table="invoices", id="42"),
    )
    client = httpx.Client(transport=httpx.MockTransport(handler))
    return reprove(finding, s, prober=RouteProber(s, client=client),
                   replay=SupabaseReplay(s.target, client))


def _by_token(a_status, b_status):
    def handler(request: httpx.Request) -> httpx.Response:
        if "tok-a" in request.headers.get("authorization", ""):
            return httpx.Response(a_status, json={"id": "42"})
        return httpx.Response(b_status, json={"id": "42"})
    return handler


def test_reprove_a_route_that_refuses_b_and_serves_a_is_fixed():
    r = _reprove(_route_finding(), _by_token(200, 403))
    assert r.status is FindingStatus.FIXED and r.legitimate_access_ok is True


def test_reprove_a_route_that_refuses_everyone_broke_it_safely():
    r = _reprove(_route_finding(), _by_token(403, 403))
    assert r.status is FindingStatus.BROKE_IT_SAFELY and r.legitimate_access_ok is False


def test_reprove_a_held_write_is_not_called_fixed():
    """A write route is never sent, so re-proving it says nothing about the fix."""
    sent = []

    def handler(request: httpx.Request) -> httpx.Response:
        sent.append(request.method)
        return httpx.Response(403)

    r = _reprove(_route_finding("DELETE"), handler)
    assert r.status is FindingStatus.REPORTED and r.attack_blocked is False
    assert sent == []


def test_reprove_without_an_owner_check_is_not_reproduced_never_fixed():
    """SQL injection that now holds, on an app with no PostgREST: half the verdict is unasked."""
    c = Candidate(check=Check.CLASSIC_INJECTION, title="sqli", severity=Severity.HIGH,
                  location=SourceLocation(file="app.py", line=1),
                  metadata={"route_path": "/api/items", "method": "GET", "kind": "sql"})
    s = ProveSetup(
        target=Target(url="http://localhost:3000"),
        account_a=Account(label="A", access_token="tok-a"),
        account_b=Account(label="B", access_token="tok-b"),
        seed=SeedRecord(table="items", id="42"),
    )
    client = httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(200, json=[])))
    r = reprove(Finding(candidate=c, status=FindingStatus.PROVEN), s,
                prober=RouteProber(s, client=client), replay=SupabaseReplay(s.target, client))
    assert r.status is FindingStatus.NOT_REPRODUCED and r.legitimate_access_ok is None
