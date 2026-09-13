"""Demonstration mode — the workflow without a repository, and its honesty guarantees.

The risk a demo carries is specific: a tool whose argument is "a suspicion is not a finding"
must not be able to show invented findings that look real. So most of what is asserted here is
about labelling and about the demo showing its unflattering cases, not just its wins.
"""

from __future__ import annotations

import time

import pytest
from fastapi.testclient import TestClient

from backend import demo as demo_mode
from backend.app import app
from tainted.models import Check, FindingStatus

client = TestClient(app)


def _noop(_seconds):
    """Skip the deliberate delays so the suite stays fast."""


@pytest.fixture(autouse=True)
def instant(request, monkeypatch):
    """Every test runs the demo instantly, except the one measuring how long it takes."""
    if "measures_timing" not in request.keywords:
        monkeypatch.setenv("TAINTED_DEMO_INSTANT", "1")


# --------------------------------------------------------------------------- #
# Recognising the request
# --------------------------------------------------------------------------- #
def test_demo_is_recognised_from_either_repo_field():
    assert demo_mode.is_demo("demo/demo") is True
    assert demo_mode.is_demo(None, "demo/demo") is True
    assert demo_mode.is_demo("  demo/demo  ") is True
    assert demo_mode.is_demo("/real/path") is False
    assert demo_mode.is_demo(None, None) is False


def test_demo_works_without_a_repository_that_exists():
    """`demo/demo` is not a path; the real endpoint would reject it before doing anything."""
    r = client.post("/api/analyze", json={"repo_path": "demo/demo"})
    assert r.status_code == 200

    missing = client.post("/api/analyze", json={"repo_path": "/no/such/repo"})
    assert missing.status_code == 400


# --------------------------------------------------------------------------- #
# It is marked, everywhere
# --------------------------------------------------------------------------- #
def test_every_demo_report_is_flagged_as_demo():
    for report in (
        demo_mode.demo_analyze_report(sleep=_noop),
        demo_mode.demo_prove_report(sleep=_noop),
    ):
        assert report.demo is True


def test_a_real_report_is_not_flagged():
    from pathlib import Path

    fixture = Path(__file__).resolve().parents[3] / "tests" / "fixtures" / "vulnerable_supabase"
    r = client.post("/api/analyze", json={"repo_path": str(fixture)})
    assert r.json()["demo"] is False


def test_the_flag_survives_serialization_to_the_frontend():
    """A flag that gets dropped in transit is worse than no flag."""
    assert client.post("/api/analyze", json={"repo_path": "demo/demo"}).json()["demo"] is True
    assert client.post(
        "/api/prove", json={"repo_path": "demo/demo", "url": ""}
    ).json()["demo"] is True


# --------------------------------------------------------------------------- #
# The demo is inert
# --------------------------------------------------------------------------- #
def test_prove_needs_no_target_and_bypasses_the_ownership_gate():
    """Exempt because it contacts nothing — not because it is privileged."""
    r = client.post("/api/prove", json={"repo_path": "demo/demo", "url": ""})
    assert r.status_code == 200

    # The same request against a real repo and a non-local URL is still refused.
    refused = client.post(
        "/api/prove", json={"repo_path": "/tmp", "url": "https://someone-elses.app"}
    )
    assert refused.status_code == 403


def test_demo_prove_is_not_blocked_by_the_sandbox_requirement(monkeypatch):
    """Requiring a sandbox is about executing exploits; the demo executes none."""
    monkeypatch.setenv("TAINTED_REQUIRE_SANDBOX", "1")
    r = client.post("/api/prove", json={"repo_path": "demo/demo", "url": ""})
    assert r.status_code == 200


# --------------------------------------------------------------------------- #
# It is computed, not hand-written
# --------------------------------------------------------------------------- #
def test_the_summary_is_computed_by_the_real_report_builder():
    """Hand-written totals would drift out of step with the engine and quietly lie."""
    report = demo_mode.demo_prove_report(sleep=_noop)
    statuses = [f.status for f in report.findings]
    assert report.summary.proven == statuses.count(FindingStatus.PROVEN)
    assert report.summary.reported == statuses.count(FindingStatus.REPORTED)
    assert report.summary.not_reproduced == statuses.count(FindingStatus.NOT_REPRODUCED)
    assert report.summary.total_candidates == len(report.findings)


def test_coverage_notes_are_generated_from_the_engines_own_rules():
    report = demo_mode.demo_prove_report(sleep=_noop)
    checks = {n.check for n in report.coverage}
    assert Check.BOLA in checks and Check.AGENT_INJECTION in checks
    # The coded-agent asymmetry is stated because a coded finding is present.
    assert any("asymmetry" in n.detail for n in report.coverage)


def test_analyze_only_demo_proves_nothing():
    report = demo_mode.demo_analyze_report(sleep=_noop)
    assert report.summary.proven == 0
    assert report.findings == []
    assert len(report.unproven_candidates) == 9
    assert all(not n.proved for n in report.coverage)


# --------------------------------------------------------------------------- #
# It shows the unflattering cases too
# --------------------------------------------------------------------------- #
def test_demo_includes_a_candidate_that_was_attacked_and_held():
    """A demo of only successes would misrepresent the product as much as a false positive."""
    report = demo_mode.demo_prove_report(sleep=_noop)
    held = [f for f in report.findings if f.status is FindingStatus.NOT_REPRODUCED]
    assert held, "the demo must show that Tainted sometimes says no"
    assert held[0].proof.response_status == 403


def test_demo_never_shows_command_injection_as_executed():
    report = demo_mode.demo_prove_report(sleep=_noop)
    cmd = [
        f for f in report.findings
        if f.check is Check.CLASSIC_INJECTION and f.candidate.metadata.get("kind") == "command"
    ][0]
    assert cmd.status is FindingStatus.REPORTED
    assert cmd.proof.exploit.executed is False
    assert "NOT executed" in cmd.proof.notes


def test_demo_shows_the_coded_agent_as_reported_not_proven():
    report = demo_mode.demo_prove_report(sleep=_noop)
    coded = [
        f for f in report.findings
        if f.check is Check.AGENT_INJECTION and f.candidate.metadata.get("coded")
    ][0]
    assert coded.status is FindingStatus.REPORTED
    assert "booting the repo" in coded.proof.notes


def test_demo_shows_a_proven_configured_agent():
    report = demo_mode.demo_prove_report(sleep=_noop)
    configured = [
        f for f in report.findings
        if f.check is Check.AGENT_INJECTION and not f.candidate.metadata.get("coded")
    ][0]
    assert configured.status is FindingStatus.PROVEN
    assert configured.proof.exploit.payload


def test_proven_findings_carry_a_request_and_a_response():
    """The demo has to show what proof looks like, which is the exact request and what came back."""
    report = demo_mode.demo_prove_report(sleep=_noop)
    bola = [f for f in report.findings if f.check is Check.BOLA
            and f.status is FindingStatus.PROVEN][0]
    assert bola.proof.exploit.url.endswith("/api/invoices/1043")
    assert bola.proof.response_status == 200
    assert "Northwind" in bola.proof.response_body


# --------------------------------------------------------------------------- #
# Fix
# --------------------------------------------------------------------------- #
def _demo_id(check: Check) -> str:
    """The demo candidate for one check, named by id rather than by position.

    A position is not a name: the report publishes candidates in one order and `ranked()`
    sorts them into another, so "the first one" means two different holes depending on which
    list is being counted. These tests ask for a specific check.
    """
    analysis = demo_mode.demo_analysis()
    return next(c.id for c in analysis.candidates if c.check is check)


def test_demo_fix_returns_a_real_migration_for_an_rls_finding():
    result = demo_mode.demo_fix_result(sleep=_noop, finding_id=_demo_id(Check.RLS))
    body = "\n".join(e.replacement for e in result.edits)
    assert "enable row level security" in body
    assert "auth.uid()" in body
    assert "patch-only" in result.notes


def test_demo_fix_declines_to_write_the_tool_plane_fix():
    """The interview exists because the code cannot answer; the demo must show that, not skip it."""
    result = demo_mode.demo_fix_result(
        sleep=_noop, finding_id=_demo_id(Check.AGENT_INJECTION)
    )
    assert result.edits == []
    assert "underdetermined" in result.notes


def test_demo_fix_by_position_follows_the_published_order():
    """The positional form still works, and now means the order the page actually drew."""
    report = demo_mode.demo_analyze_report(sleep=_noop)
    published = list(report.unproven_candidates)
    for i, cand in enumerate(published):
        result = demo_mode.demo_fix_result(i, sleep=_noop)
        assert result.finding.candidate.id == cand.id


def test_demo_fix_endpoint_says_the_loop_did_not_close():
    payload = client.post("/api/fix", json={"repo_path": "demo/demo", "index": 0}).json()
    assert payload["loop_closed"] is False


# --------------------------------------------------------------------------- #
# Timing
# --------------------------------------------------------------------------- #
@pytest.mark.measures_timing
def test_operations_take_a_plausible_amount_of_time():
    """An instant result would misrepresent the work as much as an inflated one."""
    started = time.time()
    client.post("/api/analyze", json={"repo_path": "demo/demo"})
    analyze_took = time.time() - started
    assert 0.8 <= analyze_took < 4

    started = time.time()
    client.post("/api/prove", json={"repo_path": "demo/demo", "url": ""})
    prove_took = time.time() - started
    # Proving is two logins plus a probe per candidate, so it costs more than analysing.
    assert prove_took > analyze_took


# --------------------------------------------------------------------------- #
# The frontend surfaces it
# --------------------------------------------------------------------------- #
def test_frontend_chrome_is_driven_by_the_run_not_the_mockup():
    """Every number and chip on the page must come from the report, or it will go stale."""
    from pathlib import Path

    html = (Path(__file__).resolve().parent.parent / "frontend" / "index.html").read_text()
    # The mockup's fixed copy is gone.
    assert "acme/ledger-web" not in html
    assert "6 candidates<br>unproven" not in html
    assert "VERIFIED &middot; localhost</b>" not in html
    assert "<dd>4 candidates</dd>" not in html
    # And each of those regions now has a function that fills it. The gates panel is
    # `refreshGates`, which derives every chip from the form on each keystroke rather than
    # from the last report — a stronger guarantee than the `updateGates` this once named.
    for fn in ("announceCandidates", "refreshGates", "updatePlanes", "renderCoverage"):
        assert fn in html, f"{fn} should populate its panel from the report"


def test_frontend_never_claims_the_demo_ran_against_your_app():
    """The banner would be undone by a sentence three lines below it saying otherwise."""
    from pathlib import Path

    html = (Path(__file__).resolve().parent.parent / "frontend" / "index.html").read_text()
    assert "the demonstration app" in html
    assert "successfully against your app" not in html


def test_frontend_tool_graph_uses_real_design_tokens():
    """`--ink` is this design's background; labels drawn with it are invisible."""
    from pathlib import Path

    html = (Path(__file__).resolve().parent.parent / "frontend" / "index.html").read_text()
    assert "pick('--wash'" in html
    assert "pick('--lamp'" in html
    # --ink may back a label, never ink one. (It is the scrim that keeps a label
    # legible where an edge passes behind it.)
    assert "color: pick('--ink'" not in html
    assert "'text-background-color': pick('--ink'" in html
    assert "var(--open)" not in html  # a token this stylesheet never defined


def test_frontend_renders_the_demo_banner_from_the_flag():
    from pathlib import Path

    html = (Path(__file__).resolve().parent.parent / "frontend" / "index.html").read_text()
    assert 'id="demobar"' in html
    assert "report.demo" in html
    assert "demo/demo" in html  # the affordance that tells you the demo exists
    assert "no exploit ran" in html or "no exploit is fired" in html
