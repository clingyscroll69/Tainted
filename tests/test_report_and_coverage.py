"""The report's honesty machinery, and the two false-positive guards behind it.

A scanner is trusted or ignored on the strength of what it refuses to claim. These cover the
places where claiming too much would be easy: a schema that isn't in the repository, and an
empty proof column that reads like a clean bill of health.
"""

from __future__ import annotations

from pathlib import Path

from tainted import analyze
from tainted.checks.test_integrity import CommandResult
from tainted.models import Check, Finding, FindingStatus, Severity
from tainted.report import build_report

FIXTURES = Path(__file__).parent / "fixtures"
ROUTES = str(FIXTURES / "vulnerable_routes")  # client reads, but no migrations
SUPABASE = str(FIXTURES / "vulnerable_supabase")  # migrations present


# --------------------------------------------------------------------------- #
# "No migrations" is not "no protection"
# --------------------------------------------------------------------------- #
def test_missing_schema_is_not_reported_as_disabled_rls():
    """Supabase projects managed from the dashboard would otherwise light up entirely red."""
    rls = [c for c in analyze(ROUTES).candidates if c.check is Check.RLS]
    assert rls, "client reads should still be noticed"
    for cand in rls:
        assert cand.severity is Severity.MEDIUM
        assert cand.structural is False  # nothing was confirmed on inspection
        assert cand.metadata["schema_present"] is False
        assert "no migrations were found" in cand.description


def test_present_schema_still_yields_the_structural_critical_finding():
    """The guard must not have blunted the real case."""
    rls = [c for c in analyze(SUPABASE).candidates if c.check is Check.RLS]
    criticals = [c for c in rls if c.severity is Severity.CRITICAL]
    assert criticals
    assert all(c.structural for c in criticals)
    titles = " ".join(c.title for c in criticals)
    assert "notes" in titles  # RLS never enabled
    assert "invoices" in titles  # permissive `true` policy


# --------------------------------------------------------------------------- #
# Coverage: an untested candidate must not read as a passed test
# --------------------------------------------------------------------------- #
def test_analyze_only_run_says_proof_was_not_attempted():
    report = build_report(analyze(ROUTES))
    bola = [n for n in report.coverage if n.check is Check.BOLA][0]
    assert bola.proved is False
    assert "Not attempted in this run" in bola.detail


def test_coverage_states_the_tool_planes_asymmetry():
    """The doc promises this limit is stated; the report has to actually state it."""
    from tainted.models import Candidate, SourceLocation

    result = analyze(ROUTES)
    result.candidates.append(
        Candidate(
            check=Check.AGENT_INJECTION,
            title="coded agent",
            location=SourceLocation(file="agent.py", line=1),
            metadata={"coded": True, "scope": "x"},
        )
    )
    finding = Finding(
        candidate=result.candidates[-1], status=FindingStatus.REPORTED
    )
    report = build_report(result, [finding])

    details = " ".join(n.detail for n in report.coverage)
    assert "Coded agents" in details or "coded agent" in details
    assert "asymmetry" in details


# --------------------------------------------------------------------------- #
# Test integrity is reachable from analyze
# --------------------------------------------------------------------------- #
_MUTMUT_OUTPUT = """\
survived src/app.py:14 AOR
killed src/app.py:20 AOR
survived src/app.py:31 SDL
"""


def _runner(cmd, cwd):
    if cmd[:2] == ["mutmut", "results"]:
        return CommandResult(0, stdout=_MUTMUT_OUTPUT)
    return CommandResult(0)


def test_test_integrity_runs_and_reaches_the_report():
    result = analyze(ROUTES, only={Check.TEST_INTEGRITY}, mutation_runner=_runner)

    assert result.mutation is not None
    assert result.mutation.total == 3
    assert result.mutation.survived == 2
    assert result.mutation.score == 1 / 3

    mutants = [c for c in result.candidates if c.check is Check.TEST_INTEGRITY]
    assert len(mutants) == 2
    # A surviving mutant is a measurement, not a suspicion — nothing to rank or prove.
    assert all(c.structural for c in mutants)
    assert all(c.severity is Severity.LOW for c in mutants)
    assert build_report(result).mutation.survived == 2


def test_test_integrity_is_not_run_by_default():
    """A mutation campaign is minutes; it must be opt-in, and its absence must be visible."""
    assert analyze(ROUTES).mutation is None
