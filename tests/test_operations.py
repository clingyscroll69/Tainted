"""Composed operations: preflight/positive-control (A2/B7), regression gate (A7),
completion gate (B8), pairing diff (B5), and reprove classification (A1/B2)."""

from __future__ import annotations

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
