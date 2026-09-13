"""Semgrep taint integration — additive, post-filtered, and legible when absent.

The runner is injected throughout so these are hermetic: they test how Tainted *uses* Semgrep,
which is the part that can be wrong, not whether Semgrep works.
"""

from __future__ import annotations

import json
from pathlib import Path

from tainted.checks.classic_injection import scan_classic_injection
from tainted.models import Check, Severity
from tainted.static.semgrep import (
    BOLA_RULES,
    INJECTION_RULES,
    SemgrepRun,
    parse_results,
    semgrep_bola_candidates,
    semgrep_injection_candidates,
)

FIXTURES = Path(__file__).parent / "fixtures"
ROUTES = str(FIXTURES / "vulnerable_routes")
INJECTION = str(FIXTURES / "classic_injection")


def _result(path: str, line: int, rule: str, lines: str, kind: str | None = None):
    extra = {"lines": lines, "message": "..."}
    if kind:
        extra["metadata"] = {"tainted_kind": kind}
    return {
        "check_id": rule,
        "path": path,
        "start": {"line": line},
        "end": {"line": line},
        "extra": extra,
    }


def _runner(results, available=True, note=""):
    def run(rules, repo_path):
        return SemgrepRun(available=available, findings=results, note=note)

    return run


# --------------------------------------------------------------------------- #
# Absence degrades legibly
# --------------------------------------------------------------------------- #
def test_missing_semgrep_yields_no_candidates_and_does_not_raise():
    runner = _runner([], available=False, note="semgrep not installed")
    assert semgrep_bola_candidates(ROUTES, runner=runner) == []
    assert semgrep_injection_candidates(INJECTION, runner=runner) == []


def test_analysis_still_produces_candidates_without_semgrep():
    """The route scan carries the plane alone — a missing optional tool costs coverage only."""
    assert scan_classic_injection(INJECTION)  # semgrep almost certainly absent in CI


# --------------------------------------------------------------------------- #
# BOLA: the ownership post-filter
# --------------------------------------------------------------------------- #
def test_taint_flow_into_a_scoped_read_is_filtered_out():
    """The rules stop at the flow; the scoping question is answered against the real source.

    `receipts/[id]/route.ts` has `.eq("user_id", user.id)`. A taint hit there is a flow, not a
    bug, and reporting it would be the false positive that makes a scanner unusable.
    """
    hit = _result(
        "app/api/receipts/[id]/route.ts", 14, "tainted-request-param-to-db-read-js",
        '.eq("id", params.id)',
    )
    assert semgrep_bola_candidates(ROUTES, runner=_runner([hit])) == []


def test_taint_flow_into_an_unscoped_read_becomes_a_candidate():
    hit = _result(
        "app/api/invoices/[id]/route.ts", 15, "tainted-request-param-to-db-read-js",
        '.eq("id", params.id)',
    )
    cands = semgrep_bola_candidates(ROUTES, runner=_runner([hit]))
    assert len(cands) == 1
    assert cands[0].check is Check.BOLA
    # Identity is read in that handler and not used — the higher severity reflects it.
    assert cands[0].severity is Severity.HIGH
    assert "semgrep" in cands[0].provenance[0].detail


# --------------------------------------------------------------------------- #
# Injection: taint confirmation upgrades rather than duplicates
# --------------------------------------------------------------------------- #
def test_taint_confirmation_upgrades_the_matching_regex_candidate():
    baseline = scan_classic_injection(INJECTION)
    target = [c for c in baseline if c.location.file.endswith(".py")][0]

    hit = _result(
        target.location.file, target.location.line,
        "tainted-user-input-to-raw-sql-python", target.location.snippet, kind="sql",
    )
    upgraded = semgrep_injection_candidates(INJECTION, runner=_runner([hit]))
    assert len(upgraded) == 1
    assert upgraded[0].metadata["taint_confirmed"] is True
    # A confirmed flow is worth much more than a pattern match on interpolation.
    assert upgraded[0].confidence.score > target.confidence.score


def test_command_injection_candidate_is_never_marked_live_provable():
    hit = _result("h.py", 3, "tainted-user-input-to-shell-python", "os.system(cmd)", kind="command")
    cand = semgrep_injection_candidates(INJECTION, runner=_runner([hit]))[0]
    assert cand.metadata["live_provable"] is False
    assert cand.metadata["demonstrated_exploit"]["executed"] is False


# --------------------------------------------------------------------------- #
# The bundled rules are real files Semgrep could load
# --------------------------------------------------------------------------- #
def test_bundled_rule_files_exist_and_declare_taint_mode():
    for rules in (BOLA_RULES, INJECTION_RULES):
        text = rules.read_text(encoding="utf-8")
        assert "mode: taint" in text
        assert "pattern-sources" in text and "pattern-sinks" in text


def test_parse_results_reads_the_semgrep_document_shape():
    payload = json.dumps({"results": [_result("a.ts", 1, "r", "x")], "errors": []})
    assert parse_results(payload)[0]["path"] == "a.ts"
