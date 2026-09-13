"""The underdetermined-fix interview and the report model."""

from __future__ import annotations

import httpx

from tainted import analyze, prove
from tainted.checks.test_integrity import SurvivingMutant
from tainted.dynamic.replay import SupabaseReplay
from tainted.dynamic.target import Account, ProveSetup, SeedRecord, Target
from tainted.fix.interview import (
    InterviewAnswer,
    ToolRemediation,
    mutant_questions,
    resolve_tool_plane_fix,
    tool_plane_interview,
)
from tainted.models import Candidate, Check, SourceLocation
from tainted.report import build_report


# --------------------------------------------------------------------------- #
# Tool-plane interview -> four remediations
# --------------------------------------------------------------------------- #
def _cand():
    return Candidate(
        check=Check.AGENT_INJECTION,
        title="x",
        location=SourceLocation(file="a.json"),
        metadata={"scope": "assistant"},
    )


def test_interview_leaves_map_to_four_remediations():
    assert tool_plane_interview(_cand())  # produces decision-shaped questions

    def answers(**kw):
        return [InterviewAnswer(key=k, choice=v) for k, v in kw.items()]

    assert resolve_tool_plane_fix(answers(needs_both="no")) == ToolRemediation.SCOPE_SPLIT
    assert (
        resolve_tool_plane_fix(answers(needs_both="yes", human_available="yes"))
        == ToolRemediation.MEDIATION
    )
    assert (
        resolve_tool_plane_fix(
            answers(needs_both="yes", human_available="no", latency_ok="yes")
        )
        == ToolRemediation.SINK_CONFIRMATION
    )
    assert (
        resolve_tool_plane_fix(
            answers(needs_both="yes", human_available="no", latency_ok="no")
        )
        == ToolRemediation.PROVENANCE
    )


def test_mutant_questions_offer_both_branches():
    qs = mutant_questions([SurvivingMutant(file="a.py", line=10, mutator="Negate")])
    assert len(qs) == 1
    assert "intended" in qs[0].question
    assert qs[0].if_intended and qs[0].if_wrong  # correct-vs-bug branches, no auto-assert


# --------------------------------------------------------------------------- #
# Report model
# --------------------------------------------------------------------------- #
def test_report_summarizes_analysis_and_findings(vuln_repo):
    result = analyze(vuln_repo)
    report = build_report(result)
    assert report.summary.total_candidates == len(result.candidates)
    assert report.summary.by_check.get("rls", 0) >= 2
    # analyze-only: everything is still an unproven candidate.
    assert len(report.unproven_candidates) == len(result.candidates)


def test_report_counts_proven_after_prove(vuln_repo):
    result = analyze(vuln_repo)

    def handler(request):
        if request.url.path.startswith("/rest/v1/"):
            return httpx.Response(200, json=[{"id": "x", "owner": "user-A"}])
        return httpx.Response(404, json=[])

    setup = ProveSetup(
        target=Target(url="http://localhost:54321", anon_key="anon"),
        account_a=Account(label="A", access_token="tok-A"),
        account_b=Account(label="B", access_token="tok-B"),
        seed=SeedRecord(table="invoices", id="x"),
    )
    replay = SupabaseReplay(setup.target, httpx.Client(transport=httpx.MockTransport(handler)))
    findings = prove(result, setup, replay=replay)
    report = build_report(result, findings)
    assert report.summary.proven >= 1
    assert report.proven_findings
