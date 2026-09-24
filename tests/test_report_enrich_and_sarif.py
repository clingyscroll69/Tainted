"""Report projections (A4/A9/A11/B1) and SARIF emission (A8)."""

from __future__ import annotations

import json

from tainted.models import (
    AnalysisResult,
    ApplicabilityDecision,
    Candidate,
    Check,
    Confidence,
    Exploit,
    Finding,
    FindingStatus,
    Plane,
    ProbeResult,
    Provenance,
    Register,
    Severity,
    SourceLocation,
)
from tainted.report import build_report
from tainted.report.enrich import prioritized, reproducers, silence_ledger, standards
from tainted.report.sarif import to_sarif, to_sarif_json


def _proven():
    c = Candidate(check=Check.BOLA, title="leak", location=SourceLocation(file="r.ts", line=3),
                  severity=Severity.HIGH, metadata={"seed_id": "42"})
    ex = Exploit(description="d", method="GET", url="http://localhost/api/x/42",
                 headers={"Accept": "application/json"}, executed=True)
    return Finding(candidate=c, status=FindingStatus.PROVEN,
                   proof=ProbeResult(succeeded=True, kind="route_bola", exploit=ex))


def _report(findings=None, candidates=None, applicability=None):
    analysis = AnalysisResult(
        repo_path=".",
        candidates=candidates or [f.candidate for f in (findings or [])],
        applicability=applicability or [],
    )
    return build_report(analysis, findings or [])


def test_prioritized_puts_proven_above_a_reported_critical():
    proven = _proven()
    crit = Candidate(check=Check.RLS, title="c", location=SourceLocation(file="m.sql", line=1),
                     severity=Severity.CRITICAL)
    reported = Finding(candidate=crit, status=FindingStatus.REPORTED)
    rows = prioritized(_report([proven, reported]))
    assert rows[0]["id"] == proven.candidate.id


def test_standards_tier_matches_proof():
    rows = standards(_report([_proven()]))
    assert rows and any("(proven)" in t for t in rows[0]["tagged"])


def test_reproducers_only_for_proven_findings():
    rows = reproducers(_report([_proven()]))
    assert rows and rows[0]["available"] is True and "curl" in rows[0]


def test_silence_ledger_names_skipped_planes_and_reminds():
    decision = ApplicabilityDecision(
        plane=Plane.TOOL, applies=False, established=True,
        provenance=Provenance(origin=Register.MEANING, detail="no agent tools", rung=2),
        confidence=Confidence(score=0.9),
    )
    led = silence_ledger(_report(findings=[], applicability=[decision]))
    assert led["skipped_planes"] and led["skipped_planes"][0]["plane"] == "tool"
    assert "clean bill of health" in led["reminder"]


def test_sarif_is_valid_and_carries_proof_and_silence():
    sarif = to_sarif(_report([_proven()]))
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert run["results"][0]["level"] == "error"  # proven -> error
    assert run["results"][0]["properties"]["tainted"]["proof"] == "proven"
    assert "notTested" in run["properties"]["tainted"]
    json.loads(to_sarif_json(_report([_proven()])))  # round-trips as JSON


def test_reported_finding_is_a_warning_not_an_error():
    c = Candidate(check=Check.BOLA, title="t", location=SourceLocation(file="a.py", line=1),
                  severity=Severity.HIGH)
    f = Finding(candidate=c, status=FindingStatus.REPORTED)
    sarif = to_sarif(_report([f]))
    assert sarif["runs"][0]["results"][0]["level"] == "warning"
