"""Standard-id tiering (A11) and severity-x-proof priority (A4)."""

from __future__ import annotations

from tainted.models import (
    Candidate,
    Check,
    Finding,
    FindingStatus,
    Severity,
    SourceLocation,
)
from tainted.priority import PROOF_WEIGHT, by_priority, priority_of, priority_of_candidate
from tainted.standards import Tier, ids_for, ids_for_check


def _finding(check, status, sev=Severity.MEDIUM, **meta):
    c = Candidate(check=check, title="t", location=SourceLocation(file="a.py", line=1),
                  severity=sev, metadata=meta)
    return Finding(candidate=c, status=status)


# --------------------------- standards (A11) --------------------------------- #
def test_proven_and_static_are_different_tiers():
    proven = ids_for(_finding(Check.BOLA, FindingStatus.PROVEN))
    static = ids_for(_finding(Check.BOLA, FindingStatus.REPORTED))
    assert proven.tier is Tier.PROVEN
    assert static.tier is Tier.STATIC
    assert any("(proven)" in t for t in proven.tagged())
    assert any("(static)" in t for t in static.tagged())


def test_agent_injection_carries_asi02():
    ids = ids_for(_finding(Check.AGENT_INJECTION, FindingStatus.PROVEN))
    assert "ASI02" in ids.owasp_asi


def test_exfiltrating_scope_earns_the_exfil_technique():
    plain = ids_for(_finding(Check.AGENT_INJECTION, FindingStatus.PROVEN))
    exfil = ids_for(_finding(Check.AGENT_INJECTION, FindingStatus.PROVEN, can_exfiltrate=True))
    assert len(exfil.mitre_atlas) > len(plain.mitre_atlas)


def test_injection_cwe_splits_by_kind():
    assert ids_for_check(Check.CLASSIC_INJECTION, kind="sql").cwe == ("CWE-89",)
    assert ids_for_check(Check.CLASSIC_INJECTION, kind="command").cwe == ("CWE-78",)


def test_test_integrity_invents_no_vulnerability_id():
    ids = ids_for_check(Check.TEST_INTEGRITY)
    assert ids.all_ids == ()
    assert "measures the test suite" in ids.note


# --------------------------- priority (A4) ----------------------------------- #
def test_proven_low_outranks_reported_critical():
    low = priority_of(_finding(Check.BOLA, FindingStatus.PROVEN, Severity.LOW))
    crit = priority_of(_finding(Check.BOLA, FindingStatus.REPORTED, Severity.CRITICAL))
    assert low.score > crit.score


def test_not_reproduced_is_floored_near_zero_not_at_zero():
    p = priority_of(_finding(Check.BOLA, FindingStatus.NOT_REPRODUCED, Severity.HIGH))
    assert 0 < p.score < 10


def test_the_weight_table_is_published_with_a_claim_per_status():
    for status, weight in PROOF_WEIGHT.items():
        assert 0.0 <= weight <= 1.0


def test_explanation_shows_the_arithmetic():
    p = priority_of(_finding(Check.BOLA, FindingStatus.PROVEN, Severity.HIGH))
    assert "x 1.00" in p.explanation and "proven" in p.explanation


def test_by_priority_is_stable_and_proven_first():
    a = _finding(Check.BOLA, FindingStatus.PROVEN, Severity.LOW)
    b = _finding(Check.RLS, FindingStatus.REPORTED, Severity.CRITICAL)
    ordered = by_priority([b, a])
    assert ordered[0] is a  # proven low beats reported critical
    assert by_priority([b, a]) == ordered  # deterministic


def test_structural_candidate_is_not_docked_the_full_unproven_discount():
    plain = Candidate(check=Check.RLS, title="t", location=SourceLocation(file="m.sql", line=1),
                      severity=Severity.CRITICAL, structural=False)
    struct = Candidate(check=Check.RLS, title="t", location=SourceLocation(file="m.sql", line=1),
                       severity=Severity.CRITICAL, structural=True)
    assert priority_of_candidate(struct).score > priority_of_candidate(plain).score
