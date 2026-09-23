"""One number per finding: severity, weighted by how far proof actually reached.

Every scanner multiplies severity by a confidence the model guessed. Tainted's confidence is not
a guess — `FindingStatus` records whether an attack ran and what happened when it did. So the
multiplier here is *earned*, and the table is published rather than hidden, because the whole
value of the number is that a reader can check it.

The consequence is deliberate and is the reason this module exists: **a proven LOW outranks a
reported CRITICAL** (40 against 35). That is the ranking a proof-first tool should produce, and
no confidence-scoring tool can defend it, because their multiplier is an opinion.

`NOT_REPRODUCED` is floored near zero rather than at zero. Zero would say "this is not a
finding", and the attack having held is a real result about one exploit, not a clean bill of
health for the hole.
"""

from __future__ import annotations

from dataclasses import dataclass

from tainted.models import Candidate, Finding, FindingStatus, Severity

# Severity contributes the base. Spread so the gaps between levels are wider than the noise in
# the multiplier, which keeps a CRITICAL from being overtaken by rounding.
_SEVERITY_BASE: dict[Severity, int] = {
    Severity.INFO: 5,
    Severity.LOW: 40,
    Severity.MEDIUM: 60,
    Severity.HIGH: 80,
    Severity.CRITICAL: 100,
}

# The published multiplier table. Changing a number here changes every ranking in every surface,
# so each one carries the claim it encodes.
PROOF_WEIGHT: dict[FindingStatus, float] = {
    # An attack ran and the hole was real. Nothing outranks this at the same severity.
    FindingStatus.PROVEN: 1.00,
    # Proven, then patched, and the patch closed it. Still evidence of a real hole, but it is
    # shut, so it should sink below anything still open at the same severity.
    FindingStatus.FIXED: 0.10,
    # The attack is blocked and the owner is locked out. The security hole is closed; a
    # functional break is now open. It stays high because somebody has to look at it.
    FindingStatus.BROKE_IT_SAFELY: 0.70,
    # Argued from the code and never fired — including every target Tainted could not reach.
    FindingStatus.REPORTED: 0.35,
    # Fired and held. Evidence about one exploit, not a guarantee about the hole.
    FindingStatus.NOT_REPRODUCED: 0.05,
    # Static suspicion, not yet carried to any outcome.
    FindingStatus.CANDIDATE: 0.30,
}

# A candidate confirmed on inspection (RLS off in the migration, a surviving mutant) is certain
# about its own claim even before any attack, so it is not docked the full unproven discount.
_STRUCTURAL_FLOOR = 0.45


@dataclass(frozen=True)
class Priority:
    """A finding's rank, and the arithmetic that produced it — never the number alone."""

    score: int  # 0-100
    severity: Severity
    status: FindingStatus
    weight: float
    structural: bool = False

    @property
    def explanation(self) -> str:
        base = _SEVERITY_BASE[self.severity]
        detail = f"{self.severity.value} ({base}) x {self.weight:.2f} [{self.status.value}]"
        if self.structural:
            detail += f", floored at {_STRUCTURAL_FLOOR:.2f} because the hole is structural"
        return f"{self.score} = {detail}"

    def as_dict(self) -> dict:
        return {
            "score": self.score,
            "severity": self.severity.value,
            "status": self.status.value,
            "weight": self.weight,
            "structural": self.structural,
            "explanation": self.explanation,
        }


def _weight(status: FindingStatus, structural: bool) -> float:
    weight = PROOF_WEIGHT.get(status, 0.30)
    if structural and status in (FindingStatus.CANDIDATE, FindingStatus.REPORTED):
        return max(weight, _STRUCTURAL_FLOOR)
    return weight


def priority_of(finding: Finding) -> Priority:
    """The finding's 0-100 rank, with its arithmetic attached."""
    structural = finding.candidate.structural
    weight = _weight(finding.status, structural)
    base = _SEVERITY_BASE[finding.severity]
    return Priority(
        score=int(round(base * weight)),
        severity=finding.severity,
        status=finding.status,
        weight=weight,
        structural=structural,
    )


def priority_of_candidate(candidate: Candidate) -> Priority:
    """The same scale for a candidate no attack has been carried to yet."""
    weight = _weight(FindingStatus.CANDIDATE, candidate.structural)
    base = _SEVERITY_BASE[candidate.severity]
    return Priority(
        score=int(round(base * weight)),
        severity=candidate.severity,
        status=FindingStatus.CANDIDATE,
        weight=weight,
        structural=candidate.structural,
    )


def by_priority(findings: list[Finding]) -> list[Finding]:
    """Findings, highest priority first. Ties break on severity, then check name, so the order
    is stable across runs — a dashboard that reshuffles equal rows looks broken."""
    return sorted(
        findings,
        key=lambda f: (
            -priority_of(f).score,
            -f.severity.rank,
            f.check.value,
            f.candidate.id,
        ),
    )


def weight_table() -> list[dict]:
    """The published table, for a surface that wants to print it next to the scores."""
    return [
        {"status": status.value, "weight": weight, "claim": _CLAIMS[status]}
        for status, weight in PROOF_WEIGHT.items()
    ]


_CLAIMS: dict[FindingStatus, str] = {
    FindingStatus.PROVEN: "the attack ran and the hole was real",
    FindingStatus.FIXED: "proven, then patched, and the patch held",
    FindingStatus.BROKE_IT_SAFELY: "attack blocked, but the real owner lost access too",
    FindingStatus.REPORTED: "argued from the code; no attack was fired",
    FindingStatus.NOT_REPRODUCED: "the attack fired and did not succeed",
    FindingStatus.CANDIDATE: "a static suspicion, not carried to any outcome",
}
