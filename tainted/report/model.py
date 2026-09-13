"""The report data model: candidates, findings, and what a surface renders.

Two fields exist to keep the report honest. `coverage` says what was not tried, and why, so a
possible hole nobody attacked never looks the same as one that was tested and held. `mutation`
says how much of your own test suite is fake.
"""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field

from tainted.models import (
    AnalysisResult,
    ApplicabilityDecision,
    Candidate,
    Check,
    Finding,
    FindingStatus,
    MutationSummary,
    Severity,
)


class ReportSummary(BaseModel):
    total_candidates: int = 0
    proven: int = 0
    reported: int = 0
    fixed: int = 0
    not_reproduced: int = 0
    by_severity: dict[str, int] = Field(default_factory=dict)
    by_check: dict[str, int] = Field(default_factory=dict)


class CoverageNote(BaseModel):
    """One statement about the limit of what was tested."""

    check: Optional[Check] = None
    proved: bool
    detail: str


class Report(BaseModel):
    repo_path: str
    summary: ReportSummary
    findings: list[Finding] = Field(default_factory=list)
    unproven_candidates: list[Candidate] = Field(default_factory=list)
    applicability: list[ApplicabilityDecision] = Field(default_factory=list)
    mutation: Optional[MutationSummary] = None
    coverage: list[CoverageNote] = Field(default_factory=list)
    # True when this report is a demo, not a real run. It lives on the model itself so no
    # surface can drop it and show invented findings as real ones.
    demo: bool = False

    @property
    def proven_findings(self) -> list[Finding]:
        return [f for f in self.findings if f.status == FindingStatus.PROVEN]

    @property
    def reported_findings(self) -> list[Finding]:
        """Argued from the code. No attack was built."""
        return [f for f in self.findings if f.status == FindingStatus.REPORTED]

    def skipped_planes(self) -> list[ApplicabilityDecision]:
        """Planes Tainted confirmed are absent from this repo. You can override that call."""
        return [d for d in self.applicability if not d.applies and d.established]

    def worst_severity(self) -> Optional[Severity]:
        sevs = [f.severity for f in self.proven_findings] or [
            c.severity for c in self.unproven_candidates
        ]
        return max(sevs, key=lambda s: s.rank) if sevs else None


def build_report(
    analysis: AnalysisResult, findings: Optional[list[Finding]] = None
) -> Report:
    findings = findings or []

    summary = ReportSummary(total_candidates=len(analysis.candidates))
    for f in findings:
        if f.status == FindingStatus.PROVEN:
            summary.proven += 1
        elif f.status == FindingStatus.REPORTED:
            summary.reported += 1
        elif f.status in (FindingStatus.FIXED,):
            summary.fixed += 1
        elif f.status == FindingStatus.NOT_REPRODUCED:
            summary.not_reproduced += 1

    for c in analysis.candidates:
        summary.by_severity[c.severity.value] = (
            summary.by_severity.get(c.severity.value, 0) + 1
        )
        summary.by_check[c.check.value] = summary.by_check.get(c.check.value, 0) + 1

    # Candidates that were never carried to a finding (e.g. analyze-only run).
    carried = {id(f.candidate) for f in findings}
    unproven = [c for c in analysis.candidates if id(c) not in carried]

    return Report(
        repo_path=analysis.repo_path,
        summary=summary,
        findings=findings,
        unproven_candidates=unproven,
        applicability=analysis.applicability,
        mutation=analysis.mutation,
        coverage=_coverage(analysis, findings),
    )


# --------------------------------------------------------------------------- #
# How far proof actually reached, stated plainly
# --------------------------------------------------------------------------- #
_COVERAGE_RULES: dict[Check, tuple[bool, str]] = {
    Check.BOLA: (
        True,
        "Tainted ran the attack: account B asked for account A's record, and the "
        "response is the evidence.",
    ),
    Check.RLS: (
        True,
        "Tainted ran the attack against PostgREST, capped at a few rows, and only claims "
        "a hole when a returned row is not the caller's.",
    ),
    Check.CLASSIC_INJECTION: (
        True,
        "SQL injection is proven by running it. Command and template injection are only "
        "demonstrated, never run, since running them could break your app.",
    ),
    Check.AGENT_INJECTION: (
        True,
        "Configured agents are proven in a sandbox that logs instead of acting. Agents defined "
        "in code are argued from the graph only, since proving one means booting your "
        "repository. Give Tainted a runnable entrypoint to prove those too.",
    ),
    Check.TEST_INTEGRITY: (
        False,
        "This is a measurement, not an attack: a surviving mutant is its own proof, so there "
        "is nothing to run and nothing to prove.",
    ),
}


def _coverage(analysis: AnalysisResult, findings: list[Finding]) -> list[CoverageNote]:
    """One note per check present in this run, saying how far its proof actually reached."""
    notes: list[CoverageNote] = []
    present = {c.check for c in analysis.candidates}
    for check in sorted(present, key=lambda c: c.value):
        proved, detail = _COVERAGE_RULES.get(check, (False, ""))
        # Candidates with no findings were only analyzed, not proven. Say so, rather than
        # let an empty proof column look like a passed attack.
        if proved and not any(f.check == check for f in findings):
            detail = f"Not attempted in this run (static analysis only). {detail}"
            proved = False
        notes.append(CoverageNote(check=check, proved=proved, detail=detail))

    coded = [
        f
        for f in findings
        if f.check is Check.AGENT_INJECTION and f.candidate.metadata.get("coded")
    ]
    if coded:
        notes.append(
            CoverageNote(
                check=Check.AGENT_INJECTION,
                proved=False,
                detail=(
                    f"{len(coded)} coded agent scope(s) were argued from the code, not proven. "
                    f"This is a real asymmetry: the request plane proves against your live app, "
                    f"the tool plane only proves against agents you configure."
                ),
            )
        )
    return notes
