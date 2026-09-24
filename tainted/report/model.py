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


# Statuses that mean an attack actually ran and the hole was real. FIXED and
# BROKE_IT_SAFELY only arise in the fix loop, downstream of a hole that was already proven,
# so both carry the proof forward. REPORTED is argued statically and NOT_REPRODUCED is the
# attack holding — neither is a proof by running.
_PROOF_ESTABLISHING = frozenset(
    {FindingStatus.PROVEN, FindingStatus.FIXED, FindingStatus.BROKE_IT_SAFELY}
)


def _coverage(analysis: AnalysisResult, findings: list[Finding]) -> list[CoverageNote]:
    """One note per check present in this run, saying how far its proof actually reached."""
    notes: list[CoverageNote] = []
    present = {c.check for c in analysis.candidates}
    for check in sorted(present, key=lambda c: c.value):
        proved, detail = _COVERAGE_RULES.get(check, (False, ""))
        # Three outcomes, not two. Asking only whether a finding *exists* conflated the last
        # two, because every prove outcome is a finding — NOT_REPRODUCED included. A run whose
        # single attack fired and held then reported the check proven, in the same report whose
        # summary said `proven: 0`.
        if proved:
            for_check = [f for f in findings if f.check == check]
            if not for_check:
                # Only analyzed. Say so, rather than let an empty proof column read as a
                # passed attack.
                detail = f"Not attempted in this run (static analysis only). {detail}"
                proved = False
            elif any(f.status in _PROOF_ESTABLISHING for f in for_check):
                pass  # An attack ran and the hole was real. The rule's own detail stands.
            elif any(f.status is FindingStatus.NOT_REPRODUCED for f in for_check):
                # Attempted, and it held. A real result, and a different one from never
                # having tried — the note must claim neither the proof nor the silence.
                detail = (
                    f"Attempted in this run: the attack ran and did not succeed. That is "
                    f"evidence, not a guarantee — it rules out this exploit, not the hole. "
                    f"{detail}"
                )
                proved = False
            else:
                # Argued from the code and never fired — an unreachable target lands here.
                # Saying the attack ran would invent a result from a run that never reached
                # the app, which is the same overclaim in a quieter voice.
                detail = (
                    f"Argued from the code in this run; no attack was run, so nothing here "
                    f"is proof. {detail}"
                )
                proved = False
        notes.append(CoverageNote(check=check, proved=proved, detail=detail))

    # The model's one membership decision, said out loud. A scope it filtered out was never
    # tried and never appears as a candidate, so without this the report of a repository whose
    # fourth scope was dropped reads exactly like the report of a repository with three. That
    # is the same silence the coverage column exists to break.
    filtered_scopes = analysis.filtered_scopes
    if filtered_scopes:
        names = ", ".join(f"`{s.scope}`" for s in filtered_scopes)
        notes.append(
            CoverageNote(
                check=Check.AGENT_INJECTION,
                proved=False,
                detail=(
                    f"{len(filtered_scopes)} agent scope(s) were filtered out before dynamic "
                    f"proof and never attempted: {names}. The model judged a confused-deputy "
                    f"attack implausible there. Dynamic proof is expensive, so this filter "
                    f"exists — but a drop is a judgement, not a result, and these were not "
                    f"shown to be safe."
                ),
            )
        )

    # A pass that failed says so. Its absence from the candidates is not a clean result.
    for gap in analysis.gaps:
        notes.append(CoverageNote(check=gap.check, proved=False, detail=gap.detail))

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


# --------------------------------------------------------------------------- #
# Naming one candidate out of many
#
# A surface shows a list and then has to be told which row the reader meant, across a boundary
# that carries no objects — a CLI flag, an MCP argument, an HTTP body. There are two orders of
# the same set in play and they are not the same order: `build_report` publishes candidates in
# discovery order (carried findings first, then everything untried), while
# `AnalysisResult.ranked()` sorts structural-first then by model score. Rendering one and
# selecting from the other is how a reader asks to fix the RLS row at the top of the table and
# is handed a patch for a BOLA route — and with the model enabled `rank_score` is not stable
# between two runs, so the mismatch is not even reproducible.
#
# So both halves live here, in the engine, and every surface uses them. `published_order` is the
# one list a surface may draw and address; `Candidate.id` is the handle that survives a re-run
# and is what a client should send. The positional form stays supported because a human reading
# a numbered table will always want to type the number.
# --------------------------------------------------------------------------- #
def published_order(
    analysis: AnalysisResult, findings: Optional[list[Finding]] = None
) -> list[Candidate]:
    """The candidates in the order `build_report` publishes them.

    Anything that means "the nth row" has to mean this list and no other.
    """
    report = build_report(analysis, findings)
    return [f.candidate for f in report.findings] + list(report.unproven_candidates)


def select_candidate(
    analysis: AnalysisResult,
    finding_id: Optional[str] = None,
    index: int = 0,
    findings: Optional[list[Finding]] = None,
) -> Candidate:
    """The one candidate a caller named, by id if they gave one and by row if they did not.

    Raises `LookupError` — with a message written for the person who typed the wrong thing —
    rather than returning None, so a surface cannot forget to check and go on to fix whatever
    happened to be at position zero.
    """
    if finding_id:
        for cand in analysis.candidates:
            if cand.id == finding_id:
                return cand
        raise LookupError(
            f"No finding with id {finding_id} in this repository. Re-run the analysis — "
            "the code may have changed since that report was drawn."
        )

    published = published_order(analysis, findings)
    # Negative indices are a valid Python expression and the wrong candidate: `-1` silently
    # addresses the last row when the caller meant to address the first.
    if index < 0 or index >= len(published):
        raise LookupError(
            f"No candidate at index {index}. This report lists {len(published)} "
            f"(0–{len(published) - 1})." if published else
            f"No candidate at index {index}. This report lists none."
        )
    return published[index]
