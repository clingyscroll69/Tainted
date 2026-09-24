"""The core data model — the spine everything in the engine flows through.

A `Candidate` is a static *suspicion*. A `Finding` is a candidate that has been carried
through the pipeline to an outcome (proven, reported, or not-reproduced). Every decision the
engine makes carries `Provenance` (which register/rung produced it) and `Confidence`, so a
skip on an unusual stack is legible and overridable rather than silent.
"""

from __future__ import annotations

import hashlib
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field, computed_field


# --------------------------------------------------------------------------- #
# Enumerations
# --------------------------------------------------------------------------- #
class Plane(str, Enum):
    """The two primary planes untrusted data reaches a dangerous place on."""

    REQUEST = "request"  # untrusted data through code into a database
    TOOL = "tool"  # untrusted data through an agent's tools


class Check(str, Enum):
    """The user-facing unit of work. A plane is architecture; a check is what runs."""

    BOLA = "bola"  # Broken Object Level Authorization (request plane)
    RLS = "rls"  # Row-Level Security missing/permissive (request plane)
    AGENT_INJECTION = "agent_injection"  # confused-deputy prompt injection (tool plane)
    CLASSIC_INJECTION = "classic_injection"  # SQL / command / template injection
    TEST_INTEGRITY = "test_integrity"  # mutation-tested safety net
    TOOL_TENANCY = "tool_tenancy"  # cross-tenant object access through a shared tool backend


CHECK_PLANE: dict[Check, Optional[Plane]] = {
    Check.BOLA: Plane.REQUEST,
    Check.RLS: Plane.REQUEST,
    Check.AGENT_INJECTION: Plane.TOOL,
    Check.CLASSIC_INJECTION: Plane.REQUEST,
    Check.TEST_INTEGRITY: None,  # a codebase-level measurement, not a plane
    Check.TOOL_TENANCY: Plane.TOOL,
}


class Register(str, Enum):
    """Which of the three registers produced a decision."""

    STRUCTURE = "structure"  # deterministic static analysis
    MEANING = "meaning"  # the language model
    PROOF = "proof"  # live execution


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}[self.value]


class FindingStatus(str, Enum):
    CANDIDATE = "candidate"  # static suspicion, not yet tested
    PROVEN = "proven"  # attack carried out and observed to succeed
    REPORTED = "reported"  # argued statically (proof too expensive / unsafe to run)
    NOT_REPRODUCED = "not_reproduced"  # tested and the attack did not succeed
    FIXED = "fixed"  # remediation written and re-verified closed
    BROKE_IT_SAFELY = "broke_it_safely"  # attack blocked but legitimate access also broke


# --------------------------------------------------------------------------- #
# Provenance & confidence — attached to every engine decision
# --------------------------------------------------------------------------- #
class Provenance(BaseModel):
    origin: Register  # which of the three registers produced this decision
    detail: str = ""  # e.g. "static signature: @supabase/supabase-js import"
    rung: Optional[int] = None  # applicability cascade rung, when relevant


class Confidence(BaseModel):
    score: float = Field(ge=0.0, le=1.0)
    rationale: str = ""


# --------------------------------------------------------------------------- #
# Source locations
# --------------------------------------------------------------------------- #
class SourceLocation(BaseModel):
    file: str
    line: int = 0
    end_line: Optional[int] = None
    snippet: str = ""

    def __str__(self) -> str:  # clickable file:line
        return f"{self.file}:{self.line}"


# --------------------------------------------------------------------------- #
# Candidate — a static suspicion
# --------------------------------------------------------------------------- #
class Candidate(BaseModel):
    """A place static analysis suspects untrusted data reaches something dangerous.

    On the request plane the LLM *ranks* candidates (all are tried); on the tool plane's
    dynamic half it *filters* them. `rank_score` records the model's ordering judgment;
    `structural` marks a hole confirmed on inspection (e.g. RLS off on a client-read table),
    which needs no ranking to be real.
    """

    check: Check
    plane: Optional[Plane] = None
    title: str
    description: str = ""
    location: SourceLocation
    # The dataflow, when known: where untrusted data enters and the dangerous place it reaches.
    source: str = ""  # e.g. "route param `id`", "read_email tool"
    sink: str = ""  # e.g. ".from('invoices').select()", "send_email tool"
    # Meaning-register judgments.
    rank_score: Optional[float] = None  # request plane ordering; higher = try sooner
    filtered_in: Optional[bool] = None  # tool plane keep/drop
    structural: bool = False  # confirmed on inspection, independent of the model
    severity: Severity = Severity.MEDIUM
    provenance: list[Provenance] = Field(default_factory=list)
    confidence: Optional[Confidence] = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def id(self) -> str:
        """A stable handle for this hole, derived from where it is rather than when it was found.

        A surface has to be able to say "fix *that* one" across a request boundary, and the
        obvious handle — the position in a list — is wrong in a way that is easy to miss: the
        report publishes candidates in discovery order while `ranked()` sorts them by
        structural-first, then model score, then severity. Two orders of one set. Addressing by
        position meant a reader clicking the second row could be handed the patch for a
        different hole entirely, and with the model enabled `rank_score` is not even stable
        between two analyses of the same tree.

        So the handle is computed from the hole's own coordinates: which check found it, the
        file and line it sits on, and the dangerous place it reaches. Deliberately excluded are
        `rank_score`, `filtered_in`, `severity` and `description` — every field a second run or
        a model call could move. Two analyses of an unchanged tree therefore agree, which is
        the property `test_fix_identity` pins.

        Not a security boundary: it identifies a finding, it does not authorise anything. The
        16 hex characters are for a URL fragment and a log line, not for unguessability.
        """
        seed = "\x1f".join(
            (
                self.check.value,
                self.plane.value if self.plane else "",
                self.location.file,
                str(self.location.line),
                self.sink,
                self.title,
            )
        )
        return hashlib.sha256(seed.encode("utf-8")).hexdigest()[:16]

    def __str__(self) -> str:
        return f"[{self.check.value}] {self.title} ({self.location})"


# --------------------------------------------------------------------------- #
# Exploit & proof
# --------------------------------------------------------------------------- #
class Exploit(BaseModel):
    """The exact attack that was (or would be) carried out."""

    description: str
    # For the request plane: a raw HTTP request, printable verbatim.
    method: Optional[str] = None
    url: Optional[str] = None
    headers: dict[str, str] = Field(default_factory=dict)
    body: Optional[str] = None
    # For the tool plane: the generated injection payload.
    payload: Optional[str] = None
    executed: bool = False  # False when demonstrated-but-held (cmd/template injection)


class ProbeResult(BaseModel):
    """The observed outcome of firing one probe."""

    succeeded: bool
    kind: str = ""  # "targeted_bola" | "unfiltered_rls" | "agent_injection" | ...
    exploit: Optional[Exploit] = None
    # The response that proves (or refutes) the leak — the thing a reader trusts.
    response_status: Optional[int] = None
    response_body: str = ""
    rows_returned: Optional[int] = None
    row_cap: Optional[int] = None  # the cap applied to the unfiltered read
    notes: str = ""


# --------------------------------------------------------------------------- #
# Finding — a candidate carried to an outcome
# --------------------------------------------------------------------------- #
class Finding(BaseModel):
    candidate: Candidate
    status: FindingStatus = FindingStatus.CANDIDATE
    proof: Optional[ProbeResult] = None
    recommended_fix: str = ""
    provenance: list[Provenance] = Field(default_factory=list)

    @property
    def check(self) -> Check:
        return self.candidate.check

    @property
    def severity(self) -> Severity:
        return self.candidate.severity

    def __str__(self) -> str:
        return f"<{self.status.value}> {self.candidate}"


# --------------------------------------------------------------------------- #
# Fix
# --------------------------------------------------------------------------- #
class FileEdit(BaseModel):
    file: str
    original: str = ""
    replacement: str = ""
    description: str = ""


class ReverifyAssertion(BaseModel):
    """A single re-verification claim and whether it held."""

    name: str  # "attack_now_fails" | "legitimate_access_survives" | ...
    passed: bool
    detail: str = ""


class FixResult(BaseModel):
    finding: Finding
    edits: list[FileEdit] = Field(default_factory=list)
    # Re-verification. A fix is only FIXED when the attack fails AND legitimate access
    # survives — a policy that locks out the real owner is secure and broken.
    assertions: list[ReverifyAssertion] = Field(default_factory=list)
    resulting_status: FindingStatus = FindingStatus.CANDIDATE
    notes: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)

    @property
    def all_assertions_passed(self) -> bool:
        return bool(self.assertions) and all(a.passed for a in self.assertions)


# --------------------------------------------------------------------------- #
# Applicability & top-level results
# --------------------------------------------------------------------------- #
class ApplicabilityDecision(BaseModel):
    """Whether a plane/check applies to the target, and why — always legible."""

    plane: Optional[Plane] = None
    check: Optional[Check] = None
    applies: bool
    established: bool  # True = a rung positively decided; False = genuine doubt (so it runs)
    provenance: Provenance
    confidence: Confidence
    overridden: bool = False


class MutationSummary(BaseModel):
    """The test-integrity measurement: how much of the safety net is actually watching.

    Not a vulnerability and not a plane — a number, which is why it lives in the report rather
    than the foreground. A high surviving-mutant rate is the whole-suite echo of Tainted's own
    caveat: it proves what it finds, not what it misses.
    """

    tool: str
    available: bool
    total: int = 0
    killed: int = 0
    survived: int = 0
    score: Optional[float] = None  # killed / total
    note: str = ""


class FilteredScope(BaseModel):
    """One agent scope the model dropped before dynamic proof, and why it said it did.

    `rationale` is the model's own words and comes, indirectly, from the repository under
    analysis — render it as a quotation, never as Tainted's finding.
    """

    scope: str
    rationale: str = ""


class AnalysisGap(BaseModel):
    """A pass that should have run and could not, and why.

    Distinct from a plane applicability skipped: that is a decision, this is a failure. A
    tool-plane pass whose labelling call failed returns no candidates, and without this record
    its report is indistinguishable from one for a repository with no agents at all.
    """

    check: Check
    detail: str


class AnalysisResult(BaseModel):
    """The output of `analyze`: candidates plus the applicability decisions behind them."""

    repo_path: str
    candidates: list[Candidate] = Field(default_factory=list)
    applicability: list[ApplicabilityDecision] = Field(default_factory=list)
    stack: dict[str, Any] = Field(default_factory=dict)  # detected stack facts
    mutation: Optional[MutationSummary] = None
    # Tool-plane scopes the model filtered out before dynamic proof, with its reason.
    #
    # This is the engine's one *membership* decision made by the model: `rank` only orders the
    # request plane and every candidate is tried regardless, but a `False` here removes a scope
    # from the run entirely. That drop previously left no trace at all — the report simply
    # contained fewer scopes, indistinguishable from a repository that had fewer. Recording it
    # is what lets the report say how far the run reached instead of implying it reached
    # everything, which is the product's standing rule about proof strength applied to the
    # filter itself.
    filtered_scopes: list[FilteredScope] = Field(default_factory=list)
    gaps: list[AnalysisGap] = Field(default_factory=list)

    def by_check(self, check: Check) -> list[Candidate]:
        return [c for c in self.candidates if c.check == check]

    def ranked(self) -> list[Candidate]:
        """Request-plane order: structural holes first, then by model rank, then severity."""
        return sorted(
            self.candidates,
            key=lambda c: (
                not c.structural,
                -(c.rank_score or 0.0),
                -c.severity.rank,
            ),
        )
