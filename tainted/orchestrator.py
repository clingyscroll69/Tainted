"""The engine's three operations, composed over the selected checks.

`analyze` decides what to attack (static, universal, read-only). `prove` decides what is real
(dynamic, ownership-gated off localhost). `fix` closes it (writes the remediation and
re-verifies by the loop its plane requires). Surfaces are thin adapters over these.
"""

from __future__ import annotations

from typing import Callable, Optional, Sequence

from tainted.applicability import BehavioralProbe, decide_plane
from tainted.budget import Budget
from tainted.checks.classic_injection import scan_classic_injection
from tainted.checks.request_plane import analyze_request_plane
from tainted.checks.test_integrity import CommandRunner, measure_test_integrity
from tainted.checks.tool_plane import analyze_tool_plane
from tainted.dynamic.agent_driver import AgentDriver, build_driver
from tainted.dynamic.injection_probes import prove_sql_injection
from tainted.dynamic.probes import prove_candidate
from tainted.dynamic.replay import SupabaseReplay
from tainted.dynamic.route_probes import RouteProber
from tainted.dynamic.sandbox import run_sandbox
from tainted.dynamic.target import ProveSetup, Target
from tainted.fix.deterministic import generate_rls_fix
from tainted.fix.interview import InterviewAnswer, resolve_tool_plane_fix
from tainted.fix.reverify import reverify_request_plane, reverify_tool_plane
from tainted.fix.tool_plane_fix import generate_tool_plane_fix
from tainted.llm.client import LLMClient, LLMUnavailable
from tainted.models import (
    AnalysisResult,
    ApplicabilityDecision,
    Candidate,
    Check,
    FilteredScope,
    Finding,
    FindingStatus,
    FixResult,
    Plane,
    ProbeResult,
    Provenance,
    Register,
)
from tainted.static.tools import AgentScope, discover_scopes

# Paths a behavioral probe (applicability rung 3) tries with no credentials. Reaching protected
# data as nobody is missing auth — a finding, not merely a detection.
DEFAULT_PROTECTED_PATHS = [
    "/api/me",
    "/api/user",
    "/api/users",
    "/api/account",
    "/api/profile",
    "/api/orders",
    "/api/invoices",
]


# --------------------------------------------------------------------------- #
# analyze
# --------------------------------------------------------------------------- #
def analyze(
    repo_path: str,
    llm: Optional[LLMClient] = None,
    only: Optional[set[Check]] = None,
    skip: Optional[set[Check]] = None,
    target: Optional[Target] = None,
    behavioral_probe: Optional[BehavioralProbe] = None,
    mutation_runner: Optional[CommandRunner] = None,
    exclude: Sequence[str] = (),
) -> AnalysisResult:
    """Static pass over a repository. Read-only, universal, produces ranked candidates.

    `only`/`skip` are the user-facing check overrides. The applicability cascade decides which
    planes the target has; a plane runs unless a rung positively established its absence.

    `target` enables the cascade's third rung: when the cheap rungs and the model are all
    inconclusive, and the owner's app is up, an unauthenticated request settles it. Passing no
    target simply stops the cascade one rung earlier — it never turns doubt into a skip.

    `exclude` is the caller's list of demo/fixture/specimen paths to leave unscanned, on top of
    the machine-generated trees every walker already skips. Deliberately-vulnerable sample code
    is the motivating case: without it, pointing Tainted at a repo that ships intentional holes
    (its own included) reports those specimens as if the running app were vulnerable.
    """
    candidates: list[Candidate] = []
    active = _active_checks(only, skip)
    decisions: list[ApplicabilityDecision] = []
    if target is not None and behavioral_probe is None:
        behavioral_probe = BehavioralProbe(DEFAULT_PROTECTED_PATHS)

    # Request plane — run unless applicability positively established its absence.
    request_decision = decide_plane(
        Plane.REQUEST, repo_path, llm=llm, target=target, behavioral_probe=behavioral_probe
    )
    decisions.append(request_decision)
    if request_decision.applies:
        request_checks = active & {Check.BOLA, Check.RLS}
        if request_checks:
            candidates.extend(
                analyze_request_plane(
                    repo_path, llm=llm, checks=request_checks, exclude=exclude
                )
            )
        if Check.CLASSIC_INJECTION in active:
            candidates.extend(scan_classic_injection(repo_path, exclude))

    # Tool plane — same rule. Labeling/filtering needs the LLM; without it the pass is empty.
    tool_decision = decide_plane(
        Plane.TOOL, repo_path, llm=llm, target=target, behavioral_probe=behavioral_probe
    )
    decisions.append(tool_decision)
    # What the model filtered out travels with the result, so the report can say a scope was
    # dropped rather than look identical to a repository that never had one.
    filtered_scopes: list[FilteredScope] = []
    if tool_decision.applies and Check.AGENT_INJECTION in active:
        candidates.extend(
            analyze_tool_plane(
                repo_path, llm=llm, dropped=filtered_scopes, exclude=exclude
            )
        )

    # Test integrity — a codebase-level measurement, not a plane, so no applicability gate.
    # It is opt-in by cost, not by relevance: a mutation campaign is minutes, not milliseconds.
    mutation = None
    if Check.TEST_INTEGRITY in active and (only or mutation_runner is not None):
        mutation, mutant_candidates = measure_test_integrity(
            repo_path, runner=mutation_runner
        )
        candidates.extend(mutant_candidates)

    return AnalysisResult(
        repo_path=repo_path,
        candidates=candidates,
        applicability=decisions,
        mutation=mutation,
        filtered_scopes=filtered_scopes,
    )


def _active_checks(only: Optional[set[Check]], skip: Optional[set[Check]]) -> set[Check]:
    active = set(only) if only else set(Check)
    if skip:
        active -= skip
    return active


# --------------------------------------------------------------------------- #
# prove
# --------------------------------------------------------------------------- #
class OwnershipError(PermissionError):
    """Raised when `prove` is aimed at a non-local target without proof of ownership."""


def prove(
    analysis: AnalysisResult,
    setup: ProveSetup,
    replay: Optional[SupabaseReplay] = None,
    ownership_verified: bool = False,
    llm: Optional[LLMClient] = None,
    driver: Optional[AgentDriver] = None,
    prober: Optional[RouteProber] = None,
    autodiscover: bool = False,
    on_finding: Optional[Callable[[Finding], None]] = None,
    budget: Optional["Budget"] = None,
) -> list[Finding]:
    """Fire live probes at the running target for each candidate, in ranked order.

    Ownership-gated: a local target needs nothing; a non-local target must have had ownership
    verified out of band (`ownership_verified=True`) — see `tainted.ownership`.

    Each check is proven by the harness its danger allows:
      * BOLA / RLS — a real request, two probes, surgical before blunt.
      * Classic injection — SQL live against the running target; command and template
        **demonstrated and never executed**, because running `rm -rf` to prove a point is worse
        than the bug.
      * Agent injection — a configured agent stood up from its manifest with logging stubs for
        sinks. Coded agents are reported from the static graph and say so.

    `on_finding` is an optional progress observer, called once per finding in the order they are
    produced. It exists so a surface can report a run *while it happens* rather than only when it
    ends; it is handed a result, never asked for a decision, and it cannot change the order
    anything is attempted in. The return value is the same list either way.
    """
    if not setup.target.is_local and not ownership_verified:
        raise OwnershipError(
            "prove targets a non-local URL without verified ownership. Verify via DNS TXT, "
            "a /.well-known/tainted-verify file, or CI OIDC before proving a remote target."
        )

    # Autonomy empties the seed field when it can, and leaves it alone when it cannot. Walking
    # as A (never B) is the point: the probe asks whether B can read something *of A's*.
    if autodiscover and setup.seed is None:
        from tainted.dynamic.discovery import seed_from_discovery

        discovered, _why = seed_from_discovery(setup)
        if discovered is not None:
            setup.seed = discovered

    replay = replay or SupabaseReplay(setup.target)
    prober = prober or RouteProber(setup)
    scopes: Optional[list[AgentScope]] = None
    findings: list[Finding] = []

    # Ranked order: structural holes first, then model rank, then severity. Everything is
    # tried — the ordering only decides who goes first.
    if budget is not None:
        budget.start()
    for candidate in analysis.ranked():
        # A budget is checked *between* candidates, never during one: a half-fired probe proves
        # nothing. When it is spent the loop stops and returns everything proven so far — the
        # graceful stop. The caller reads `budget.attempted` to report how many were skipped, so
        # a capped run can never be mistaken for a complete one with no findings.
        if budget is not None and budget.exhausted() is not None:
            break
        if budget is not None:
            budget.note_attempt()
        finding: Optional[Finding] = None
        if candidate.check in (Check.BOLA, Check.RLS):
            finding = _prove_request_plane(candidate, setup, replay, prober)
        elif candidate.check is Check.CLASSIC_INJECTION:
            finding = prove_sql_injection(candidate, setup, prober)
        elif candidate.check is Check.AGENT_INJECTION:
            if scopes is None:
                scopes = _discover_labelled_scopes(analysis.repo_path, llm)
            finding = _prove_tool_plane(candidate, scopes, llm, driver)
        elif candidate.check is Check.TEST_INTEGRITY:
            # The surviving mutant *is* the proof; there is no dynamic step to run.
            finding = Finding(
                candidate=candidate,
                status=FindingStatus.REPORTED,
                proof=ProbeResult(
                    succeeded=True,
                    kind="mutation",
                    notes="A surviving mutant is its own evidence. No probe is needed.",
                ),
            )
        if finding is None:
            continue
        findings.append(finding)
        # The progress hook, and the only thing it may be: an observer. It is handed each
        # finding at the moment that finding exists, so a surface can report a run as it
        # happens instead of only when it ends. It cannot change what is attempted, in what
        # order, or what comes back — a caller that raises from here would abort a live run
        # for the sake of a picture, so it does not get to.
        if on_finding is not None:
            try:
                on_finding(finding)
            except Exception:  # noqa: BLE001 - an observer may not break the run
                pass
    return findings


def _prove_request_plane(
    candidate: Candidate,
    setup: ProveSetup,
    replay: SupabaseReplay,
    prober: RouteProber,
) -> Finding:
    """Route candidates go through the app's own HTTP surface; table candidates via PostgREST.

    A BOLA candidate discovered from a route names a URL, so the honest proof is to *request
    that URL* as B. Falling back to PostgREST for it would prove something adjacent to the
    finding rather than the finding itself.
    """
    if candidate.check is Check.BOLA and candidate.metadata.get("route_path"):
        return prober.prove_route_bola(candidate)
    return prove_candidate(candidate, setup, replay)


def _discover_labelled_scopes(
    repo_path: str, llm: Optional[LLMClient]
) -> list[AgentScope]:
    """Scopes with their tools labelled source/sink/neither.

    The labelling is not optional here. An unlabelled scope has no sinks, so the sandbox would
    stand up an agent with nothing to fire, observe nothing fire, and record NOT_REPRODUCED —
    a false negative that looks exactly like a resistant agent.
    """
    from tainted.checks.tool_plane import label_scopes

    scopes = discover_scopes(repo_path)
    if llm is not None and scopes:
        try:
            label_scopes(scopes, llm)
        except LLMUnavailable:
            pass
    return scopes


def _prove_tool_plane(
    candidate: Candidate,
    scopes: list[AgentScope],
    llm: Optional[LLMClient],
    driver: Optional[AgentDriver],
) -> Finding:
    """Stand the configured agent up from its manifest and try to turn it."""
    scope = _scope_for(candidate, scopes)
    if scope is None:
        return Finding(
            candidate=candidate,
            status=FindingStatus.NOT_REPRODUCED,
            proof=ProbeResult(
                succeeded=False,
                kind="agent_injection",
                notes="The agent scope this possible hole names was not found in the repository.",
            ),
        )

    if driver is None:
        # `build_driver` answers None for an LLM that exists but is not available — a key that
        # was never set, a client constructed from an empty config. Only `llm is None` was
        # checked, so that case fell through to `run_sandbox(..., driver=None)` and the sandbox
        # called a method on it. It survived because `generate_injection` below happens to raise
        # `LLMUnavailable` first, which is a rescue by coincidence and not by design: any
        # injectable client that answers while reporting itself unavailable reaches the sandbox
        # with nothing to drive it.
        driver = build_driver(llm)
        if driver is None:
            return _unprovable(
                candidate,
                "No LLM configured. The sandbox needs a model to drive the agent. "
                "Reported from static analysis only.",
            )

    if llm is None:
        return _unprovable(
            candidate, "No LLM configured. Tainted cannot generate an injection payload."
        )
    try:
        injection = llm.generate_injection(
            {
                "scope": scope.name,
                "sources": [t.as_prompt_dict() for t in scope.sources],
                "sinks": [t.as_prompt_dict() for t in scope.sinks],
            }
        )
    except LLMUnavailable:
        return _unprovable(candidate, "LLM unavailable. No injection was generated.")

    return run_sandbox(candidate, scope, injection, driver)


def _scope_for(candidate: Candidate, scopes: list[AgentScope]) -> Optional[AgentScope]:
    name = candidate.metadata.get("scope")
    for scope in scopes:
        if scope.name == name:
            return scope
    return None


def _unprovable(candidate: Candidate, why: str) -> Finding:
    finding = Finding(
        candidate=candidate,
        status=FindingStatus.REPORTED,
        proof=ProbeResult(succeeded=False, kind="agent_injection", notes=why),
    )
    finding.provenance.append(
        Provenance(origin=Register.STRUCTURE, detail="static-only: dynamic proof unavailable")
    )
    return finding


# --------------------------------------------------------------------------- #
# fix
# --------------------------------------------------------------------------- #
def fix(
    finding: Finding,
    setup: Optional[ProveSetup] = None,
    replay_after: Optional[SupabaseReplay] = None,
    answers: Optional[list[InterviewAnswer]] = None,
    llm: Optional[LLMClient] = None,
    driver: Optional[AgentDriver] = None,
    repo_path: Optional[str] = None,
    prober: Optional[RouteProber] = None,
) -> FixResult:
    """Write the remediation and re-verify it by the loop the finding's plane requires.

    Three shapes, decided by one question — what does the correct fix depend on that the code
    doesn't contain?

      * **Nothing** (request plane, classic injection): the code determines the fix. Written
        directly, re-verified by *re-proving* — the surface didn't move, so the old exploit is
        still aimed correctly and simply now fails. Two assertions: the attack fails AND
        legitimate access survives.
      * **User intent about structure** (tool plane): which of four remediations is right isn't
        in the code. Requires `answers` from the interview. Re-verified by re-analysing and
        proving *fresh*, because the fix reshapes the graph it was measured on.
      * **User intent about correctness** (test integrity): only the developer knows whether
        current behavior is intended, so this returns the question, never an auto-written test.
    """
    if finding.check in (Check.BOLA, Check.RLS):
        return _fix_request_plane(finding, setup, replay_after, prober)
    if finding.check is Check.AGENT_INJECTION:
        return _fix_tool_plane(finding, answers, llm, driver, repo_path)
    if finding.check is Check.TEST_INTEGRITY:
        return _fix_test_integrity(finding)
    if finding.check is Check.CLASSIC_INJECTION:
        return _fix_classic_injection(finding)
    raise NotImplementedError(f"No fix strategy for {finding.check}.")


def _fix_request_plane(
    finding: Finding,
    setup: Optional[ProveSetup],
    replay_after: Optional[SupabaseReplay],
    prober: Optional[RouteProber],
) -> FixResult:
    from tainted.fix.deterministic import generate_bola_fix

    if finding.check is Check.BOLA and finding.candidate.metadata.get("route_path"):
        edits, note, _complete = generate_bola_fix(finding.candidate)
    else:
        edits, note, _complete = generate_rls_fix(finding.candidate)
    result = FixResult(finding=finding, edits=edits, notes=note)

    if setup is not None and replay_after is not None:
        reverify_request_plane(result, setup, replay_after, prober=prober)
    else:
        result.notes += " (patch-only: no target given, so the loop is not closed)"
    return result


def _fix_tool_plane(
    finding: Finding,
    answers: Optional[list[InterviewAnswer]],
    llm: Optional[LLMClient],
    driver: Optional[AgentDriver],
    repo_path: Optional[str],
) -> FixResult:
    if not answers:
        raise ValueError(
            "The tool-plane fix is architecturally underdetermined: which remediation is correct "
            "depends on facts only the developer holds. Run `tool_plane_interview(candidate)` "
            "and pass the answers."
        )
    remediation = resolve_tool_plane_fix(answers)
    edits, note = generate_tool_plane_fix(finding.candidate, remediation)
    result = FixResult(finding=finding, edits=edits, notes=note)
    result.metadata["remediation"] = remediation.value

    if repo_path is not None:
        reverify_tool_plane(result, repo_path, llm=llm, driver=driver)
    else:
        result.notes += (
            " (patch-only: no repository given, so Tainted did not re-check the changed graph)"
        )
    return result


def _fix_test_integrity(finding: Finding) -> FixResult:
    """Never auto-assert a test from the code the check exists to distrust."""
    result = FixResult(finding=finding, edits=[])
    result.notes = (
        "Only you know if the current behavior is right. A test that kills this mutant would "
        "assert that it is, and the code is exactly what this check does not trust. Answer the "
        "question in the finding. Tainted will not write that test for you."
    )
    result.resulting_status = FindingStatus.REPORTED
    return result


def _fix_classic_injection(finding: Finding) -> FixResult:
    from tainted.fix.deterministic import generate_injection_fix

    edits, note = generate_injection_fix(finding.candidate)
    return FixResult(finding=finding, edits=edits, notes=note)
