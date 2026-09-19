"""Where a `prove` run executes, and how a surface asks for one.

`prove` executes untrusted, network-active exploit code. Running it in the process that asked
for it means a generated payload and the tool that generated it share a machine, a filesystem
and a uid. This package is the seam that lets a surface put a container between them.

It lives in the engine rather than in a surface because all three surfaces that run `prove`
need it. It is deliberately **not** called `sandbox`: `tainted/dynamic/sandbox.py` already owns
that word for the agent-plane logging-stub sandbox, which is a different concept — an equivalent
agent stood up from a manifest, not OS-level containment. Two things called "sandbox" in one
engine is how the next reader loses an hour.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Optional, Protocol

from tainted import analyze as core_analyze
from tainted import prove as core_prove
from tainted.dynamic.target import ProveSetup
from tainted.llm.gemini import get_default_client
from tainted.models import Candidate, Finding
from tainted.report import Report, build_report
from tainted.selfdefense import ProbePlan

OnCandidates = Callable[[list[Candidate]], None]
OnFinding = Callable[[Finding], None]


class SandboxUnavailable(RuntimeError):
    """Raised when a sandboxed run was required and the sandbox could not be provided.

    Always carries what is missing — daemon, image, version skew, or the macOS host-networking
    toggle — because a refusal a user cannot act on is merely a failure.
    """


@dataclass
class ProveOutcome:
    """A finished run, plus what the guard refused along the way.

    `blocked_calls` is part of the result rather than read off a guard object because the guard
    now lives inside a container: there is no shared object for the caller to inspect afterwards.
    """

    report: Report
    blocked_calls: list[dict] = field(default_factory=list)


def _llm_or_none():
    llm = get_default_client(reload=True)
    return llm if llm.available else None


class Executor(Protocol):
    sandboxed: bool
    # `streams` is the executor's own answer to "can you report this run as it happens?".
    # A surface reads it rather than inferring from whether callbacks fired, because "no events
    # yet" and "no events ever" are different things and a progress indicator that confuses them
    # claims to know something it does not.
    streams: bool

    def analyze(
        self, repo_path: str, only=None, skip=None
    ) -> Report: ...

    def prove(
        self,
        repo_path: str,
        setup: ProveSetup,
        ownership_verified: bool,
        autodiscover: bool = False,
        plan: Optional[ProbePlan] = None,
        plan_signature: Optional[str] = None,
        run_key: Optional[bytes] = None,
        on_candidates: Optional[OnCandidates] = None,
        on_finding: Optional[OnFinding] = None,
    ) -> ProveOutcome: ...


class LocalExecutor:
    """Runs in-process. Correct for `analyze`, and for `prove` only where the caller has said
    out loud that it accepts an uncontained run — see `TAINTED_REQUIRE_SANDBOX`."""

    sandboxed = False
    streams = True

    def analyze(self, repo_path: str, only=None, skip=None) -> Report:
        return build_report(
            core_analyze(repo_path, llm=_llm_or_none(), only=only, skip=skip)
        )

    def prove(
        self,
        repo_path: str,
        setup: ProveSetup,
        ownership_verified: bool,
        autodiscover: bool = False,
        plan: Optional[ProbePlan] = None,
        plan_signature: Optional[str] = None,
        run_key: Optional[bytes] = None,
        on_candidates: Optional[OnCandidates] = None,
        on_finding: Optional[OnFinding] = None,
    ) -> ProveOutcome:
        from tainted.execution.guard import guarded_prober, guarded_replay

        llm = _llm_or_none()
        result = core_analyze(repo_path, llm=llm, target=setup.target)
        # In ranked order, because that is the order they will be attempted in. A surface that
        # draws them in some other order is drawing its own order, not the run's.
        if on_candidates is not None:
            on_candidates(result.ranked())

        supplied = [plan is not None, plan_signature is not None, run_key is not None]
        if any(supplied) and not all(supplied):
            raise ValueError(
                "A guarded run needs the plan, its signature and the run key together. "
                "Got a partial set, which would otherwise have run unguarded — refusing "
                "rather than quietly downgrading the containment the caller asked for."
            )

        replay = prober = None
        guard = None
        if plan is not None and plan_signature is not None and run_key is not None:
            replay, guard = guarded_replay(setup, plan, plan_signature, run_key)
            prober = guarded_prober(setup, guard)

        findings: list[Finding] = core_prove(
            result,
            setup,
            replay=replay,
            prober=prober,
            ownership_verified=ownership_verified,
            autodiscover=autodiscover,
            llm=llm,
            on_finding=on_finding,
        )
        return ProveOutcome(
            report=build_report(result, findings),
            blocked_calls=guard.blocked_calls if guard is not None else [],
        )
