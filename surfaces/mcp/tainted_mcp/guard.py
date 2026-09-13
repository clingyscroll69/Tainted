"""Wire the engine's plan-commitment self-defense into prove's live HTTP calls.

Before `prove` touches the target it commits to a probe plan — the bounded set of requests it
will make. Every outgoing request is checked against that committed plan via an httpx request
hook; anything not in the plan (an exfiltration the tool "decided" to do after reading target
content) is refused. This is the product guarding its own most dangerous tool with its own thesis.

**Why the signature is not decoration here.** Committing and enforcing in one breath would make
the HMAC ceremonial: nothing could tamper in between. So the boundary is real — the plan is
built and signed on the MCP request thread, handed to the job record, and verified again in the
worker thread that actually fires the probes. The plan therefore has to survive being stored and
passed around, and the signature is what makes that survival checkable. The process secret never
leaves memory and never crosses that boundary with the plan.
"""

from __future__ import annotations

import os
from typing import Optional

import httpx

from tainted.dynamic.replay import SupabaseReplay
from tainted.dynamic.target import ProveSetup
from tainted.selfdefense import AllowedCall, PlanGuard, ProbePlan, commit

# One secret per server process, held only in memory. A plan signed by this process can only be
# verified by this process, which is the property that matters: a plan that arrives at the
# worker unsigned or re-signed by anything else does not verify.
_SECRET = os.urandom(32)


def build_probe_plan(setup: ProveSetup) -> ProbePlan:
    """The enumerable set of calls prove legitimately makes against the named target.

    This is the whole reason plan-commitment is airtight for `prove` in particular. Most agents
    cannot pre-commit, because what they do next legitimately depends on what they read. `prove`
    has no such legitimate dynamism: it fires a bounded set of probes at a human-named target
    and should never do something new because of what came back.
    """
    base = setup.target.rest_base
    app = setup.target.url.rstrip("/")
    return ProbePlan(
        target_url=setup.target.url,
        allowed=[
            # Password-grant authentication for A and B.
            AllowedCall(tool="POST", arg_constraints={"url": f"{base}/auth/v1/token"}),
            # PostgREST reads only, only on this target's /rest/v1/ path.
            AllowedCall(tool="GET", arg_constraints={"url": f"re:{_esc(base)}/rest/v1/.*"}),
            # The app's own routes, for route-discovered BOLA findings.
            AllowedCall(tool="GET", arg_constraints={"url": f"re:{_esc(app)}/.*"}),
        ],
    )


def commit_plan(plan: ProbePlan) -> str:
    """Sign a plan with the process secret. The signature travels; the secret does not."""
    return commit(plan, _SECRET)


def _esc(s: str) -> str:
    import re

    return re.escape(s)


def guarded_replay(
    setup: ProveSetup,
    plan: Optional[ProbePlan] = None,
    signature: Optional[str] = None,
) -> tuple[SupabaseReplay, PlanGuard]:
    """A SupabaseReplay whose httpx client refuses any request outside the committed plan.

    Passing a `plan`/`signature` pair that was committed earlier is the real path: the guard
    re-verifies the signature before enforcing, so a plan altered in transit is rejected rather
    than obeyed. Omitting them commits on the spot, which is only appropriate when there is no
    boundary to cross.
    """
    if plan is None:
        plan = build_probe_plan(setup)
        signature = commit_plan(plan)
    elif signature is None:
        raise ValueError("A pre-built probe plan must arrive with its signature.")

    guard = PlanGuard(plan, signature, _SECRET)  # raises PlanViolation if tampered with

    def _check(request: httpx.Request) -> None:
        # Strip query string for the URL match; the plan constrains path + method.
        url = str(request.url).split("?", 1)[0]
        guard.check(request.method, {"url": url})

    client = httpx.Client(timeout=20.0, event_hooks={"request": [_check]})
    return SupabaseReplay(setup.target, client), guard


def guarded_prober(setup: ProveSetup, guard: PlanGuard):
    """A RouteProber sharing the same committed plan, so route probes are guarded too.

    A guard that covered only the PostgREST client would leave the app-route harness — which
    sends requests to arbitrary paths — entirely unguarded, which is the half that most needs it.
    """
    from tainted.dynamic.route_probes import RouteProber

    def _check(request: httpx.Request) -> None:
        guard.check(request.method, {"url": str(request.url).split("?", 1)[0]})

    client = httpx.Client(
        timeout=20.0, follow_redirects=True, event_hooks={"request": [_check]}
    )
    return RouteProber(setup, client=client)
