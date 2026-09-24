"""Wire the engine's plan-commitment self-defense into prove's live HTTP calls.

Before `prove` touches the target it commits to a probe plan — the bounded set of requests it
will make. Every outgoing request is checked against that committed plan via an httpx request
hook; anything not in the plan (an exfiltration the tool "decided" to do after reading target
content) is refused. This is the product guarding its own most dangerous tool with its own thesis.

**Why the signature is not decoration here.** Committing and enforcing in one breath would make
the HMAC ceremonial: nothing could tamper in between. So the boundary is real — the plan is
built and signed on the MCP request thread, handed to the job record, and verified again in the
worker thread that actually fires the probes. The plan therefore has to survive being stored and
passed around, and the signature is what makes that survival checkable. The run key crosses to
the container with the plan, because the boundary is now a process boundary rather than a thread
boundary and a per-process key could not verify on the far side. It is scoped to one run and
travels only on the container we spawn. See `new_run_key`.
"""

from __future__ import annotations

import os

import httpx

from tainted.dynamic.replay import SupabaseReplay
from tainted.dynamic.target import ProveSetup
from tainted.selfdefense import AllowedCall, PlanGuard, ProbePlan, commit

def new_run_key() -> bytes:
    """A fresh signing key for one prove run.

    This used to be one secret per server process, held only in memory and never crossing a
    boundary. That worked while the only boundary was a thread. It cannot work now: the plan is
    signed on the host and enforced inside a container, which is a different process with a
    different memory, so a per-process key would fail to verify on every single run.

    So the key is per *run* instead of per process, and it does cross — as an env var on the
    container we spawn, over a pipe nobody else is on. What that buys is the property the
    signature exists for: the plan is genuinely re-verified after crossing a real boundary,
    rather than committed and enforced in one breath, which would make the HMAC ceremonial.
    What it costs is that the key is no longer memory-only. The blast radius of a leaked key is
    one run: forging a probe plan for a run that is already happening, on a target the caller
    already named.
    """
    return os.urandom(32)


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
            # The same routes in every other method route discovery can name. A candidate on a
            # POST or DELETE route is probed with that method; committing GET alone refused
            # those probes and aborted the whole run as though the guard had caught an
            # exfiltration. Writes stay off PostgREST and GoTrue even when the app and the
            # database share a base URL: prove reads the database, it never writes to it.
            *(
                AllowedCall(
                    tool=method,
                    arg_constraints={"url": f"re:{_esc(app)}/(?!rest/v1/|auth/v1/).*"},
                )
                for method in _ROUTE_WRITE_METHODS
            ),
        ],
    )


# Every method `tainted.static.routes` recovers beyond GET, uppercased as the prober sends it. A
# catch-all route (`*`) is sent as GET, which the read entry above already commits.
_ROUTE_WRITE_METHODS = ("POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS")


def commit_plan(plan: ProbePlan, key: bytes) -> str:
    """Sign a plan with this run's key. The signature and the key travel together, to the
    container and nowhere else."""
    return commit(plan, key)


def _esc(s: str) -> str:
    import re

    return re.escape(s)


def guarded_replay(
    setup: ProveSetup,
    plan: ProbePlan,
    signature: str,
    key: bytes,
) -> tuple[SupabaseReplay, PlanGuard]:
    """A SupabaseReplay whose httpx client refuses any request outside the committed plan.

    The plan, its signature and the run key all arrive from the host that committed them; the
    guard re-verifies the signature before enforcing, so a plan altered in transit is rejected
    rather than obeyed.
    """
    guard = PlanGuard(plan, signature, key)  # raises PlanViolation if tampered with

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
