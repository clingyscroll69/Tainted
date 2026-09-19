import pytest

from tainted.dynamic.target import Account, ProveSetup, Target
from tainted.execution.guard import (
    build_probe_plan,
    commit_plan,
    guarded_replay,
    new_run_key,
)
from tainted.selfdefense import PlanViolation


def _setup() -> ProveSetup:
    return ProveSetup(
        target=Target(url="http://localhost:3000"),
        account_a=Account(label="A"),
        account_b=Account(label="B"),
    )


def test_two_run_keys_are_different():
    """Per-run, not per-process: the whole point of the change."""
    assert new_run_key() != new_run_key()


def test_a_plan_verifies_under_the_key_it_was_signed_with():
    setup, key = _setup(), new_run_key()
    plan = build_probe_plan(setup)
    signature = commit_plan(plan, key)
    replay, guard = guarded_replay(setup, plan, signature, key)
    assert guard.plan.target_url == "http://localhost:3000"


def test_a_plan_does_not_verify_under_a_different_key():
    """The regression guard for the bug this task exists to fix: signing in one process and
    verifying in another must fail loudly, not silently pass."""
    setup = _setup()
    plan = build_probe_plan(setup)
    signature = commit_plan(plan, new_run_key())
    with pytest.raises(PlanViolation):
        guarded_replay(setup, plan, signature, new_run_key())
