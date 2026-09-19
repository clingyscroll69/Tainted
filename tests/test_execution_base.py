from tainted.execution.base import LocalExecutor, ProveOutcome, SandboxUnavailable


def test_local_executor_is_not_sandboxed_and_says_so():
    """The honesty property: a surface must be able to ask, not infer."""
    ex = LocalExecutor()
    assert ex.sandboxed is False
    assert ex.streams is True


def test_prove_outcome_carries_blocked_calls():
    outcome = ProveOutcome(report=None, blocked_calls=[{"tool": "GET"}])
    assert outcome.blocked_calls == [{"tool": "GET"}]


def test_sandbox_unavailable_is_a_runtime_error():
    assert issubclass(SandboxUnavailable, RuntimeError)
