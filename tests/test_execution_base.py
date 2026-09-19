import pytest

from tainted.dynamic.target import Account, ProveSetup, Target
from tainted.execution import base as execution_base
from tainted.execution.base import LocalExecutor, ProveOutcome, SandboxUnavailable
from tainted.models import AnalysisResult
from tainted.report import build_report


def _setup() -> ProveSetup:
    return ProveSetup(
        target=Target(url="http://localhost:3000"),
        account_a=Account(label="A", email="a@example.com", password="pw"),
        account_b=Account(label="B", email="b@example.com", password="pw"),
    )


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


def test_partial_guard_arguments_refuse_rather_than_run_unguarded(monkeypatch, tmp_path):
    """A caller that asked for plan-commitment must get it or an error — never a silent
    downgrade to an unguarded run."""
    empty_result = AnalysisResult(repo_path=str(tmp_path))
    monkeypatch.setattr(execution_base, "core_analyze", lambda *a, **k: empty_result)

    with pytest.raises(ValueError, match="refusing"):
        LocalExecutor().prove(
            str(tmp_path),
            _setup(),
            ownership_verified=True,
            plan=object(),
            plan_signature="sig",
            run_key=None,
        )


def test_no_guard_arguments_runs_unguarded_without_raising(monkeypatch, tmp_path):
    """Supplying none of plan/plan_signature/run_key is the legitimate unguarded path the
    website uses today — the partial-supply refusal must not swallow it."""
    empty_result = AnalysisResult(repo_path=str(tmp_path))
    monkeypatch.setattr(execution_base, "core_analyze", lambda *a, **k: empty_result)
    monkeypatch.setattr(execution_base, "core_prove", lambda *a, **k: [])

    outcome = LocalExecutor().prove(str(tmp_path), _setup(), ownership_verified=True)

    assert outcome.report == build_report(empty_result, [])
    assert outcome.blocked_calls == []
