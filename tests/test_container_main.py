import io
import json

from tainted.execution.container_main import main


def _lines(out):
    return [json.loads(line) for line in out.getvalue().splitlines() if line.strip()]


def test_a_plan_violation_is_reported_as_refused_not_error(monkeypatch):
    """Spec test 5. A refusal is the guard working; it must never read as a crash."""
    from tainted.selfdefense import PlanViolation

    def _boom(*a, **k):
        raise PlanViolation("Call `POST` to evil.com was not in the committed plan")

    monkeypatch.setattr("tainted.execution.container_main._run", _boom)
    out = io.StringIO()
    req = {
        "repo_path": "/repo",
        "setup": {"target": {"url": "http://localhost:3000"}},
        "ownership_verified": True,
    }
    code = main(io.StringIO(json.dumps(req)), out, {})
    events = _lines(out)
    assert events[-1]["kind"] == "refused"
    assert "committed plan" in events[-1]["message"]
    assert code == 0  # a refusal is a completed run, not a failed process


def test_an_unexpected_exception_is_reported_as_error(monkeypatch):
    monkeypatch.setattr(
        "tainted.execution.container_main._run",
        lambda *a, **k: (_ for _ in ()).throw(ValueError("kaboom")),
    )
    out = io.StringIO()
    req = {"repo_path": "/repo", "setup": {}, "ownership_verified": True}
    code = main(io.StringIO(json.dumps(req)), out, {})
    assert _lines(out)[-1]["kind"] == "error"
    assert "kaboom" in _lines(out)[-1]["message"]
    assert code == 1
