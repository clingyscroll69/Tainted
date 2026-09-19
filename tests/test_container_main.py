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


def test_llm_expected_but_missing_refuses_instead_of_running_thinner(monkeypatch):
    """Finding B2, part 2. The host had a usable LLM and the container resolves none — the
    key did not cross. Running anyway would silently re-rank every finding on Structure alone
    and hand back a report that looks complete but is missing the register the host already
    showed the user via `analyze`. This must be a loud terminal error, not a thinner report."""
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.setattr("tainted.execution.base.get_default_client", lambda reload=False: type(
        "_NoLLM", (), {"available": False}
    )())
    out = io.StringIO()
    req = {
        "repo_path": "/repo",
        "setup": {"target": {"url": "http://localhost:3000"}},
        "ownership_verified": True,
        "llm_expected": True,
    }
    code = main(io.StringIO(json.dumps(req)), out, {})
    events = _lines(out)
    assert events[-1]["kind"] == "error"
    assert "did not reach this container" in events[-1]["message"]
    assert code == 1


def test_a_malformed_run_key_is_reported_as_error():
    """A corrupted TAINTED_RUN_KEY must emit an error event, not die silently."""
    out = io.StringIO()
    req = {"repo_path": "/repo", "setup": {}, "ownership_verified": True}
    code = main(io.StringIO(json.dumps(req)), out, {"TAINTED_RUN_KEY": "not-hex"})
    events = _lines(out)
    assert events[-1]["kind"] == "error"
    assert "hex" in events[-1]["message"].lower()
    assert code == 1
