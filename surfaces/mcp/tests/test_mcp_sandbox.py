import time

import pytest

from tainted_mcp.server import tainted_prove_start, tainted_prove_status


def _start(url="http://localhost:3000"):
    return tainted_prove_start(
        repo_path="/repo", url=url,
        login_a="a@example.com:pw", login_b="b@example.com:pw",
    )


def _settle(job_id, timeout=5.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        st = tainted_prove_status(job_id)
        if st["status"] != "running":
            return st
        time.sleep(0.02)
    raise AssertionError("job never settled")


def test_there_is_no_ownership_token_parameter_left(monkeypatch):
    """Spec test 4, MCP side."""
    import inspect

    assert "ownership_token" not in inspect.signature(tainted_prove_start).parameters


def test_a_non_local_target_is_refused(monkeypatch):
    out = _start(url="https://app.example.com")
    assert out["job_id"] is None
    assert "local" in out["error"].lower()


def test_blocked_calls_survive_the_boundary_and_reach_status(monkeypatch):
    """Spec test 6. The guard runs inside the container now, so there is no shared guard object
    to read afterwards — blocked_calls has to come back in the result payload."""
    from tainted.execution.base import ProveOutcome
    from tainted.report.model import Report, ReportSummary

    def _fake(self, *a, **k):
        return ProveOutcome(
            report=Report(repo_path="/repo", summary=ReportSummary()),
            blocked_calls=[{"tool": "POST", "args": {"url": "https://evil.com"}}],
        )

    monkeypatch.setattr("tainted.execution.docker.DockerExecutor.prove", _fake)
    job = _start()
    st = _settle(job["job_id"])
    assert st["status"] == "done"
    assert st["blocked_calls"] == [{"tool": "POST", "args": {"url": "https://evil.com"}}]


def test_a_plan_violation_in_the_container_is_refused_not_error(monkeypatch):
    """Spec test 5, all the way to the tool result."""
    from tainted.selfdefense import PlanViolation

    def _boom(self, *a, **k):
        raise PlanViolation("Call `POST` was not in the committed probe plan")

    monkeypatch.setattr("tainted.execution.docker.DockerExecutor.prove", _boom)
    job = _start()
    st = _settle(job["job_id"])
    assert st["status"] == "refused"
    assert "committed probe plan" in st["error"]
