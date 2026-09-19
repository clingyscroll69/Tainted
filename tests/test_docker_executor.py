import json

import pytest

import tainted
from tainted.dynamic.target import Account, ProveSetup, Target
from tainted.execution.base import SandboxUnavailable
from tainted.execution.docker import DockerExecutor
from tainted.selfdefense import PlanViolation


class FakeRunner:
    """Records the argv it was handed and replays canned NDJSON. No daemon involved."""

    def __init__(self, lines=(), exc=None):
        self.lines, self.exc, self.argv, self.stdin, self.env = list(lines), exc, None, None, None

    def run(self, argv, stdin, env):
        self.argv, self.stdin, self.env = argv, stdin, env
        if self.exc:
            raise self.exc
        return iter(self.lines)


def _setup():
    return ProveSetup(
        target=Target(url="http://localhost:3000"),
        account_a=Account(label="A", email="a@example.com", password="pw"),
        account_b=Account(label="B", email="b@example.com", password="pw"),
    )


def _report_line():
    """A minimal valid Report. `repo_path` and `summary` are required fields; the rest default."""
    return json.dumps({
        "kind": "report",
        "report": {"repo_path": "/repo", "summary": {}, "findings": []},
        "blocked_calls": [],
    })


def test_it_pins_the_image_to_the_engine_version_never_latest():
    """Spec test 10. A host on 0.2.0 driving a 0.1.1 sandbox reports findings from a different
    analyser than the one that ranked them."""
    r = FakeRunner([_report_line()])
    DockerExecutor(runner=r).prove("/repo", _setup(), ownership_verified=True)
    image = r.argv[-1]
    assert image.endswith(f":{tainted.__version__}")
    assert ":latest" not in " ".join(r.argv)


def test_cli_and_mcp_get_host_networking_and_the_website_gets_bridge():
    """Spec test 2."""
    r = FakeRunner([_report_line()])
    DockerExecutor(network="host", runner=r).prove("/repo", _setup(), ownership_verified=True)
    assert "--network=host" in r.argv

    r2 = FakeRunner([_report_line()])
    DockerExecutor(network="bridge", runner=r2).prove("/repo", _setup(), ownership_verified=True)
    assert "--network=bridge" in r2.argv


def test_the_repo_is_mounted_read_only():
    """Spec test 8."""
    r = FakeRunner([_report_line()])
    DockerExecutor(runner=r).prove("/repo", _setup(), ownership_verified=True)
    assert "/repo:/repo:ro" in r.argv
    assert "--read-only" in r.argv
    assert "--cap-drop" in r.argv


def test_the_target_url_crosses_unmodified():
    """Spec test 3 — the regression guard for the `.internal` trap. Rewriting localhost to
    host.docker.internal would make Target.is_local false and Target.is_internal true, so the
    run would only survive by asserting ownership it had not derived."""
    import json

    r = FakeRunner([_report_line()])
    DockerExecutor(network="host", runner=r).prove("/repo", _setup(), ownership_verified=True)
    assert json.loads(r.stdin)["setup"]["target"]["url"] == "http://localhost:3000"


def test_a_missing_daemon_refuses_and_names_docker_rather_than_running_locally():
    """Spec test 1, and the most important one in the file. The replaced design's equivalent
    was test_unreachable_sandbox_raises_rather_than_running_locally."""
    r = FakeRunner(exc=FileNotFoundError("docker"))
    with pytest.raises(SandboxUnavailable, match="Docker"):
        DockerExecutor(runner=r).prove("/repo", _setup(), ownership_verified=True)


def test_a_refused_event_raises_plan_violation_not_a_generic_error():
    """Spec test 5, host side."""
    r = FakeRunner(['{"kind":"refused","message":"not in the committed plan","blocked_calls":[]}'])
    with pytest.raises(PlanViolation, match="committed plan"):
        DockerExecutor(runner=r).prove("/repo", _setup(), ownership_verified=True)


def test_observers_fire_in_order_and_streams_is_true():
    """Spec test 7."""
    assert DockerExecutor(runner=FakeRunner()).streams is True
    seen = []
    r = FakeRunner([
        '{"kind":"candidates","candidates":[]}',
        json.dumps({"kind": "finding", "finding": {
            "candidate": {
                "check": "bola", "title": "t", "location": {"file": "f.py"},
            },
        }}),
        _report_line(),
    ])
    DockerExecutor(runner=r).prove(
        "/repo", _setup(), ownership_verified=True,
        on_candidates=lambda c: seen.append("candidates"),
        on_finding=lambda f: seen.append("finding"),
    )
    assert seen == ["candidates", "finding"]


def test_a_malformed_line_fails_loudly():
    """Spec test 9, end to end."""
    r = FakeRunner(["Traceback (most recent call last):"])
    with pytest.raises(SandboxUnavailable, match="not a JSON object"):
        DockerExecutor(runner=r).prove("/repo", _setup(), ownership_verified=True)


def test_a_run_that_ends_with_no_terminal_event_is_an_error():
    """A container killed mid-run must not read as a clean run with no findings."""
    r = FakeRunner(['{"kind":"finding","finding":{"id":"f1"}}'])
    with pytest.raises(SandboxUnavailable, match="ended without"):
        DockerExecutor(runner=r).prove("/repo", _setup(), ownership_verified=True)
