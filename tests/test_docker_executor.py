import json
import subprocess
import sys

import pytest

import tainted
from tainted.dynamic.target import Account, ProveSetup, Target
from tainted.execution.base import SandboxUnavailable
from tainted.execution.container_main import RUN_KEY_ENV
from tainted.execution.docker import DockerExecutor, SubprocessRunner
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


def test_no_plan_means_no_stray_run_key_forwarded_into_the_container():
    """Finding 1. Bare `-e NAME` forwards NAME from the host's own environment, so an
    unguarded run must not append it at all — otherwise a stale host-side TAINTED_RUN_KEY
    would cross in as a real key while `plan` is None, recreating the partial-guard state
    correction 2 exists to prevent, this time through the environment rather than code."""
    r = FakeRunner([_report_line()])
    DockerExecutor(runner=r).prove("/repo", _setup(), ownership_verified=True)
    assert RUN_KEY_ENV not in r.argv


def test_a_plan_means_the_run_key_flag_is_present():
    """The counterpart to the above: a guarded run does append the flag."""
    from tainted.selfdefense import ProbePlan

    r = FakeRunner([_report_line()])
    plan = ProbePlan(target_url="http://localhost:3000", allowed=[])
    DockerExecutor(runner=r).prove(
        "/repo", _setup(), ownership_verified=True, plan=plan, plan_signature="sig",
    )
    assert RUN_KEY_ENV in r.argv


# --- Real-subprocess tests for SubprocessRunner. No Docker daemon involved: argv points at
# the Python interpreter instead of at `docker`, but the process is a genuine child process,
# so these exercise the real pipe/return-code handling that FakeRunner-based tests cannot. ---

def test_subprocess_runner_raises_on_nonzero_exit_with_stderr_reachable():
    """Finding 2. Popen never raises CalledProcessError on its own; SubprocessRunner must
    check the return code itself so the caller's actionable message (missing image, daemon
    down, etc.) is reachable instead of being swallowed as a generic empty-report error."""
    argv = [sys.executable, "-c", "import sys; sys.stderr.write('boom'); sys.exit(3)"]
    with pytest.raises(subprocess.CalledProcessError) as exc_info:
        list(SubprocessRunner().run(argv, "", {}))
    assert exc_info.value.returncode == 3
    assert "boom" in exc_info.value.stderr


def test_subprocess_runner_survives_a_child_that_never_reads_stdin():
    """Finding 3. A child that exits immediately without reading stdin must not let a
    BrokenPipeError escape from the write; the non-zero exit should surface instead."""
    argv = [sys.executable, "-c", "import sys; sys.exit(1)"]
    with pytest.raises(subprocess.CalledProcessError) as exc_info:
        list(SubprocessRunner().run(argv, "some stdin that is never read", {}))
    assert exc_info.value.returncode == 1


def test_subprocess_runner_yields_lines_and_raises_nothing_on_clean_exit():
    """A well-behaved child that echoes NDJSON and exits 0 must simply yield those lines."""
    line = _report_line()
    argv = [sys.executable, "-c", f"print({line!r})"]
    lines = list(SubprocessRunner().run(argv, "", {}))
    assert any(json.loads(l.strip())["kind"] == "report" for l in lines if l.strip())
