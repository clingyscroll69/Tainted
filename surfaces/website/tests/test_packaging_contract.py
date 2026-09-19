"""What the packaged website promises, checked against what ships.

This surface is no longer a container: it ships as a wheel and runs as a process on a host
that has Docker, spawning sandbox containers as siblings rather than children (see
`backend/sandbox.py`). What is left to check here is the packaging itself — that the wheel
actually contains the page it serves — plus the two app-level behaviours that used to be
guarded by reading the (now-deleted) Dockerfile: the demo still works when sandboxing is
required, and a real `prove` is refused rather than run on our own metal.

The sandbox-image contract (browser installed, non-root user, minimal build context, fail-closed
default) moved to `tests/test_sandbox_image_contract.py` in Task 6 — it now guards the *sandbox*
image `DockerExecutor` spawns, not this surface.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

from fastapi.testclient import TestClient

from backend import app as app_module
from backend.app import app
from tainted.execution.docker import DockerExecutor

# --------------------------------------------------------------------------- #
# The one thing a fail-closed deployment must still be able to do
# --------------------------------------------------------------------------- #
def test_the_demo_still_runs_when_sandboxing_is_required(monkeypatch):
    """`run.apply_deployment_defaults()` sets `require_sandbox`, so a plain deployment with no
    Docker daemon reachable must still demo.

    The demo contacts nothing and executes nothing, so it is exempt because it is inert, not
    because it is privileged. If that exemption ever moves below the sandbox check, the
    out-of-the-box deployment becomes a page where every button answers 503.
    """
    monkeypatch.setenv("TAINTED_REQUIRE_SANDBOX", "1")
    client = TestClient(app)
    resp = client.post("/api/prove", json={"repo": "demo/demo", "url": ""})
    assert resp.status_code == 200, resp.text
    assert resp.json()["findings"]


class _FailingRunner:
    """Stands in for a Docker daemon this test must never actually shell out to.

    `default_executor()` now unconditionally returns a live `DockerExecutor`, and `app.py`
    binds `_executor` at import time — so a naive `/api/prove` POST with a real target would
    reach `subprocess.Popen(["docker", "run", ...])` on whatever machine runs the suite. On a
    box with the daemon down that raises and this test would pass for an incidental reason; on
    a box with the sandbox image built, it would actually spawn a container that fires at
    `http://localhost:9`. Injecting this runner keeps the test hermetic and pins the *reason*
    it fails: `DockerExecutor` catching `CalledProcessError` and turning it into
    `SandboxUnavailable`, never a completed local run.
    """

    def run(self, argv, stdin, env):
        raise subprocess.CalledProcessError(1, argv, output=None, stderr=b"no such daemon")
        yield  # pragma: no cover - unreachable; satisfies the Runner protocol's Iterator return


def test_a_real_prove_is_refused_rather_than_run_on_our_own_metal(monkeypatch):
    """The `repo_path` field, in local mode, reaches `DockerExecutor` — the one path in this
    surface where `prove` would otherwise run untrusted code. Stubbing the runner means this
    test is exercising *our* refusal (`DockerExecutor` -> `SandboxUnavailable` -> 502), not the
    host's Docker state, and it can actually fail if that refusal is ever lost: if `_argv` or
    `_consume` changed shape so the exploit ran before the runner's failure surfaced, the
    injected runner would either not be reached or the response would stop being a 502.

    The `repo` field is not tested here: it is refused by the GitHub-session check (401) before
    execution is ever reached, which proves the auth gate works and nothing about sandboxing —
    see `test_api_gating.py` for that gate's own tests.
    """
    monkeypatch.setenv("TAINTED_REQUIRE_SANDBOX", "1")
    monkeypatch.setenv("TAINTED_LOCAL_MODE", "1")
    monkeypatch.setattr(
        app_module, "_executor", DockerExecutor(network="bridge", runner=_FailingRunner())
    )
    client = TestClient(app)
    resp = client.post(
        "/api/prove",
        json={"repo_path": "/tmp", "url": "http://localhost:9"},
    )
    assert resp.status_code == 502, resp.text
    assert "sandbox container failed to start" in resp.json()["detail"].lower()


# --------------------------------------------------------------------------- #
# What the wheel contains
# --------------------------------------------------------------------------- #
def test_the_page_the_server_serves_is_declared_as_package_data():
    """A wheel ships no data files by default, and `frontend/` is not inside `backend/`.

    Built from `include = ["backend*"]` alone, the wheel held the server and nothing it serves:
    `/` answered 404, the tour was gone and so was the graph library. Every documented install
    is a source install or the container, where the directory is simply on disk — so nothing
    noticed until something built a wheel.
    """
    import tomllib

    manifest = tomllib.loads(
        (Path(__file__).resolve().parents[1] / "pyproject.toml").read_text(encoding="utf-8")
    )
    tools = manifest["tool"]["setuptools"]
    assert "frontend*" in tools["packages"]["find"]["include"]
    assert tools["packages"]["find"].get("namespaces") is True, (
        "frontend/ has no __init__.py, so it is only collected as a namespace package"
    )
    patterns = tools["package-data"]["frontend"]
    assert "*.html" in patterns and "fonts/*" in patterns and "vendor/*" in patterns


def test_everything_the_page_loads_is_on_disk_where_the_app_looks():
    from backend.app import FRONTEND

    assert (FRONTEND / "index.html").is_file()
    assert (FRONTEND / "tutorial.js").is_file()
    assert list((FRONTEND / "fonts").glob("*.woff2"))
    assert (FRONTEND / "vendor" / "cytoscape.min.js").is_file()
