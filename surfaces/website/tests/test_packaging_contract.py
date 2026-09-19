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

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from backend.app import app

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


@pytest.mark.parametrize("field", ["repo", "repo_path"])
def test_a_real_prove_is_refused_rather_than_run_on_our_own_metal(monkeypatch, field):
    """`default_executor()` always returns `DockerExecutor`, so there is no longer a
    "misconfigured, refuse before touching anything" gate to hit a single status code on: the
    `repo` field is refused for lacking a GitHub session (401) before execution is even
    reached, and the `repo_path` field reaches `DockerExecutor`, which — with no sandbox image
    built in this test environment — fails to spawn its container and answers 502. Both are
    refusals: neither path lets `prove` run the exploit against this process's own filesystem
    and network, which is the one thing this test exists to rule out."""
    monkeypatch.setenv("TAINTED_REQUIRE_SANDBOX", "1")
    monkeypatch.setenv("TAINTED_LOCAL_MODE", "1")
    client = TestClient(app)
    resp = client.post(
        "/api/prove",
        json={field: "owner/name" if field == "repo" else "/tmp", "url": "http://localhost:9"},
    )
    assert resp.status_code in (401, 502, 503), resp.text


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
