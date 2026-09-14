"""What the image promises, checked against the image.

The Dockerfile is this surface's real production entrypoint, and three of its lines carry
safety or capability claims that nothing else in the suite could hold up:

* `sandbox.py` has always said "the website's production entrypoint sets it" about
  `TAINTED_REQUIRE_SANDBOX`. Nothing set it, so a deployment whose sandbox was misconfigured
  ran generated exploits in-process and looked identical to one that was working.
* The README's Deploy section offers `prove`, and the image installed the Playwright *client*
  without the browser it drives — a failure that arrives on the first discovery walk rather
  than at build time.
* `prove` executes untrusted, network-active code. Doing that as uid 0 makes a process escape
  and a container escape the same event.

These read the Dockerfile rather than build it: a text assertion catches a deleted line, which
is the way all three would come back.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from backend.app import app

DOCKERFILE = (Path(__file__).resolve().parents[1] / "Dockerfile").read_text(encoding="utf-8")
ROOT = Path(__file__).resolve().parents[3]


def test_the_image_fails_closed_on_sandboxing():
    assert "TAINTED_REQUIRE_SANDBOX=1" in DOCKERFILE, (
        "sandbox.py documents this entrypoint as the one that sets it"
    )


def test_the_image_installs_the_browser_and_not_just_its_client():
    assert "playwright install" in DOCKERFILE
    assert "chromium" in DOCKERFILE


def test_the_browsers_live_somewhere_an_unprivileged_process_can_read():
    assert "PLAYWRIGHT_BROWSERS_PATH" in DOCKERFILE


def test_the_server_does_not_run_as_root():
    assert "USER tainted" in DOCKERFILE
    assert DOCKERFILE.index("USER tainted") > DOCKERFILE.index("useradd")


def test_the_build_context_is_not_the_whole_working_tree():
    """Both Dockerfiles build from the repo root; `.venv` alone is hundreds of megabytes."""
    ignore = (ROOT / ".dockerignore")
    assert ignore.is_file(), "a root-context build with no .dockerignore ships the whole tree"
    body = ignore.read_text(encoding="utf-8")
    for path in (".venv/", ".git/", "__pycache__/", ".env"):
        assert path in body


# --------------------------------------------------------------------------- #
# The one thing a fail-closed image must still be able to do
# --------------------------------------------------------------------------- #
def test_the_demo_still_runs_when_sandboxing_is_required(monkeypatch):
    """The container default is `require_sandbox`, so a plain `docker run` must still demo.

    The demo contacts nothing and executes nothing, so it is exempt because it is inert, not
    because it is privileged. If that exemption ever moves below the sandbox check, the
    out-of-the-box container becomes a page where every button answers 503.
    """
    monkeypatch.setenv("TAINTED_REQUIRE_SANDBOX", "1")
    monkeypatch.delenv("TAINTED_SANDBOX_URL", raising=False)
    monkeypatch.delenv("TAINTED_SANDBOX_TOKEN", raising=False)
    client = TestClient(app)
    resp = client.post("/api/prove", json={"repo": "demo/demo", "url": ""})
    assert resp.status_code == 200, resp.text
    assert resp.json()["findings"]


@pytest.mark.parametrize("field", ["repo", "repo_path"])
def test_a_real_prove_is_refused_rather_than_run_on_our_own_metal(monkeypatch, field):
    monkeypatch.setenv("TAINTED_REQUIRE_SANDBOX", "1")
    monkeypatch.setenv("TAINTED_LOCAL_MODE", "1")
    monkeypatch.delenv("TAINTED_SANDBOX_URL", raising=False)
    monkeypatch.delenv("TAINTED_SANDBOX_TOKEN", raising=False)
    client = TestClient(app)
    resp = client.post(
        "/api/prove",
        json={field: "owner/name" if field == "repo" else "/tmp", "url": "http://localhost:9"},
    )
    assert resp.status_code == 503, resp.text
    assert "sandbox" in resp.json()["detail"].lower()


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
