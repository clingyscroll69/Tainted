"""The fail-closed defaults belong to the program, not to the image.

`require_sandbox()` reads `TAINTED_REQUIRE_SANDBOX` and an unset variable means **false** —
deliberately, because absence cannot be told apart from a developer's laptop. The only thing
that ever flipped it in production was one `ENV` line in `surfaces/website/Dockerfile`, so the
guarantee was a property of the image rather than of the server.

That matters because the image is going away: a containerised website cannot spawn sandbox
containers without being handed the host's Docker socket, which is root-equivalent and would go
to the exact process running strangers' generated exploits. When the Dockerfile is deleted, the
line goes with it, nothing errors, and `require_sandbox()` quietly reads false again — silently
turning off the Docker-availability pre-check `sandbox.py` exists to keep loud, in a deployment
that looks identical to a working one. (This does not put `prove` back in-process:
`default_executor()` always returns `DockerExecutor`, and no configuration changes that.)

So the default lives in `run.py`, the entrypoint `tainted-web` actually calls, and these tests
assert it there. They deliberately do not read the Dockerfile: a test that reads the file being
removed is deleted by the same commit that causes the regression.
"""

from __future__ import annotations

import os

import pytest
import uvicorn
from fastapi.testclient import TestClient

from backend import run
from backend.app import app
from backend.sandbox import require_sandbox


VARS = ("TAINTED_REQUIRE_SANDBOX", "TAINTED_CSP_ENFORCE")


@pytest.fixture(autouse=True)
def forget_the_variables():
    """Restore these by hand, because monkeypatch cannot undo them.

    `monkeypatch.delenv(raising=False)` on a variable that was never set records nothing to
    restore — so the `setdefault` the code under test performs would outlive the test and leak
    into every suite that runs after this file, where `prove` then answers 503 far from
    anything that explains why.
    """
    before = {name: os.environ.get(name) for name in VARS}
    for name in VARS:
        os.environ.pop(name, None)
    yield
    for name, value in before.items():
        os.environ.pop(name, None)
        if value is not None:
            os.environ[name] = value


def test_the_entrypoint_fails_closed_when_nothing_sets_the_variable():
    run.apply_deployment_defaults()
    assert require_sandbox() is True, (
        "`tainted-web` started with require_sandbox() false: the Docker-availability "
        "pre-check would be silently off"
    )


def test_an_explicit_opt_out_is_still_honoured(monkeypatch):
    """`TAINTED_REQUIRE_SANDBOX=0` is the documented way to turn off the Docker-availability
    pre-check in `api_prove` — it does not, and cannot, put `prove` back in-process, since
    `default_executor()` always returns `DockerExecutor` regardless of this variable.

    A default that cannot be overridden is not a default. Forcing `=1` would silently break
    every deployment that set `=0` to accept running without that pre-check.
    """
    monkeypatch.setenv("TAINTED_REQUIRE_SANDBOX", "0")
    run.apply_deployment_defaults()
    assert require_sandbox() is False


def test_the_default_is_in_place_before_the_app_is_imported(monkeypatch):
    """`app.py` binds `_executor` and announces its gaps at import time.

    `uvicorn.run("backend.app:app")` imports the module by string, from inside the call — so a
    default applied after that call, or beside it, is a no-op that still reads correctly.
    """
    seen: dict[str, str | None] = {}

    def fake_run(*args, **kwargs):
        seen["required"] = os.environ.get("TAINTED_REQUIRE_SANDBOX")

    monkeypatch.setattr(uvicorn, "run", fake_run)
    run.main()
    assert seen["required"] == "1", "the app was imported before the default was established"


# --------------------------------------------------------------------------- #
# The same trap, one line below it in the image
# --------------------------------------------------------------------------- #
def test_the_entrypoint_enforces_the_csp_when_nothing_says_otherwise():
    """Report-only blocks nothing, and the difference is invisible from the outside.

    `TAINTED_CSP_ENFORCE` lived beside `TAINTED_REQUIRE_SANDBOX` in the image's one `ENV`
    block, so it is removed by the same commit and fails the same silent way: the header keeps
    being sent, the page keeps working, and nothing is enforced.
    """
    run.apply_deployment_defaults()
    headers = TestClient(app).get("/").headers
    assert "Content-Security-Policy" in headers
    assert "Content-Security-Policy-Report-Only" not in headers


def test_watching_before_blocking_is_still_available(monkeypatch):
    """The report-only mode the policy was written to allow is an opt-out, not the default.

    A deployment that wants to watch the policy before it blocks says so, the same way one
    that wants the Docker-availability pre-check off says so.
    """
    monkeypatch.setenv("TAINTED_CSP_ENFORCE", "0")
    run.apply_deployment_defaults()
    headers = TestClient(app).get("/").headers
    assert "Content-Security-Policy-Report-Only" in headers
    assert "Content-Security-Policy" not in headers
