"""What the hosted deployment refuses.

Every test here turns `TAINTED_LOCAL_MODE` back off, so it describes the public posture
rather than the developer's own machine: the demo is open to anyone, a real repository needs
a signed-in GitHub caller, a filesystem path is refused outright, and `localhost` proves
nothing. The companion `conftest.py` explains why the rest of the suite runs the other way.

Each of these is a regression test for a specific hole, named in the test's docstring.
"""

from __future__ import annotations

import time

import httpx
import pytest
from fastapi.testclient import TestClient

from backend import ownership_token
from backend.app import app
from tainted.dynamic.target import Target
from tainted.ownership import verify_well_known

client = TestClient(app)
REAL_PATH = "/tmp"


@pytest.fixture
def hosted(monkeypatch):
    """A public deployment: not the developer's machine."""
    monkeypatch.delenv("TAINTED_LOCAL_MODE", raising=False)


# --------------------------------------------------------------------------- #
# A filesystem path is not something a stranger may name
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "endpoint,body",
    [
        ("/api/analyze", {"repo_path": REAL_PATH}),
        ("/api/prove", {"repo_path": REAL_PATH, "url": "https://example.com"}),
        ("/api/fix", {"repo_path": REAL_PATH, "index": 0}),
    ],
)
def test_a_filesystem_path_is_refused_by_a_hosted_deployment(hosted, endpoint, body):
    """An unauthenticated caller could name any directory and read the source lines back."""
    r = client.post(endpoint, json=body)
    assert r.status_code in (401, 403), r.text
    assert "repo_path" not in r.text or "local" in r.text.lower()


def test_a_filesystem_path_still_works_for_a_local_developer():
    """The dev fallback is gated, not deleted — `local_mode` is on for this one."""
    r = client.post("/api/analyze", json={"repo_path": REAL_PATH})
    assert r.status_code == 200


def test_a_github_repo_needs_a_signed_in_caller(hosted):
    r = client.post("/api/analyze", json={"repo": "octocat/hello-world"})
    assert r.status_code == 401


# --------------------------------------------------------------------------- #
# The demo is the one thing open to everybody
# --------------------------------------------------------------------------- #
def test_the_demo_runs_for_anyone_on_a_hosted_deployment(hosted, monkeypatch):
    monkeypatch.setenv("TAINTED_DEMO_INSTANT", "1")
    assert client.post("/api/analyze", json={"repo_path": "demo/demo"}).status_code == 200
    r = client.post("/api/prove", json={"repo_path": "demo/demo", "url": ""})
    assert r.status_code == 200
    assert r.json()["demo"] is True


# --------------------------------------------------------------------------- #
# `localhost` is the server's, not the caller's
# --------------------------------------------------------------------------- #
def test_localhost_does_not_prove_ownership_to_a_hosted_deployment(hosted):
    """The gate used to read `is_local` as verified, so an anonymous POST naming
    http://127.0.0.1 aimed the engine at the server's own internal services."""
    r = client.post("/api/prove", json={"repo_path": REAL_PATH, "url": "http://127.0.0.1:9"})
    assert r.status_code == 403
    assert "ownership" in r.text.lower()


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1:9",
        "http://127.0.0.2:9",  # the rest of 127/8, which the old allowlist missed
        "http://127.1:9",  # inet_aton shorthand
        "http://2130706433:9",  # the same address in decimal
        "http://[::ffff:127.0.0.1]:9",  # IPv4-mapped IPv6
        "http://169.254.169.254/",  # cloud metadata
        "http://10.0.0.5/",  # RFC1918
        "http://printer.local/",
    ],
)
def test_every_internal_address_form_is_refused(hosted, url):
    r = client.post("/api/prove", json={"repo_path": REAL_PATH, "url": url})
    assert r.status_code in (401, 403), f"{url} -> {r.status_code}"


def test_a_non_http_scheme_is_a_422_naming_the_field():
    r = client.post("/api/prove", json={"repo_path": REAL_PATH, "url": "file:///etc/passwd"})
    assert r.status_code == 422
    assert "url" in r.text


# --------------------------------------------------------------------------- #
# Ownership tokens are issued, not chosen
# --------------------------------------------------------------------------- #
def test_the_token_endpoint_needs_a_session(hosted):
    r = client.get("/api/ownership/token", params={"url": "https://app.example.com"})
    assert r.status_code == 401


def test_a_token_is_bound_to_its_caller_and_its_host(monkeypatch):
    """The old gate compared the target's body against a token the *caller* supplied, which
    proves only that the caller can echo themselves."""
    monkeypatch.setenv("TAINTED_TOKEN_SECRET", "a-long-random-value")
    token = ownership_token.issue("octocat", "app.example.com")

    assert ownership_token.check(token, "octocat", "app.example.com")
    assert not ownership_token.check(token, "octocat", "other.example.com")
    assert not ownership_token.check(token, "someone-else", "app.example.com")
    assert not ownership_token.check("tv1.9999999999.forged", "octocat", "app.example.com")
    assert not ownership_token.check(None, "octocat", "app.example.com")


def test_an_expired_token_does_not_verify(monkeypatch):
    monkeypatch.setenv("TAINTED_TOKEN_SECRET", "a-long-random-value")
    token = ownership_token.issue("octocat", "app.example.com", ttl_seconds=-1)
    assert not ownership_token.check(token, "octocat", "app.example.com")
    assert int(token.split(".")[1]) < time.time()


def test_without_a_secret_the_deployment_cannot_issue_or_accept_tokens(monkeypatch):
    """Failing closed: a deployment that cannot bind a token to a caller must not take one."""
    monkeypatch.delenv("TAINTED_TOKEN_SECRET", raising=False)
    assert ownership_token.configured() is False
    assert ownership_token.check("tv1.9999999999.whatever", "octocat", "app.example.com") is False
    with pytest.raises(ownership_token.TokenSecretMissing):
        ownership_token.issue("octocat", "app.example.com")


def test_a_published_body_must_equal_the_token_not_contain_it():
    """`"html"`, `"div"` and `"a"` all verified against any ordinary HTML body."""
    page = "<!doctype html><html><body><div id=root>Loading...</div></body></html>"

    def handler(request):
        return httpx.Response(200, text=page)

    c = httpx.Client(transport=httpx.MockTransport(handler))
    target = Target(url="https://app.example.com")
    for substring in ("html", "div", "a", "root"):
        assert not verify_well_known(target, substring, client=c).verified, substring


# --------------------------------------------------------------------------- #
# The map to the endpoints above
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("path", ["/docs", "/redoc", "/openapi.json"])
def test_interactive_docs_are_local_only(hosted, path):
    assert client.get(path).status_code == 404


@pytest.mark.parametrize("path", ["/docs", "/redoc", "/openapi.json"])
def test_interactive_docs_are_there_for_a_developer(path):
    assert client.get(path).status_code == 200


# --------------------------------------------------------------------------- #
# What is served, and with which headers
# --------------------------------------------------------------------------- #
def test_only_named_static_files_are_served():
    """The mount covered the whole frontend folder, so a superseded prototype was public."""
    assert client.get("/static/index.original.html").status_code == 404
    assert client.get("/static/index.html").status_code == 404
    assert client.get("/static/tutorial.js").status_code == 200
    assert client.get("/static/vendor/cytoscape.min.js").status_code == 200
    assert client.get("/static/fonts/Saira.woff2").status_code == 200


def test_security_headers_are_set():
    h = client.get("/").headers
    assert h["X-Content-Type-Options"] == "nosniff"
    assert h["Referrer-Policy"] == "strict-origin-when-cross-origin"
    assert h["X-Frame-Options"] == "DENY"
    assert "frame-ancestors 'none'" in h["Content-Security-Policy-Report-Only"]


def test_csp_is_enforced_when_asked(monkeypatch):
    monkeypatch.setenv("TAINTED_CSP_ENFORCE", "1")
    assert "Content-Security-Policy" in client.get("/").headers


def test_hsts_only_on_a_hosted_deployment(hosted):
    assert "Strict-Transport-Security" in client.get("/").headers


# --------------------------------------------------------------------------- #
# What one process will spend on prove
# --------------------------------------------------------------------------- #
def test_prove_slots_are_bounded_and_refuse_with_429():
    from fastapi import HTTPException

    from backend import app as app_module

    taken = []
    try:
        for _ in range(app_module._MAX_CONCURRENT_PROVES):
            app_module._take_prove_slot()
            taken.append(1)
        with pytest.raises(HTTPException) as exc:
            app_module._take_prove_slot()
        assert exc.value.status_code == 429
    finally:
        for _ in taken:
            app_module._prove_slots.release()
