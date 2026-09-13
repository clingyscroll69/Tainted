"""A session has to outlive the process that created it.

The hole (F-H02): sessions were a dict in one process. That is invisible on a laptop and
fatal on the serverless host this surface deploys to, where the instance that handles the
OAuth callback is generally not the instance the browser comes back to. Sign-in appeared to
work and then every authenticated call answered 401 — which, with a filesystem path already
refused on a hosted deployment, left the demo as the only working thing on the page.

A **cold start** is the thing under test throughout, and `reload(session_token)` is how it is
spelled: re-executing the module throws away every value it was holding, which is exactly
what a fresh instance has. A session that still opens afterwards is one that never depended
on the process at all.
"""

from __future__ import annotations

import base64
import importlib
import time

import pytest
from fastapi.testclient import TestClient

from backend import github, keys, session_token
from backend.app import SESSION_COOKIE, app

SECRET = "a-long-random-deployment-secret"


@pytest.fixture
def hosted(monkeypatch):
    """A public deployment with a stable secret: not the developer's machine."""
    monkeypatch.delenv("TAINTED_LOCAL_MODE", raising=False)
    monkeypatch.setenv(keys.SECRET_ENV, SECRET)


def cold_start():
    """Whatever this process was holding in memory, it no longer is."""
    importlib.reload(session_token)


def signed_in(token: str = "gho_secret-token", login: str = "octocat") -> dict:
    """The headers a browser sends after the callback sealed its cookie.

    Sent as a raw header rather than through the test client's cookie jar, because a jar
    applies domain rules to `testserver` that a real browser never applies to a real host —
    an artefact of the test client, not of anything the backend does.
    """
    return {"Cookie": f"{SESSION_COOKIE}={session_token.seal(token, login)}"}


# --------------------------------------------------------------------------- #
# The hole itself
# --------------------------------------------------------------------------- #
def test_a_session_sealed_by_one_instance_opens_on_another(hosted):
    cookie = session_token.seal("gho_secret-token", "octocat")
    cold_start()
    session = session_token.unseal(cookie)
    assert session is not None, "the session did not survive a cold start — this is F-H02"
    assert session.token == "gho_secret-token"
    assert session.login == "octocat"


def test_a_signed_in_caller_is_still_signed_in_on_an_instance_that_never_saw_them(
    hosted, monkeypatch
):
    """The same thing through the HTTP surface, which is where it was actually broken."""
    headers = signed_in()
    cold_start()
    monkeypatch.setattr(
        github, "list_repos", lambda token, **kw: [{"full_name": "octocat/hello", "private": False}]
    )

    client = TestClient(app)
    assert client.get("/api/auth/status", headers=headers).json()["authenticated"] is True
    r = client.get("/api/repos", headers=headers)
    assert r.status_code == 200, r.text
    assert r.json()["repos"][0]["full_name"] == "octocat/hello"


def test_a_deployment_with_no_shared_secret_loses_its_sessions_on_every_cold_start(monkeypatch):
    """Why the secret is not optional on a host that starts a new instance per request.

    Local mode falls back to a per-process key so a developer keeps the behaviour the dict
    gave them. That fallback is exactly as process-bound as the dict was, which is the point:
    it is a convenience, never a deployment.
    """
    monkeypatch.setenv("TAINTED_LOCAL_MODE", "1")
    monkeypatch.delenv(keys.SECRET_ENV, raising=False)
    cookie = session_token.seal("gho_secret-token", "octocat")
    assert session_token.unseal(cookie) is not None
    cold_start()
    assert session_token.unseal(cookie) is None


# --------------------------------------------------------------------------- #
# What the cookie may and may not carry
# --------------------------------------------------------------------------- #
def test_the_cookie_does_not_carry_the_github_token_in_the_clear(hosted):
    """Sealed, not merely signed. A signed cookie would publish the token to the browser,
    and fetching repositories server-side is only worth anything if it never gets there."""
    cookie = session_token.seal("gho_secret-token", "octocat")
    assert "gho_secret-token" not in cookie
    assert "octocat" not in cookie
    raw = base64.urlsafe_b64decode(cookie.split(".", 1)[1] + "===")
    assert b"gho_secret-token" not in raw and b"octocat" not in raw


def test_two_seals_of_the_same_session_differ(hosted):
    """A fresh nonce each time, so the cookie is not a stable fingerprint of the account."""
    assert session_token.seal("t", "octocat") != session_token.seal("t", "octocat")


@pytest.mark.parametrize(
    "mangle",
    [
        lambda c: c[:-1],                       # truncated
        lambda c: c[:-1] + ("A" if c[-1] != "A" else "B"),  # a flipped character
        lambda c: "ts1." + c.split(".", 1)[1][::-1],        # reordered ciphertext
        lambda c: c.split(".", 1)[1],           # prefix stripped
        lambda c: "tv1." + c.split(".", 1)[1],  # an ownership token's prefix
        lambda c: "ts1.",                       # empty body
        lambda c: "ts1.!!!not-base64!!!",
    ],
)
def test_a_tampered_cookie_does_not_open(hosted, mangle):
    cookie = session_token.seal("gho_secret-token", "octocat")
    assert session_token.unseal(mangle(cookie)) is None


def test_a_session_sealed_under_another_secret_does_not_open(hosted, monkeypatch):
    cookie = session_token.seal("gho_secret-token", "octocat")
    monkeypatch.setenv(keys.SECRET_ENV, "a-different-deployment-secret")
    assert session_token.unseal(cookie) is None


def test_an_expired_session_does_not_open(hosted):
    """The expiry that binds is the sealed one. `Max-Age` is a request to a cookie jar the
    caller owns; it is not a limit on what the caller may send back."""
    cookie = session_token.seal("gho_secret-token", "octocat", ttl_seconds=-1)
    assert session_token.unseal(cookie) is None

    live = session_token.seal("gho_secret-token", "octocat", ttl_seconds=60)
    session = session_token.unseal(live)
    assert session is not None and session.expires > time.time()


def test_an_absent_cookie_is_not_a_session(hosted):
    assert session_token.unseal(None) is None
    assert session_token.unseal("") is None


# --------------------------------------------------------------------------- #
# Failing closed
# --------------------------------------------------------------------------- #
def test_a_hosted_deployment_without_a_secret_cannot_sign_anyone_in(monkeypatch):
    """Not a silent half-working sign-in: the button is hidden and the route says why."""
    monkeypatch.delenv("TAINTED_LOCAL_MODE", raising=False)
    monkeypatch.delenv(keys.SECRET_ENV, raising=False)
    monkeypatch.setenv("GITHUB_CLIENT_ID", "cid")
    monkeypatch.setenv("GITHUB_CLIENT_SECRET", "sec")
    import backend.app as app_module

    monkeypatch.setattr(app_module, "_oauth", github.OAuthConfig())

    assert session_token.available() is False
    with pytest.raises(session_token.SessionSecretMissing):
        session_token.seal("gho_secret-token", "octocat")

    client = TestClient(app)
    body = client.get("/api/auth/status").json()
    assert body["configured"] is False
    assert keys.SECRET_ENV in body["reason"]

    r = client.get("/api/auth/github/login", follow_redirects=False)
    assert r.status_code == 503
    assert keys.SECRET_ENV in r.text


def test_sign_in_is_offered_once_both_halves_are_configured(hosted, monkeypatch):
    monkeypatch.setenv("GITHUB_CLIENT_ID", "cid")
    monkeypatch.setenv("GITHUB_CLIENT_SECRET", "sec")
    import backend.app as app_module

    monkeypatch.setattr(app_module, "_oauth", github.OAuthConfig())
    body = TestClient(app).get("/api/auth/status").json()
    assert body["configured"] is True and body["reason"] is None


def test_logout_takes_the_cookie_away(hosted):
    """All logout can do is tell the browser to drop it — there is no row to strike out."""
    client = TestClient(app)
    headers = signed_in()
    assert client.get("/api/auth/status", headers=headers).json()["authenticated"] is True

    r = client.post("/api/auth/logout", headers=headers)
    assert r.status_code == 200
    cleared = r.headers["set-cookie"]
    assert SESSION_COOKIE in cleared and "Max-Age=0" in cleared

    assert client.get("/api/auth/status").json()["authenticated"] is False


# --------------------------------------------------------------------------- #
# One secret, two unrelated keys
# --------------------------------------------------------------------------- #
def test_the_session_key_is_not_the_ownership_key(hosted):
    """Both features cost the operator one variable; neither is keyed off the other's key."""
    derived = keys.derive(b"tainted/website/session/v1")
    assert derived is not None and len(derived) == 32
    assert derived != keys.master()
    assert derived != keys.derive(b"something/else")


def test_no_secret_means_no_derived_key(monkeypatch):
    monkeypatch.delenv(keys.SECRET_ENV, raising=False)
    assert keys.configured() is False
    assert keys.master() is None
    assert keys.derive(b"tainted/website/session/v1") is None


def test_derivation_is_stable_across_instances(hosted):
    first = keys.derive(b"tainted/website/session/v1")
    cold_start()
    assert keys.derive(b"tainted/website/session/v1") == first
