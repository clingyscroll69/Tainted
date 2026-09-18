"""GitHub auth + repo-picker tests (no network: the OAuth app is unconfigured in test env)."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from backend.app import app
from backend import github, session_token

client = TestClient(app)


# --------------------------------------------------------------------------- #
# HTTP surface
# --------------------------------------------------------------------------- #
def test_auth_status_unconfigured():
    body = client.get("/api/auth/status").json()
    assert body["configured"] is False  # no GITHUB_CLIENT_ID/SECRET in the test env
    assert body["authenticated"] is False
    assert body["login"] is None


def test_login_returns_503_when_unconfigured():
    r = client.get("/api/auth/github/login", follow_redirects=False)
    assert r.status_code == 503


def test_repos_requires_a_session():
    r = client.get("/api/repos")
    assert r.status_code == 401


def test_callback_rejects_state_mismatch():
    r = client.get(
        "/api/auth/github/callback?code=abc&state=nope", follow_redirects=False
    )
    assert r.status_code == 400


def test_analyze_without_repo_or_path_is_400():
    r = client.post("/api/analyze", json={})
    assert r.status_code == 400


# --------------------------------------------------------------------------- #
# Unit: config, sessions, authorize URL
# --------------------------------------------------------------------------- #
def test_config_configured_reflects_credentials():
    assert github.OAuthConfig(client_id=None, client_secret=None).configured is False
    assert github.OAuthConfig(client_id="cid", client_secret="sec").configured is True


def test_authorize_url_includes_params():
    cfg = github.OAuthConfig(client_id="cid", client_secret="sec", scopes="repo read:user")
    url = github.authorize_url(cfg, state="xyz", redirect_uri="http://localhost:8000/cb")
    assert url.startswith(github.AUTHORIZE_URL)
    assert "client_id=cid" in url and "state=xyz" in url
    assert "scope=repo+read%3Auser" in url


# --------------------------------------------------------------------------- #
# How much access a sign-in asks for
#
# `repo` is the only scope GitHub has that can read a private repository, and it carries write
# access to every private repository the account can reach. Tainted only ever reads. So the
# visitor chooses, and the narrow grant is what a deployment asks for unless they say otherwise.
# --------------------------------------------------------------------------- #
CFG = dict(client_id="cid", client_secret="sec")


def test_the_default_sign_in_cannot_reach_a_private_repository():
    cfg = github.OAuthConfig(**CFG)
    assert cfg.scopes_for(include_private=False) == github.PUBLIC_SCOPES
    assert "repo" not in cfg.scopes_for(include_private=False).split()
    url = github.authorize_url(cfg, "s", "http://x/cb")
    assert "scope=read%3Auser" in url


def test_asking_for_private_asks_for_the_one_scope_that_can():
    cfg = github.OAuthConfig(**CFG)
    assert "repo" in cfg.scopes_for(include_private=True).split()
    url = github.authorize_url(cfg, "s", "http://x/cb", include_private=True)
    assert "scope=repo+read%3Auser" in url


def test_an_operator_override_pins_the_scope_for_both_choices():
    """`GITHUB_SCOPES` exists to let a deployment narrow what it may ever ask for."""
    cfg = github.OAuthConfig(**CFG, scopes="read:user")
    assert cfg.scopes_for(include_private=True) == "read:user"


def test_the_config_has_no_scope_of_its_own_by_default(monkeypatch):
    """A default here would win over the visitor's choice and make the choice decorative."""
    monkeypatch.delenv("GITHUB_SCOPES", raising=False)
    assert github.OAuthConfig(**CFG).scopes is None


@pytest.mark.parametrize(
    "granted,expected",
    [
        ("repo,read:user", github.ACCESS_PRIVATE),
        ("read:user", github.ACCESS_PUBLIC),
        ("", github.ACCESS_PUBLIC),
        ("repo:status,read:user", github.ACCESS_PUBLIC),
        ("read:user, repo", github.ACCESS_PRIVATE),
    ],
)
def test_access_is_read_off_what_github_granted(granted, expected):
    """Not off what was asked for: a visitor can decline private on the consent screen, and a
    session that recorded the request would then offer a repository it cannot fetch."""
    assert github.access_for_scopes(granted) == expected
    assert github.Grant(token="t", scopes=granted).access == expected


def test_login_asks_github_for_the_requested_scope(monkeypatch):
    """The query string on the sign-in link is what decides the consent screen."""
    import backend.app as app_module

    monkeypatch.setattr(app_module, "_oauth", github.OAuthConfig(**CFG))
    monkeypatch.setattr(app_module, "_sign_in_unavailable_reason", lambda: None)

    public = client.get("/api/auth/github/login", follow_redirects=False)
    assert "scope=read%3Auser" in public.headers["location"]

    private = client.get("/api/auth/github/login?access=private", follow_redirects=False)
    assert "scope=repo+read%3Auser" in private.headers["location"]

    # A value that is neither falls to the narrow grant rather than erroring: this is a query
    # string on a link, and the safe reading of a typo is less access, not none.
    typo = client.get("/api/auth/github/login?access=privte", follow_redirects=False)
    assert "scope=read%3Auser" in typo.headers["location"]


def test_the_state_cookie_still_pins_the_callback(monkeypatch):
    """The requested access rides on the state, and must not weaken what state is for."""
    import backend.app as app_module

    monkeypatch.setattr(app_module, "_oauth", github.OAuthConfig(**CFG))
    monkeypatch.setattr(app_module, "_sign_in_unavailable_reason", lambda: None)
    r = client.get("/api/auth/github/login?access=private", follow_redirects=False)
    state = r.cookies[app_module.STATE_COOKIE]
    assert state.startswith("private.")
    assert len(state.split(".", 1)[1]) >= 24, "the random half is still a real nonce"


def test_a_public_session_does_not_list_private_repositories(monkeypatch):
    """The picker is the only way to name a repository, so the list *is* the offer."""
    import backend.app as app_module

    seen = {}

    def fake_list(token, *, include_private=True, max_pages=10):
        seen["include_private"] = include_private
        return [{"full_name": "octo/pub", "private": False}]

    monkeypatch.setattr(github, "list_repos", fake_list)
    cookie = session_token.seal("tok", "octocat", access=github.ACCESS_PUBLIC)
    body = client.get(
        "/api/repos", headers={"Cookie": f"{app_module.SESSION_COOKIE}={cookie}"}
    ).json()
    assert seen["include_private"] is False
    assert body["access"] == github.ACCESS_PUBLIC


def test_a_private_session_lists_everything_it_was_granted(monkeypatch):
    import backend.app as app_module

    seen = {}

    def fake_list(token, *, include_private=True, max_pages=10):
        seen["include_private"] = include_private
        return []

    monkeypatch.setattr(github, "list_repos", fake_list)
    cookie = session_token.seal("tok", "octocat", access=github.ACCESS_PRIVATE)
    client.get("/api/repos", headers={"Cookie": f"{app_module.SESSION_COOKIE}={cookie}"})
    assert seen["include_private"] is True


def test_the_status_endpoint_reports_the_sessions_reach(monkeypatch):
    import backend.app as app_module

    cookie = session_token.seal("tok", "octocat", access=github.ACCESS_PUBLIC)
    body = client.get(
        "/api/auth/status", headers={"Cookie": f"{app_module.SESSION_COOKIE}={cookie}"}
    ).json()
    assert body["authenticated"] is True
    assert body["access"] == github.ACCESS_PUBLIC
    # Nobody signed in has no grant to describe.
    assert client.get("/api/auth/status").json()["access"] is None


def test_authorize_url_raises_when_unconfigured():
    cfg = github.OAuthConfig(client_id=None, client_secret=None)
    try:
        github.authorize_url(cfg, "s", "http://x/cb")
        assert False, "expected GitHubNotConfigured"
    except github.GitHubNotConfigured:
        pass


def test_session_roundtrip_and_expiry():
    """Sessions are sealed into the cookie, not stored. `test_session_persistence.py` is where
    that is tested properly — surviving a cold start is the whole reason for it."""
    cookie = session_token.seal("tok", "octocat")
    s = session_token.unseal(cookie)
    assert s is not None and s.token == "tok" and s.login == "octocat"
    assert session_token.unseal(None) is None

    assert session_token.unseal(session_token.seal("tok", "octocat", ttl_seconds=-1)) is None
