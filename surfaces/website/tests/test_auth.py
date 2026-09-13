"""GitHub auth + repo-picker tests (no network: the OAuth app is unconfigured in test env)."""

from __future__ import annotations

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
