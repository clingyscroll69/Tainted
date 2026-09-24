"""CI surface smoke tests (run with core + this surface on the path)."""

from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

from tainted import analyze as core_analyze
from tainted.report import build_report
from tainted_ci.oidc import decode_claims
from tainted_ci.render import render_markdown

REPO = str(Path(__file__).resolve().parents[3] / "tests" / "fixtures" / "vulnerable_supabase")


def _fake_jwt(claims: dict) -> str:
    def seg(obj):
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()

    return f"{seg({'alg': 'RS256'})}.{seg(claims)}.sig"


def test_decode_claims_reads_repository():
    token = _fake_jwt({"repository": "me/app", "workflow": "ci"})
    assert decode_claims(token)["repository"] == "me/app"


def test_render_markdown_lists_candidates():
    report = build_report(core_analyze(REPO))
    md = render_markdown(report, "prove skipped: test")
    assert "🩸 Tainted" in md
    assert "Candidates" in md
    assert "rls" in md


# --------------------------------------------------------------------------- #
# The OIDC gate
#
# The claims are a base64 string the caller wrote, and `GITHUB_REPOSITORY` is read from the
# same environment as the token. Only the signature makes either mean anything, so a run that
# cannot check it is refused rather than allowed with a note in the detail string.
# --------------------------------------------------------------------------- #
GITHUB_ISS = "https://token.actions.githubusercontent.com"


@pytest.fixture
def keys(monkeypatch):
    """A local RSA key standing in for the issuer's JWKS, and the URL each lookup asked for."""
    from cryptography.hazmat.primitives.asymmetric import rsa

    import tainted_ci.oidc as oidc

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    asked: list[str] = []

    class FakeJWKClient:
        def __init__(self, url):
            asked.append(url)

        def get_signing_key_from_jwt(self, token):
            return type("K", (), {"key": key.public_key()})()

    monkeypatch.setattr("jwt.PyJWKClient", FakeJWKClient)
    return key, asked


def _signed(key, **claims) -> str:
    import time

    import jwt

    now = int(time.time())
    body = {"iss": GITHUB_ISS, "aud": "tainted", "repository": "me/app", "iat": now,
            "exp": now + 300}
    body.update(claims)
    return jwt.encode(body, key, algorithm="RS256")


def test_a_live_github_token_for_this_repo_is_verified_without_any_url_claim(keys, monkeypatch):
    """No real token carries a preview URL; demanding one refused every remote CI prove."""
    import tainted_ci.oidc as oidc

    key, asked = keys
    monkeypatch.setenv("GITHUB_REPOSITORY", "me/app")
    result = oidc.verify_ci_ownership(_signed(key))
    assert result.verified, result.detail
    assert asked == ["https://token.actions.githubusercontent.com/.well-known/jwks"]
    assert "not to the preview URL" in result.detail


def test_a_gitlab_token_is_checked_against_gitlabs_keys_and_project_path(keys, monkeypatch):
    import tainted_ci.oidc as oidc

    key, asked = keys
    monkeypatch.delenv("GITHUB_REPOSITORY", raising=False)
    monkeypatch.setenv("CI_PROJECT_PATH", "group/app")
    token = _signed(key, iss="https://gitlab.com", repository=None, project_path="group/app")
    result = oidc.verify_ci_ownership(token)
    assert result.verified, result.detail
    assert asked == ["https://gitlab.com/oauth/discovery/keys"]


@pytest.mark.parametrize(
    "claims, why",
    [
        ({"aud": "sts.amazonaws.com"}, "minted for another audience"),
        ({"exp": 1}, "expired"),
        ({"repository": "someone/else"}, "names another repository"),
    ],
)
def test_a_token_that_is_not_a_live_tainted_token_for_this_repo_is_refused(
    keys, monkeypatch, claims, why
):
    import tainted_ci.oidc as oidc

    key, _ = keys
    monkeypatch.setenv("GITHUB_REPOSITORY", "me/app")
    assert not oidc.verify_ci_ownership(_signed(key, **claims)).verified, why


def test_an_untrusted_issuer_is_refused_before_any_key_is_fetched(keys, monkeypatch):
    """A token names its own issuer; trusting whatever it names trusts its minter's keys."""
    import tainted_ci.oidc as oidc

    key, asked = keys
    monkeypatch.setenv("GITHUB_REPOSITORY", "me/app")
    result = oidc.verify_ci_ownership(_signed(key, iss="https://attacker.example"))
    assert not result.verified
    assert asked == []
    assert "not trusted" in result.detail


def test_a_token_signed_by_another_key_is_refused(keys, monkeypatch):
    from cryptography.hazmat.primitives.asymmetric import rsa

    import tainted_ci.oidc as oidc

    monkeypatch.setenv("GITHUB_REPOSITORY", "me/app")
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    result = oidc.verify_ci_ownership(_signed(other))
    assert not result.verified
    assert "not a live GitHub Actions token" in result.detail


def test_an_unreachable_key_server_refuses_and_says_it_could_not_check(monkeypatch):
    """Uncheckable is not a verdict, and must not read as one either way."""
    import tainted_ci.oidc as oidc

    class Down:
        def __init__(self, url):
            pass

        def get_signing_key_from_jwt(self, token):
            raise OSError("network down")

    monkeypatch.setattr("jwt.PyJWKClient", Down)
    monkeypatch.setenv("GITHUB_REPOSITORY", "me/app")
    token = _fake_jwt({"iss": GITHUB_ISS, "repository": "me/app"})
    result = oidc.verify_ci_ownership(token)
    assert not result.verified
    assert "could not be checked" in result.detail


# --------------------------------------------------------------------------- #
# Check selection — `only` / `skip`
#
# The action had no way to choose checks, so test_integrity, which runs only when named, could
# never run in CI at all. A misspelt name must stop the job: silently ignoring it would let the
# gate pass on a scan narrower or wider than the one asked for.
# --------------------------------------------------------------------------- #
def test_a_misspelt_check_fails_the_job_before_anything_runs(monkeypatch, capsys):
    from tainted_ci import entrypoint

    monkeypatch.setenv("TAINTED_REPO", REPO)
    monkeypatch.setenv("TAINTED_ONLY", "bola,rsl")
    monkeypatch.delenv("TAINTED_TARGET_URL", raising=False)
    monkeypatch.setattr(
        entrypoint, "core_analyze", lambda *a, **k: (_ for _ in ()).throw(AssertionError("ran"))
    )
    assert entrypoint.run() == 2
    assert "rsl" in capsys.readouterr().out


def test_only_and_skip_reach_the_engine(monkeypatch):
    from tainted.models import Check
    from tainted_ci import entrypoint

    seen = {}

    def fake_analyze(repo, **kwargs):
        seen.update(kwargs)
        return core_analyze(repo, only=kwargs["only"], skip=kwargs["skip"])

    monkeypatch.setenv("TAINTED_REPO", REPO)
    monkeypatch.setenv("TAINTED_ONLY", " RLS , bola")
    monkeypatch.setenv("TAINTED_SKIP", "bola")
    monkeypatch.delenv("TAINTED_TARGET_URL", raising=False)
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
    monkeypatch.setattr(entrypoint, "core_analyze", fake_analyze)
    entrypoint.run()
    assert seen["only"] == {Check.RLS, Check.BOLA}
    assert seen["skip"] == {Check.BOLA}


def test_an_unmeasured_test_integrity_run_says_so():
    """Asked for and not measured must not read the same as never asked for."""
    from tainted.models import Check

    def missing_tool(cmd, cwd):
        from tainted.checks.test_integrity import CommandResult

        return CommandResult(returncode=127, tool_missing=True)

    result = core_analyze(REPO, only={Check.TEST_INTEGRITY}, mutation_runner=missing_tool)
    md = render_markdown(build_report(result), "prove skipped: test")
    assert "### Test integrity" in md
    assert "Not measured" in md
