"""CI surface smoke tests (run with core + this surface on the path)."""

from __future__ import annotations

import base64
import json
from pathlib import Path

from tainted import analyze as core_analyze
from tainted.dynamic.target import Target
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
def test_unverifiable_signature_refuses_rather_than_allowing(monkeypatch):
    """PyJWT is absent in this environment, which is exactly the degraded case that used to
    return verified=True with a caveat appended."""
    import tainted_ci.oidc as oidc

    monkeypatch.setenv("GITHUB_REPOSITORY", "me/app")
    monkeypatch.setenv("TAINTED_OIDC_TOKEN", _fake_jwt({"repository": "me/app"}))

    result = oidc.verify_github_ownership(Target(url="https://preview.example.com"))
    assert not result.verified
    assert "signature" in result.detail.lower()


def test_a_forged_token_naming_someone_elses_repo_still_fails(monkeypatch):
    import tainted_ci.oidc as oidc

    monkeypatch.setenv("GITHUB_REPOSITORY", "me/app")
    monkeypatch.setenv("TAINTED_OIDC_TOKEN", _fake_jwt({"repository": "someone/else"}))
    result = oidc.verify_github_ownership(Target(url="https://preview.example.com"))
    assert not result.verified


def test_a_good_signature_is_what_makes_it_verified(monkeypatch):
    """With the signature check standing in as successful, the claims decide as before — so
    the refusal above is about the signature, not about the claims having stopped working."""
    import tainted_ci.oidc as oidc

    monkeypatch.setenv("GITHUB_REPOSITORY", "me/app")
    monkeypatch.setenv("TAINTED_OIDC_TOKEN", _fake_jwt({"repository": "me/app"}))
    monkeypatch.setattr(oidc, "verify_signature", lambda token, **kw: True)

    result = oidc.verify_github_ownership(Target(url="https://preview.example.com"))
    assert result.verified
    assert "signature verified" in result.detail


def test_a_bad_signature_is_refused_distinctly_from_an_uncheckable_one(monkeypatch):
    import tainted_ci.oidc as oidc

    monkeypatch.setenv("GITHUB_REPOSITORY", "me/app")
    monkeypatch.setenv("TAINTED_OIDC_TOKEN", _fake_jwt({"repository": "me/app"}))
    monkeypatch.setattr(oidc, "verify_signature", lambda token, **kw: False)

    result = oidc.verify_github_ownership(Target(url="https://preview.example.com"))
    assert not result.verified
    assert "not the provider" in result.detail
