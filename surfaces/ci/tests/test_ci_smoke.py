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
