"""CLI smoke tests (run with core + this surface on the path)."""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from tainted_cli.main import app

runner = CliRunner()
REPO = str(Path(__file__).resolve().parents[3] / "tests" / "fixtures" / "vulnerable_supabase")


def test_version():
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "tainted" in result.stdout


def test_analyze_json():
    result = runner.invoke(app, ["analyze", REPO, "--json"])
    assert result.exit_code == 0
    assert '"total_candidates"' in result.stdout


def test_fix_prints_migration():
    result = runner.invoke(app, ["fix", REPO, "--index", "0"])
    assert result.exit_code == 0
    assert "enable row level security" in result.stdout


def test_prove_refuses_remote_without_token():
    result = runner.invoke(
        app,
        ["prove", REPO, "--url", "https://x.vercel.app", "--login-a", "a:b", "--login-b", "c:d"],
    )
    assert result.exit_code == 2  # ownership refusal
