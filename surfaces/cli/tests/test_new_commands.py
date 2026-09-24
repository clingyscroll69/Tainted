"""CLI commands added in 0.2.0: sarif, mutate-security, ledger, and the prove budget flags."""

from __future__ import annotations

import json

from typer.testing import CliRunner

from tainted_cli.main import app

runner = CliRunner()
ROUTES = "tests/fixtures/vulnerable_routes"


def test_sarif_emits_valid_sarif():
    res = runner.invoke(app, ["sarif", ROUTES])
    assert res.exit_code == 0
    doc = json.loads(res.stdout)
    assert doc["version"] == "2.1.0"
    assert "notTested" in doc["runs"][0]["properties"]["tainted"]


def test_mutate_security_lists_survivors(tmp_path):
    (tmp_path / "route.ts").write_text(
        "const d = await db.from('t').select('*').eq('id', id).eq('user_id', user.id);\n"
    )
    res = runner.invoke(app, ["mutate-security", str(tmp_path)])
    assert res.exit_code == 0  # unassessed (no --test-cmd), so no failure
    assert "survived" in res.stdout


def test_ledger_shows_what_was_not_tested():
    res = runner.invoke(app, ["ledger", ROUTES])
    assert res.exit_code == 0
    assert "clean bill of health" in res.stdout


def test_prove_rejects_non_local_before_budget_matters():
    res = runner.invoke(app, [
        "prove", ROUTES, "--url", "https://example.com",
        "--login-a", "a:b", "--login-b", "c:d", "--max-minutes", "1",
    ])
    assert res.exit_code == 2  # non-local refused, as always
