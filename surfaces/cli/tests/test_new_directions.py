"""The three commands the new engine operations reach the terminal through.

Each test asserts the behaviour that keeps the command honest rather than its prose: an untested
lockout exits non-zero instead of printing a pass, an unfired invariant is labelled not-tested,
and an unsigned receipt still carries its admissions.
"""

from __future__ import annotations

import json

from typer.testing import CliRunner

from tainted_cli.main import app

runner = CliRunner()


def _repo(tmp_path):
    (tmp_path / "app.py").write_text(
        "from flask import Flask\n"
        "app = Flask(__name__)\n\n"
        "@app.route('/api/users/<user_id>')\n"
        "def get_user(user_id):\n"
        "    return db.execute('select * from users where id = ' + user_id)\n",
        encoding="utf-8",
    )
    return tmp_path


def test_lockout_with_an_unreachable_target_does_not_report_a_pass():
    result = runner.invoke(
        app,
        [
            "lockout",
            "--url", "http://127.0.0.1:9",  # nothing listens here
            "--login-a", "a@x.com:pw",
            "--seed", "invoices:42",
        ],
    )
    # Either it could not decide (exit 2) or it found the owner locked out (exit 1).
    # The one outcome that must never happen is a silent success.
    assert result.exit_code != 0


def test_invariants_without_a_model_reports_not_tested_not_held(tmp_path, monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    result = runner.invoke(
        app,
        [
            "invariants",
            str(_repo(tmp_path)),
            "--rule", "No user should see another user's email",
            "--url", "http://localhost:3000",
            "--login-b", "b@x.com:pw",
        ],
    )
    assert result.exit_code == 0  # nothing was violated, because nothing was tested
    assert "not_tested" in result.output
    assert "is not a rule that held" in result.output


def test_receipt_emits_json_carrying_its_untested_surface(tmp_path):
    result = runner.invoke(app, ["receipt", str(_repo(tmp_path))])
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert "not_tested" in payload
    assert "digest" in payload
    assert "signature" not in payload  # no secret supplied, so nothing is claimed to be signed


def test_receipt_signs_when_given_a_secret(tmp_path):
    result = runner.invoke(
        app, ["receipt", str(_repo(tmp_path)), "--secret", "hunter2"]
    )
    payload = json.loads(result.output)
    assert len(payload["signature"]) == 64

    from tainted.receipt import verify_payload

    assert verify_payload(payload, payload["signature"], b"hunter2") is True
    payload["not_tested"] = {}
    assert verify_payload(payload, payload["signature"], b"hunter2") is False
