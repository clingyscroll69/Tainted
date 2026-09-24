"""CI wiring for the receipt, the stated rules, and the owner-access gate.

The gates matter more than the rendering: a violated rule and a locked-out owner both have to
fail the build, and an unsigned receipt has to say so rather than pass as an attestation.
"""

from __future__ import annotations

import json
import os

import tainted_ci.entrypoint as ep
from tainted.invariants import InvariantReport, InvariantResult, InvariantVerdict
from tainted.operations import LockoutFinding, LockoutResult


def _clear_env(monkeypatch):
    for k in list(os.environ):
        if k.startswith("TAINTED_") or k in ("GITHUB_STEP_SUMMARY", "GITHUB_BASE_REF"):
            monkeypatch.delenv(k, raising=False)


REPO = "tests/fixtures/vulnerable_routes"


# ---------------------------------- receipt --------------------------------- #
def test_receipt_is_written_and_carries_its_untested_surface(tmp_path, monkeypatch):
    _clear_env(monkeypatch)
    out = tmp_path / "receipt.json"
    monkeypatch.setenv("TAINTED_REPO", REPO)
    monkeypatch.setenv("TAINTED_RECEIPT", str(out))
    ep.run()

    doc = json.loads(out.read_text())
    assert doc["version"] == "tainted-receipt/1"
    assert "not_tested" in doc
    assert "signature" not in doc


def test_an_unsigned_receipt_says_so_in_the_job_log(tmp_path, monkeypatch, capsys):
    _clear_env(monkeypatch)
    monkeypatch.setenv("TAINTED_REPO", REPO)
    monkeypatch.setenv("TAINTED_RECEIPT", str(tmp_path / "r.json"))
    ep.run()
    assert "UNSIGNED" in capsys.readouterr().out


def test_a_signed_receipt_verifies_and_resists_edits(tmp_path, monkeypatch):
    _clear_env(monkeypatch)
    out = tmp_path / "receipt.json"
    monkeypatch.setenv("TAINTED_REPO", REPO)
    monkeypatch.setenv("TAINTED_RECEIPT", str(out))
    monkeypatch.setenv("TAINTED_RECEIPT_SECRET", "ci-key")
    ep.run()

    from tainted.receipt import verify_payload

    doc = json.loads(out.read_text())
    assert verify_payload(doc, doc["signature"], b"ci-key") is True
    doc["not_tested"] = {}
    assert verify_payload(doc, doc["signature"], b"ci-key") is False


# ----------------------------------- gates ---------------------------------- #
def test_a_violated_rule_fails_the_build(monkeypatch, capsys):
    """A rule broken by a fired request is a proven finding aimed by a sentence."""
    _clear_env(monkeypatch)
    monkeypatch.setenv("TAINTED_REPO", REPO)
    monkeypatch.setenv("TAINTED_TARGET_URL", "http://localhost:3000")
    monkeypatch.setenv("TAINTED_INVARIANTS", "No user sees another user's email")

    report = InvariantReport(
        results=[
            InvariantResult(
                rule="No user sees another user's email",
                verdict=InvariantVerdict.VIOLATED,
                detail="returned 200 carrying `email`",
            )
        ]
    )
    monkeypatch.setattr(ep, "core_prove", lambda *a, **k: [])
    monkeypatch.setattr("tainted.invariants.check_invariants", lambda *a, **k: report)

    assert ep.run() == 1
    assert "stated rule" in capsys.readouterr().out


def test_a_rule_that_could_not_be_tested_does_not_fail_the_build(monkeypatch):
    """Not-tested is unknown, not broken. It must not gate, and it must not read as a pass."""
    _clear_env(monkeypatch)
    monkeypatch.setenv("TAINTED_REPO", REPO)
    monkeypatch.setenv("TAINTED_TARGET_URL", "http://localhost:3000")
    monkeypatch.setenv("TAINTED_INVARIANTS", "No user sees another user's email")

    report = InvariantReport(
        results=[
            InvariantResult(
                rule="No user sees another user's email",
                verdict=InvariantVerdict.NOT_TESTED,
                detail="no model configured",
            )
        ]
    )
    monkeypatch.setattr(ep, "core_prove", lambda *a, **k: [])
    monkeypatch.setattr("tainted.invariants.check_invariants", lambda *a, **k: report)

    assert ep.run() == 0


def test_a_locked_out_owner_fails_the_build(monkeypatch, capsys):
    _clear_env(monkeypatch)
    monkeypatch.setenv("TAINTED_REPO", REPO)
    monkeypatch.setenv("TAINTED_TARGET_URL", "http://localhost:3000")
    monkeypatch.setenv("TAINTED_LOCKOUT", "true")

    result = LockoutResult(
        checked=[
            LockoutFinding(
                resource="invoices",
                via="postgrest",
                owner_locked_out=True,
                detail="account A lost access to its own row",
            )
        ]
    )
    monkeypatch.setattr(ep, "core_prove", lambda *a, **k: [])
    monkeypatch.setattr("tainted.lockout_check", lambda *a, **k: result)

    assert ep.run() == 1
    assert "no longer reach" in capsys.readouterr().out


def test_an_undecided_lockout_does_not_fail_the_build(monkeypatch):
    """Nothing checked is not a failure — but the summary must not call it a pass either."""
    _clear_env(monkeypatch)
    monkeypatch.setenv("TAINTED_REPO", REPO)
    monkeypatch.setenv("TAINTED_TARGET_URL", "http://localhost:3000")
    monkeypatch.setenv("TAINTED_LOCKOUT", "true")

    result = LockoutResult(undecided=[{"resource": "x", "reason": "no seed record"}])
    monkeypatch.setattr(ep, "core_prove", lambda *a, **k: [])
    monkeypatch.setattr("tainted.lockout_check", lambda *a, **k: result)

    assert ep.run() == 0
    assert result.ok is False


def test_the_rendered_lockout_block_never_prints_nothing_checked_as_a_pass():
    from tainted_ci.render import render_lockout

    md = render_lockout(LockoutResult(undecided=[{"resource": "x", "reason": "no seed"}]))
    assert "This is not a pass" in md


def test_the_rendered_rules_block_keeps_not_tested_separate():
    from tainted_ci.render import render_invariants

    md = render_invariants(
        InvariantReport(
            results=[
                InvariantResult(rule="r1", verdict=InvariantVerdict.HELD, detail="d"),
                InvariantResult(rule="r2", verdict=InvariantVerdict.NOT_TESTED, detail="why"),
            ]
        )
    )
    assert "not_tested" in md and "is not a rule that held" in md
