"""The four tools the new engine operations reach a calling agent through.

An MCP tool is called by a model, so the tests that matter are the ones about what it refuses:
non-local targets, missing credentials it must ask a human for, and a finding it cannot honestly
turn into a test.
"""

from __future__ import annotations

import asyncio

from tainted_mcp.server import (
    server,
    tainted_invariants,
    tainted_lockout,
    tainted_receipt,
    tainted_regression_test,
)


def test_the_new_tools_are_registered():
    names = {t.name for t in asyncio.run(server.list_tools())}
    assert {
        "tainted_lockout",
        "tainted_invariants",
        "tainted_receipt",
        "tainted_regression_test",
    } <= names


# ---------------------------------- lockout --------------------------------- #
def test_lockout_asks_the_human_for_the_owner_login():
    """Credentials are the developer's to give. The tool must prompt, not invent."""
    out = tainted_lockout(url="http://localhost:3000")
    assert out["action_required"] == "ask_user"
    assert out["needs_credentials"] == ["login_a"]


def test_lockout_refuses_a_non_local_target():
    out = tainted_lockout(url="https://example.com", login_a="a@x.com:pw", seed="t:1")
    assert "not local" in out["error"]


# --------------------------------- invariants ------------------------------- #
def test_invariants_asks_the_human_for_the_attacking_login():
    out = tainted_invariants(repo_path=".", rules="no cross-user reads", url="http://localhost:3000")
    assert out["action_required"] == "ask_user"


def test_invariants_refuses_a_non_local_target():
    out = tainted_invariants(
        repo_path=".", rules="no cross-user reads", url="https://example.com", login_b="b@x.com:pw"
    )
    assert "not local" in out["error"]


def test_invariants_refuses_an_empty_rule_set():
    out = tainted_invariants(repo_path=".", rules="  |  ", url="http://localhost:3000")
    assert "No rules" in out["error"]


# ---------------------------------- receipt --------------------------------- #
def test_receipt_is_unsigned_by_default_and_says_so():
    out = tainted_receipt(repo_path="tests/fixtures/vulnerable_routes")
    assert "not signed" in out["unsigned"]
    assert "not_tested" in out


def test_receipt_signs_when_given_a_secret():
    out = tainted_receipt(repo_path="tests/fixtures/vulnerable_routes", secret="k")
    assert len(out["signature"]) == 64
    assert "unsigned" not in out

    from tainted.receipt import verify_payload

    assert verify_payload(out, out["signature"], b"k") is True


# ----------------------------- regression test ------------------------------ #
def test_regression_test_needs_a_completed_prove_job():
    out = tainted_regression_test(repo_path=".", job_id="no-such-job")
    assert "No completed prove job" in out["error"]
