"""The fix loop: deterministic RLS fix + re-prove with two assertions.

Uses two mock PostgREST servers: one *before* the fix (leaks A's row to B) and one *after* the
fix migration is applied (B is denied, A still reads A's own row). The re-verify must flip the
finding to FIXED only when both assertions hold.
"""

from __future__ import annotations

import httpx

from tainted.dynamic.probes import prove_candidate
from tainted.dynamic.replay import SupabaseReplay
from tainted.dynamic.target import Account, ProveSetup, SeedRecord, Target
from tainted.fix.deterministic import generate_rls_fix
from tainted.models import (
    Candidate,
    Check,
    FindingStatus,
    Plane,
    SourceLocation,
)
from tainted.orchestrator import fix

SEED_ID = "11111111-1111-1111-1111-111111111111"


def _setup() -> ProveSetup:
    return ProveSetup(
        target=Target(url="http://localhost:54321", anon_key="anon"),
        account_a=Account(label="A", access_token="tok-A"),
        account_b=Account(label="B", access_token="tok-B"),
        seed=SeedRecord(table="invoices", id=SEED_ID, owner_column="owner"),
    )


def _candidate() -> Candidate:
    return Candidate(
        check=Check.RLS,
        plane=Plane.REQUEST,
        title="Permissive true policy on invoices",
        location=SourceLocation(file="supabase/migrations/0001.sql", line=10),
        structural=True,
        metadata={"table": "invoices", "owner_column": "owner", "policy": "invoices readable"},
    )


def _who(request: httpx.Request) -> str:
    auth = request.headers.get("authorization", "")
    return auth.replace("Bearer ", "")


def _before_handler(request):
    # Vulnerable: any authenticated caller gets A's row.
    if request.url.path == "/rest/v1/invoices":
        return httpx.Response(200, json=[{"id": SEED_ID, "owner": "user-A", "amount": 999}])
    return httpx.Response(404, json=[])


def _after_handler(request):
    # Fixed: RLS enforces owner = auth.uid(). Only A sees A's row; B gets nothing.
    if request.url.path == "/rest/v1/invoices":
        if _who(request) == "tok-A":
            return httpx.Response(200, json=[{"id": SEED_ID, "owner": "user-A", "amount": 999}])
        return httpx.Response(200, json=[])  # B denied by policy
    return httpx.Response(404, json=[])


def _replay(handler):
    return SupabaseReplay(
        Target(url="http://localhost:54321", anon_key="anon"),
        httpx.Client(transport=httpx.MockTransport(handler)),
    )


# --------------------------------------------------------------------------- #
def test_deterministic_fix_generates_scoped_policy():
    edits, note, complete = generate_rls_fix(_candidate())
    assert complete is True  # owner column was inferable
    sql = edits[0].replacement
    assert "enable row level security" in sql
    assert "auth.uid() = owner" in sql
    assert 'drop policy if exists "invoices readable"' in sql  # replaces the permissive one


def test_fix_reproves_closed_with_both_assertions():
    setup = _setup()
    # Sanity: before the fix, the attack is proven.
    before = prove_candidate(_candidate(), setup, _replay(_before_handler))
    assert before.status == FindingStatus.PROVEN

    # Apply the fix and re-verify against the fixed target.
    result = fix(before, setup=setup, replay_after=_replay(_after_handler))

    assert result.resulting_status == FindingStatus.FIXED
    assert result.all_assertions_passed
    names = {a.name: a.passed for a in result.assertions}
    assert names["attack_now_fails"] is True
    assert names["legitimate_access_survives"] is True


def test_fix_that_locks_out_owner_is_broke_it_safely():
    setup = _setup()
    before = prove_candidate(_candidate(), setup, _replay(_before_handler))

    def _overzealous(request):
        # Denies EVERYONE, including the legitimate owner A.
        if request.url.path == "/rest/v1/invoices":
            return httpx.Response(200, json=[])
        return httpx.Response(404, json=[])

    result = fix(before, setup=setup, replay_after=_replay(_overzealous))
    assert result.resulting_status == FindingStatus.BROKE_IT_SAFELY
    assert result.all_assertions_passed is False


def test_patch_only_when_no_target():
    before = prove_candidate(_candidate(), _setup(), _replay(_before_handler))
    result = fix(before)  # no setup/replay -> website-style patch-only mode
    assert result.edits
    assert not result.assertions
    assert "patch-only" in result.notes
