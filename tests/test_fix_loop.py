"""The fix loop: a deterministic RLS fix, verified by proving again once it is live.

Uses two mock PostgREST servers: one *before* the fix (leaks A's row to B) and one *after* the
fix migration is applied (B is denied, A still reads A's own row). `fix` writes the patch and
claims nothing about it; `prove` against the fixed target is what shows the hole closed.
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


def test_fix_is_a_patch_and_names_prove_as_its_verification():
    """Re-running the attack beside an unapplied patch only re-finds the hole, so fix doesn't."""
    before = prove_candidate(_candidate(), _setup(), _replay(_before_handler))
    assert before.status == FindingStatus.PROVEN

    result = fix(before)
    assert result.edits
    assert not result.assertions
    assert result.resulting_status is FindingStatus.CANDIDATE
    assert "run `prove`" in result.notes


def test_proving_again_once_the_fix_is_live_shows_the_hole_closed():
    before = prove_candidate(_candidate(), _setup(), _replay(_before_handler))
    fix(before)  # the patch, applied and deployed as `_after_handler`
    after = prove_candidate(_candidate(), _setup(), _replay(_after_handler))
    assert after.status is FindingStatus.NOT_REPRODUCED
