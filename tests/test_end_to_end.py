"""Full engine smoke: analyze -> prove -> fix over the vulnerable fixture.

`prove`/`fix` run against a mocked running instance of the fixture app (a stand-in PostgREST),
so the whole loop is exercised without a live server.
"""

from __future__ import annotations

import httpx
import pytest

from tainted import analyze, fix, prove
from tainted.dynamic.replay import SupabaseReplay
from tainted.dynamic.target import Account, ProveSetup, SeedRecord, Target
from tainted.models import Check, FindingStatus
from tainted.orchestrator import OwnershipError

INVOICE_ID = "aaaa1111-0000-0000-0000-000000000001"


def _setup(url="http://localhost:54321") -> ProveSetup:
    return ProveSetup(
        target=Target(url=url, anon_key="anon"),
        account_a=Account(label="A", access_token="tok-A"),
        account_b=Account(label="B", access_token="tok-B"),
        seed=SeedRecord(table="invoices", id=INVOICE_ID, owner_column="owner"),
    )


def _vulnerable(request):
    # Mirrors the fixture: invoices (permissive), notes (rls off) leak; profiles is scoped.
    p = request.url.path
    if p == "/rest/v1/invoices":
        return httpx.Response(200, json=[{"id": INVOICE_ID, "owner": "user-A", "amount": 500}])
    if p == "/rest/v1/notes":
        return httpx.Response(200, json=[{"id": "n1", "author": "user-A", "body": "x"}] * 3)
    if p == "/rest/v1/public_posts":
        return httpx.Response(200, json=[{"id": "p1", "title": "hello"}])
    if p == "/rest/v1/profiles":
        # scoped: B (the caller in prove) sees nothing
        return httpx.Response(200, json=[])
    return httpx.Response(404, json=[])


def _replay(handler):
    return SupabaseReplay(
        Target(url="http://localhost:54321", anon_key="anon"),
        httpx.Client(transport=httpx.MockTransport(handler)),
    )


def test_full_loop_analyze_prove_fix(vuln_repo):
    # analyze — static, no LLM needed (RLS holes are structural).
    result = analyze(vuln_repo)
    tables = {c.metadata.get("table") for c in result.by_check(Check.RLS)}
    assert {"invoices", "notes"} <= tables
    assert "profiles" not in tables  # correctly scoped table is spared

    # prove — against the mocked running instance.
    findings = prove(result, _setup(), replay=_replay(_vulnerable))
    proven = [f for f in findings if f.status == FindingStatus.PROVEN]
    assert proven, "expected at least the invoices/notes holes to be proven"
    # The targeted probe on invoices returns A's seed row to B.
    invoices = next(f for f in findings if f.candidate.metadata.get("table") == "invoices")
    assert invoices.status == FindingStatus.PROVEN
    assert INVOICE_ID in invoices.proof.response_body

    # fix — the patch; then prove again against the target with it applied.
    patch = fix(invoices)
    assert patch.edits and "run `prove`" in patch.notes

    def _fixed(request):
        if request.url.path == "/rest/v1/invoices":
            auth = request.headers.get("authorization", "")
            if "tok-A" in auth:
                return httpx.Response(200, json=[{"id": INVOICE_ID, "owner": "user-A"}])
            return httpx.Response(200, json=[])
        return httpx.Response(404, json=[])

    after = prove(result, _setup(), replay=_replay(_fixed))
    invoices_after = next(f for f in after if f.candidate.metadata.get("table") == "invoices")
    assert invoices_after.status is not FindingStatus.PROVEN


def test_prove_refuses_unverified_remote_target(vuln_repo):
    result = analyze(vuln_repo)
    remote = _setup(url="https://someone-elses-app.vercel.app")
    with pytest.raises(OwnershipError):
        prove(result, remote, replay=_replay(_vulnerable))
    # With ownership verified out of band, it proceeds.
    findings = prove(
        result, remote, replay=_replay(_vulnerable), ownership_verified=True
    )
    assert findings
