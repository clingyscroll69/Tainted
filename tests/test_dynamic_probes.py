"""Dynamic request-plane proof against a mocked Supabase PostgREST server."""

from __future__ import annotations

import json

import httpx
import pytest

from tainted.dynamic.probes import prove_candidate
from tainted.dynamic.replay import SupabaseReplay
from tainted.dynamic.target import Account, ProveSetup, SeedRecord, Target
from tainted.models import Candidate, Check, FindingStatus, Plane, SourceLocation

SEED_ID = "11111111-1111-1111-1111-111111111111"


def make_setup(**overrides) -> ProveSetup:
    base = dict(
        target=Target(url="http://localhost:54321", anon_key="anon"),
        account_a=Account(label="A", email="a@x.com", password="pw", access_token="tok-A"),
        account_b=Account(label="B", email="b@x.com", password="pw"),
        seed=SeedRecord(table="invoices", id=SEED_ID, owner_column="owner"),
        row_cap=5,
    )
    base.update(overrides)
    return ProveSetup(**base)


def rls_candidate(table: str, owner_column: str | None = None) -> Candidate:
    return Candidate(
        check=Check.RLS,
        plane=Plane.REQUEST,
        title=f"RLS hole on {table}",
        location=SourceLocation(file="src/data.ts", line=1),
        metadata={"table": table, "owner_column": owner_column},
    )


def make_handler(record_capture: list):
    """A mock PostgREST/GoTrue.

    `invoices` leaks A's row to B (BOLA). `notes` returns rows owned by A on an unfiltered read
    (RLS absent). `own_notes` returns rows B legitimately owns — the correctly-scoped table that
    must NOT be called a leak. `opaque` returns rows with no owner column at all.
    """

    def handler(request: httpx.Request) -> httpx.Response:
        record_capture.append(request)
        if request.url.path == "/auth/v1/token":
            return httpx.Response(
                200, json={"access_token": "tok-B", "user": {"id": "user-B"}}
            )
        if request.url.path == "/rest/v1/invoices":
            # Targeted: id=eq.<seed>. B's token still gets A's row back (BOLA).
            if request.url.params.get("id") == f"eq.{SEED_ID}":
                return httpx.Response(
                    200, json=[{"id": SEED_ID, "owner": "user-A", "amount": 999}]
                )
            return httpx.Response(200, json=[])
        limit = int(request.url.params.get("limit", "1000"))
        if request.url.path == "/rest/v1/notes":
            # Unfiltered read returns rows owned by A -> the boundary is gone.
            rows = [{"id": f"n{i}", "author": "user-A", "body": "secret"} for i in range(20)]
            return httpx.Response(200, json=rows[:limit])
        if request.url.path == "/rest/v1/own_notes":
            # A correctly-scoped table: B's unfiltered read returns only B's own rows.
            rows = [{"id": f"b{i}", "author": "user-B", "body": "mine"} for i in range(20)]
            return httpx.Response(200, json=rows[:limit])
        if request.url.path == "/rest/v1/opaque":
            # Rows come back, but nothing in them says who owns them.
            rows = [{"id": f"o{i}", "body": "?"} for i in range(20)]
            return httpx.Response(200, json=rows[:limit])
        return httpx.Response(404, json=[])

    return handler


@pytest.fixture
def captured():
    return []


@pytest.fixture
def replay(captured):
    client = httpx.Client(transport=httpx.MockTransport(make_handler(captured)))
    return SupabaseReplay(Target(url="http://localhost:54321", anon_key="anon"), client)


def test_targeted_bola_fires_first_and_proves(replay, captured):
    setup = make_setup()
    finding = prove_candidate(rls_candidate("invoices"), setup, replay)

    assert finding.status == FindingStatus.PROVEN
    assert finding.proof.kind == "targeted_bola"  # surgical probe, not the blunt one
    assert finding.proof.rows_returned == 1  # A's row and only A's row
    # The proof carries the exact request and the response body proving the leak.
    assert finding.proof.exploit.method == "GET"
    assert "invoices" in finding.proof.exploit.url
    assert SEED_ID in finding.proof.response_body
    # The bearer token is redacted in the recorded exploit.
    assert "tok-B" not in json.dumps(finding.proof.exploit.headers)


def test_unfiltered_rls_respects_row_cap(replay, captured):
    # notes has no seed match, so the blunt probe runs; the cap must bound the read.
    setup = make_setup(seed=SeedRecord(table="invoices", id=SEED_ID), row_cap=5)
    finding = prove_candidate(rls_candidate("notes", owner_column="author"), setup, replay)

    assert finding.status == FindingStatus.PROVEN
    assert finding.proof.kind == "unfiltered_rls"
    assert finding.proof.rows_returned == 5  # capped, not the full 20 rows
    assert finding.proof.row_cap == 5
    # The request actually sent limit=5.
    notes_req = [r for r in captured if r.url.path == "/rest/v1/notes"][0]
    assert notes_req.url.params.get("limit") == "5"
    # The proof names *why* it is a leak, not merely that rows came back.
    assert "owned by another account" in finding.proof.notes


def test_unfiltered_rls_does_not_prove_when_rows_belong_to_the_caller(replay):
    """The regression guard: rows alone are not a leak.

    A correctly-scoped table returns B's own rows to B with a 200. Calling that "proven" would
    be a false proof of the exact claim the product stakes its credibility on.
    """
    setup = make_setup(seed=SeedRecord(table="invoices", id=SEED_ID))
    finding = prove_candidate(rls_candidate("own_notes", owner_column="author"), setup, replay)

    assert finding.status == FindingStatus.NOT_REPRODUCED
    assert finding.proof.rows_returned == 5  # rows DID come back …
    assert finding.proof.succeeded is False  # … and that is not a leak
    assert "every row belongs to B" in finding.proof.notes


def test_unfiltered_rls_refuses_to_claim_a_leak_it_cannot_attribute(replay):
    """No owner column in the payload -> the probe says so instead of guessing."""
    setup = make_setup(seed=SeedRecord(table="invoices", id=SEED_ID))
    finding = prove_candidate(rls_candidate("opaque"), setup, replay)

    assert finding.status == FindingStatus.NOT_REPRODUCED
    assert finding.proof.rows_returned == 5
    assert "not attributable" in finding.proof.notes


def test_authentication_records_the_callers_own_user_id(replay):
    setup = make_setup()
    replay.authenticate(setup.account_b)
    assert setup.account_b.user_id == "user-B"


def test_authorization_holds_is_not_reproduced(replay):
    # A table the mock returns nothing for -> the boundary held.
    setup = make_setup(seed=SeedRecord(table="profiles", id=SEED_ID))
    finding = prove_candidate(rls_candidate("profiles"), setup, replay)
    assert finding.status == FindingStatus.NOT_REPRODUCED
    assert finding.proof.succeeded is False
