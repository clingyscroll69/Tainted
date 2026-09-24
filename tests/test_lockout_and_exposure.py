"""The lockout check (B01) and exposure measurement (B09).

Both exist to state something no severity label can. Lockout reports the *opposite* failure from a
vulnerability — secure and broken — and exposure replaces a guessed consequence with a counted
one. The tests below pin the properties that make each honest: an untested resource is never a
pass, and an uncounted table is never zero.
"""

from __future__ import annotations

import httpx

from tainted.dynamic.replay import SupabaseReplay
from tainted.dynamic.route_probes import RouteProber
from tainted.dynamic.target import Account, ProveSetup, SeedRecord, Target
from tainted.exposure import measure_exposure
from tainted.models import (
    Candidate,
    Check,
    Exploit,
    Finding,
    FindingStatus,
    ProbeResult,
    Severity,
    SourceLocation,
)
from tainted.operations import lockout_check


def _setup(route_path=None, seed=True):
    return ProveSetup(
        target=Target(url="http://localhost:3000", anon_key="anon"),
        account_a=Account(label="A", email="a@x.com", password="p", access_token="tok-a", user_id="uid-a"),
        account_b=Account(label="B", email="b@x.com", password="p", access_token="tok-b", user_id="uid-b"),
        seed=SeedRecord(table="invoices", id="42", owner_column="user_id", route_path=route_path)
        if seed
        else None,
    )


def _client(handler):
    return httpx.Client(transport=httpx.MockTransport(handler))


# ------------------------------- lockout (B01) ------------------------------ #
def test_owner_still_reads_own_row_is_not_a_lockout():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=[{"id": "42", "user_id": "uid-a"}])

    s = _setup()
    client = _client(handler)
    result = lockout_check(s, prober=RouteProber(s, client=client), replay=SupabaseReplay(s.target, client))
    assert result.ok is True
    assert result.locked_out == []


def test_owner_locked_out_of_own_row_is_reported():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, json={"error": "forbidden"})

    s = _setup()
    client = _client(handler)
    result = lockout_check(s, prober=RouteProber(s, client=client), replay=SupabaseReplay(s.target, client))
    assert result.ok is False
    assert len(result.locked_out) == 1
    assert "no longer" in result.locked_out[0].detail or "lost access" in result.locked_out[0].detail


def test_route_and_postgrest_are_both_checked_when_the_seed_names_a_route():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=[{"id": "42", "user_id": "uid-a"}])

    s = _setup(route_path="/api/invoices/[id]")
    client = _client(handler)
    result = lockout_check(s, prober=RouteProber(s, client=client), replay=SupabaseReplay(s.target, client))
    assert {c.via for c in result.checked} == {"route", "postgrest"}


def test_no_seed_is_undecided_and_never_ok():
    """The property that matters: nothing tested must not read as nothing wrong."""
    result = lockout_check(_setup(seed=False))
    assert result.ok is False
    assert result.checked == []
    assert result.undecided and "seed" in result.undecided[0]["reason"].lower()


def test_non_local_target_without_ownership_is_refused_not_passed():
    s = _setup()
    s.target = Target(url="https://someone-elses-app.com", anon_key="anon")
    result = lockout_check(s, ownership_verified=False)
    assert result.ok is False
    assert result.checked == []
    assert "ownership" in result.undecided[0]["reason"]


# ------------------------------ exposure (B09) ------------------------------ #
def _proven_finding():
    cand = Candidate(
        check=Check.RLS,
        title="invoices readable by any account",
        location=SourceLocation(file="db.sql", line=1),
        severity=Severity.HIGH,
        metadata={"table": "invoices"},
    )
    return Finding(
        candidate=cand,
        status=FindingStatus.PROVEN,
        proof=ProbeResult(
            succeeded=True,
            kind="unfiltered_rls",
            exploit=Exploit(description="read", url="http://x/rest/v1/invoices", executed=True),
            response_body='[{"id": "42", "user_id": "uid-a", "amount": 100}]',
        ),
    )


def test_exposure_is_opt_in_and_silence_is_recorded():
    """Without consent nothing is counted — and the finding is listed as skipped, not as zero."""
    report = measure_exposure([_proven_finding()], _setup(), consented=False)
    assert report.measured == []
    assert len(report.skipped) == 1
    assert report.total_rows is None


def test_exposure_counts_rows_without_pulling_them():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.headers.get("Prefer") == "count=exact":
            seen["limit"] = request.url.params.get("limit")
            return httpx.Response(
                200, json=[{"id": "42"}], headers={"Content-Range": "0-0/1240"}
            )
        return httpx.Response(200, json=[{"id": "42", "user_id": "uid-a", "amount": 100}])

    s = _setup()
    replay = SupabaseReplay(s.target, _client(handler))
    report = measure_exposure([_proven_finding()], s, replay=replay, consented=True)

    assert len(report.measured) == 1
    e = report.measured[0]
    assert e.counted is True
    assert e.reachable_rows == 1240
    assert e.values_collected is False
    # The count came back while the body stayed at a single row — the whole point.
    assert seen["limit"] == "1"


def test_columns_come_from_the_existing_proof_not_a_new_read():
    """The response that proved the hole already names the columns; re-reading would be gratuitous."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=[], headers={"Content-Range": "0-0/7"})

    s = _setup()
    replay = SupabaseReplay(s.target, _client(handler))
    report = measure_exposure([_proven_finding()], s, replay=replay, consented=True)
    assert set(report.measured[0].columns) == {"id", "user_id", "amount"}


def test_uncounted_is_not_zero():
    """A server that declines to count leaves the exposure unknown, and the report must say so."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=[{"id": "42"}])  # no Content-Range at all

    s = _setup()
    replay = SupabaseReplay(s.target, _client(handler))
    report = measure_exposure([_proven_finding()], s, replay=replay, consented=True)
    e = report.measured[0]
    assert e.counted is False
    assert e.reachable_rows is None
    assert "not counted" in e.headline
    assert report.total_rows is None


def test_a_suspicion_is_never_sized():
    """A number attached to an unproven hole would read as a measured fact."""
    f = _proven_finding()
    f.status = FindingStatus.REPORTED
    report = measure_exposure([f], _setup(), consented=True)
    assert report.measured == []
    assert "only a hole that actually fired" in report.skipped[0]["reason"]
