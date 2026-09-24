"""The two request-plane probes — surgical before blunt, two questions.

  * Targeted BOLA (always first): account B requests account A's known seed id. Success means
    B received A's row and only A's row — one record, no collateral.
  * Unfiltered RLS (only when the targeted shape doesn't apply or doesn't fire): B queries with
    no ownership filter, row-capped. A different finding — absent row-level security. Five rows
    prove the boundary is gone as well as fifty thousand.

The output is the exact request, the response body that proves the leak, and the fix.
"""

from __future__ import annotations

from typing import Optional

import httpx

from tainted.dynamic.replay import SupabaseReplay
from tainted.dynamic.target import ProveSetup, SeedRecord
from tainted.models import (
    Candidate,
    Exploit,
    Finding,
    FindingStatus,
    ProbeResult,
    Provenance,
    Register,
)


def _redact(token: Optional[str]) -> str:
    if not token:
        return "<none>"
    return f"{token[:8]}…{token[-4:]}" if len(token) > 16 else "<token>"


def _exploit_from_response(resp: httpx.Response, description: str) -> Exploit:
    req = resp.request
    headers = {
        k: (_redact(v.split(" ", 1)[-1]) if k.lower() == "authorization" else v)
        for k, v in req.headers.items()
        if k.lower() in ("authorization", "apikey", "accept", "content-type")
    }
    return Exploit(
        description=description,
        method=req.method,
        url=str(req.url),
        headers=headers,
        executed=True,
    )


def _table_of(candidate: Candidate, setup: ProveSetup) -> Optional[str]:
    return candidate.metadata.get("table") or (setup.seed.table if setup.seed else None)


def prove_candidate(
    candidate: Candidate, setup: ProveSetup, replay: SupabaseReplay
) -> Finding:
    """Carry one candidate through live proof and return a Finding with its outcome."""
    table = _table_of(candidate, setup)
    finding = Finding(candidate=candidate)
    if table is None:
        # Nothing was sent, so this is not an attack that held.
        return _unreachable(finding, "No table to probe, so no request was sent.")

    # A target that cannot be reached has not resisted anything. Every other probe path
    # degrades this way (`route_probes`, `injection_probes`); this one used to raise straight
    # out of `prove`, so an app that was not running yet produced a traceback instead of a run.
    try:
        replay.authenticate(setup.account_b)

        # ---- Targeted BOLA (surgical, first) ---- #
        if setup.seed is not None and setup.seed.table == table:
            result = _targeted_bola(setup, setup.seed, replay, table)
            if result.succeeded:
                return _proven(finding, result)
            # Fall through to the blunt probe if the surgical one didn't fire.

        # ---- Unfiltered RLS (blunt, row-capped) ---- #
        result = _unfiltered_rls(
            setup, replay, table, owner_column=candidate.metadata.get("owner_column")
        )
    except httpx.HTTPError as exc:
        return _unreachable(finding, f"Request-plane probe could not reach the target: {exc}")

    if result.succeeded:
        return _proven(finding, result)

    finding.status = FindingStatus.NOT_REPRODUCED
    finding.proof = result
    return finding


def _targeted_bola(
    setup: ProveSetup, seed: SeedRecord, replay: SupabaseReplay, table: str
) -> ProbeResult:
    # The seed is a parameter rather than read from `setup` so the caller's `is not None`
    # guard is the type the function receives, not a fact it has to trust.
    resp = replay.select_by_id(
        setup.account_b, table, seed.id, id_column=seed.id_column
    )
    rows = replay.rows(resp)
    got_a_row = resp.status_code == 200 and any(
        str(r.get(seed.id_column)) == str(seed.id) for r in rows
    )
    exploit = _exploit_from_response(
        resp,
        f"Account {setup.account_b.label} requested account {setup.account_a.label}'s "
        f"`{table}` record `{seed.id}`.",
    )
    return ProbeResult(
        succeeded=got_a_row,
        kind="targeted_bola",
        exploit=exploit,
        response_status=resp.status_code,
        response_body=resp.text[:2000],
        rows_returned=len(rows),
        notes=(
            f"B received A's row (and {len(rows)} row(s) total)."
            if got_a_row
            else "B did not receive A's row. Either the check held or the row does not exist."
        ),
    )


def _unfiltered_rls(
    setup: ProveSetup, replay: SupabaseReplay, table: str, owner_column: Optional[str] = None
) -> ProbeResult:
    cap = setup.row_cap
    resp = replay.select_unfiltered(setup.account_b, table, cap)
    rows = replay.rows(resp)

    # A leak is only proven when B's unfiltered read returns a row B demonstrably does NOT own.
    # Rows alone prove nothing: a correctly-scoped table returns B's own rows to B with a 200,
    # and calling that a leak would be a false proof of the very claim this product stakes its
    # credibility on. So ownership must be attributable, by one of two independent routes.
    seed_leaked = bool(
        setup.seed
        and setup.seed.table == table
        and any(str(r.get(setup.seed.id_column)) == str(setup.seed.id) for r in rows)
    )
    foreign_rows, attributable = _foreign_rows(rows, setup, owner_column)
    definite = resp.status_code == 200 and (seed_leaked or bool(foreign_rows))

    exploit = _exploit_from_response(
        resp,
        f"Account {setup.account_b.label} read `{table}` with no ownership filter "
        f"(capped at {cap} rows).",
    )
    return ProbeResult(
        succeeded=definite,
        kind="unfiltered_rls",
        exploit=exploit,
        response_status=resp.status_code,
        response_body=resp.text[:2000],
        rows_returned=len(rows),
        row_cap=cap,
        notes=_unfiltered_notes(
            setup, table, rows, seed_leaked, foreign_rows, attributable, definite, resp
        ),
    )


def _foreign_rows(
    rows: list[dict], setup: ProveSetup, owner_column: Optional[str]
) -> tuple[list[dict], bool]:
    """Rows whose owner column names somebody other than B.

    Returns (foreign_rows, attributable). `attributable` is False when we cannot tell who owns
    a row — no owner column in the payload, or B's own user id unknown — in which case the
    probe must not claim a leak, and says so.
    """
    col = owner_column or (setup.seed.owner_column if setup.seed else None)
    b_id = setup.account_b.user_id
    if not col or not b_id or not rows:
        return [], False
    if not any(col in r for r in rows):
        return [], False
    foreign = [r for r in rows if col in r and str(r.get(col)) != str(b_id)]
    return foreign, True


def _unfiltered_notes(
    setup: ProveSetup,
    table: str,
    rows: list[dict],
    seed_leaked: bool,
    foreign_rows: list[dict],
    attributable: bool,
    definite: bool,
    resp: httpx.Response,
) -> str:
    b = setup.account_b.label
    if definite:
        why = (
            f"One of them is account {setup.account_a.label}'s seed row."
            if seed_leaked
            else f"{len(foreign_rows)} of them are owned by another account."
        )
        return f"{b} pulled {len(rows)} row(s) from `{table}` with no filter. {why}"
    if not rows:
        return "No rows came back. The boundary appears to hold."
    if not attributable:
        return (
            f"{b} pulled {len(rows)} row(s) from `{table}`, but Tainted cannot tell who owns "
            f"them (no owner column in the response, or {b}'s user id is unknown). This is not "
            f"attributable, so it is not claimed as a leak. Give a seed record or an owner "
            f"column to decide it."
        )
    return (
        f"{b} pulled {len(rows)} row(s) from `{table}`, but every row belongs to {b}. "
        f"The ownership boundary held."
    )


def _unreachable(finding: Finding, why: str) -> Finding:
    """REPORTED, not NOT_REPRODUCED.

    NOT_REPRODUCED means the attack ran and the boundary held. Saying that about a target we
    never reached is a false all-clear — the one thing this tool must never print.
    """
    finding.status = FindingStatus.REPORTED
    finding.proof = ProbeResult(succeeded=False, kind="request_plane", notes=why)
    return finding


def _proven(finding: Finding, result: ProbeResult) -> Finding:
    finding.status = FindingStatus.PROVEN
    finding.proof = result
    finding.provenance.append(
        Provenance(origin=Register.PROOF, detail=f"live probe: {result.kind}")
    )
    return finding
