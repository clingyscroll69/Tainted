"""How much a proven hole actually reaches — a number, measured, not a severity label.

Every scanner answers "how bad is this?" with a word. The word is a guess about consequence made
before anyone looked. Once an exploit has actually fired, a better answer is available for free:
ask the target how many rows the attacking account can reach through the hole that was just
proven, and which columns come back.

Two rules shape the whole module, and both exist because the measurement is being taken against a
real application holding real people's data:

  * **Count, never collect.** PostgREST answers `Prefer: count=exact` with the total in a
    `Content-Range` header while `limit=1` keeps the body to one row. So the size of the exposure
    arrives without pulling the table. Column *names* are kept because they say what kind of data
    is exposed; column *values* are never stored, because a security tool that copies the database
    to describe the database has become the incident.

  * **Opt in, and never imply zero.** Measuring is off unless the caller asks for it, and a
    measurement that could not be taken reports `counted=False` with the reason. An uncounted hole
    is not a small hole. This is the same rule the coverage ledger applies to checks that did not
    run, applied to a number instead of a check.

Only a finding that actually fired is measured. Sizing a suspicion would attach a real number to an
unreal hole, which is precisely the overclaim the proof labels exist to prevent.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from tainted.dynamic.replay import SupabaseReplay
from tainted.dynamic.target import ProveSetup
from tainted.models import Finding, FindingStatus

# Statuses that mean an attack ran and the hole was real. Identical to the sets in
# `report.model`, `standards` and `memories` — evidence is evidence everywhere.
_PROOF_ESTABLISHING = frozenset(
    {FindingStatus.PROVEN, FindingStatus.FIXED, FindingStatus.BROKE_IT_SAFELY}
)


@dataclass(frozen=True)
class Exposure:
    """What one proven hole reaches, as measured against the running target.

    `reachable_rows` is `None` whenever `counted` is False, and the two must be read together: a
    `None` means nobody counted, which is a different statement from a count of zero and must
    never be rendered as one.
    """

    finding_id: str
    table: str
    counted: bool
    reachable_rows: Optional[int] = None
    columns: tuple[str, ...] = ()
    values_collected: bool = False  # always False; present so a reader can see the guarantee
    detail: str = ""

    @property
    def headline(self) -> str:
        if not self.counted:
            return f"`{self.table}`: not counted — {self.detail}"
        cols = ", ".join(self.columns) if self.columns else "no column names recovered"
        return (
            f"`{self.table}`: {self.reachable_rows} row(s) reachable by the attacking account. "
            f"Columns: {cols}."
        )

    def as_dict(self) -> dict:
        return {
            "finding_id": self.finding_id,
            "table": self.table,
            "counted": self.counted,
            "reachable_rows": self.reachable_rows,
            "columns": list(self.columns),
            "values_collected": self.values_collected,
            "detail": self.detail,
            "headline": self.headline,
        }


@dataclass
class ExposureReport:
    """Every measurement taken in one run, plus what was deliberately left unmeasured."""

    measured: list[Exposure] = field(default_factory=list)
    skipped: list[dict] = field(default_factory=list)

    @property
    def total_rows(self) -> Optional[int]:
        """Rows across everything actually counted, or None when nothing could be counted.

        Deliberately not a sum-with-zeros: adding an uncounted table in as 0 would understate the
        exposure in the one number a reader is most likely to quote.
        """
        counted = [e.reachable_rows for e in self.measured if e.counted and e.reachable_rows is not None]
        return sum(counted) if counted else None

    def as_dict(self) -> dict:
        return {
            "total_rows": self.total_rows,
            "measured": [e.as_dict() for e in self.measured],
            "skipped": self.skipped,
            "guarantee": (
                "Row counts and column names only. No column values were read into this report."
            ),
            "reminder": (
                "A table listed under `skipped`, or one whose `counted` is false, has an unknown "
                "exposure — not a small one."
            ),
        }


def measure_exposure(
    findings: list[Finding],
    setup: ProveSetup,
    replay: Optional[SupabaseReplay] = None,
    consented: bool = False,
) -> ExposureReport:
    """Size every proven hole in `findings` against the running target.

    `consented` is the switch, and it is off by default. Counting rows touches the owner's real
    data, and while a count is a far lighter touch than a read, it is still an action against a
    live system — so it happens because the caller asked for it, never because it was available.
    Without it, every finding is recorded as skipped with that reason rather than quietly
    measured or quietly dropped.
    """
    report = ExposureReport()
    if not consented:
        for f in findings:
            if f.status in _PROOF_ESTABLISHING:
                report.skipped.append(
                    {
                        "finding_id": f.candidate.id,
                        "reason": (
                            "Exposure measurement is opt-in. Nothing was counted, so the size of "
                            "this hole is unknown rather than small."
                        ),
                    }
                )
        return report

    replay = replay or SupabaseReplay(setup.target)
    for finding in findings:
        if finding.status not in _PROOF_ESTABLISHING:
            report.skipped.append(
                {
                    "finding_id": finding.candidate.id,
                    "reason": (
                        f"Status is {finding.status.value}; only a hole that actually fired is "
                        f"sized, because a number on a suspicion reads as a measured fact."
                    ),
                }
            )
            continue
        table = _table_for(finding, setup)
        if not table:
            report.skipped.append(
                {
                    "finding_id": finding.candidate.id,
                    "reason": "No table is recoverable from this finding, so there is nothing to count.",
                }
            )
            continue
        report.measured.append(_measure_one(finding, table, setup, replay))
    return report


def _measure_one(
    finding: Finding, table: str, setup: ProveSetup, replay: SupabaseReplay
) -> Exposure:
    """Count what account B reaches in `table`, and recover the column names from one row."""
    try:
        replay.authenticate(setup.account_b)
    except Exception as exc:  # noqa: BLE001 - auth against an unknown app fails many ways
        return Exposure(
            finding_id=finding.candidate.id,
            table=table,
            counted=False,
            detail=f"the attacking account could not authenticate: {exc}",
        )

    counted, total, detail = replay.count_reachable(setup.account_b, table)
    columns = _columns_from_finding(finding)
    if not columns and counted:
        columns = _columns_from_sample(replay, setup, table)
    return Exposure(
        finding_id=finding.candidate.id,
        table=table,
        counted=counted,
        reachable_rows=total,
        columns=columns,
        detail=detail,
    )


def _columns_from_finding(finding: Finding) -> tuple[str, ...]:
    """Column names already visible in the proof, so no extra request is made to learn them.

    The probe that proved the hole already holds a response body. Reading the key names out of it
    costs nothing and touches nothing, which is why it is tried before asking the target again.
    """
    proof = finding.proof
    if proof is None or not proof.response_body:
        return ()
    import json

    try:
        body = json.loads(proof.response_body)
    except Exception:
        return ()
    if isinstance(body, dict):
        body = [body]
    if not isinstance(body, list):
        return ()
    for row in body:
        if isinstance(row, dict) and row:
            return tuple(str(k) for k in row.keys())
    return ()


def _columns_from_sample(
    replay: SupabaseReplay, setup: ProveSetup, table: str
) -> tuple[str, ...]:
    """One row, for its key names only. The values are discarded here and never stored."""
    try:
        resp = replay.select_unfiltered(setup.account_b, table, 1)
    except Exception:  # noqa: BLE001
        return ()
    rows = replay.rows(resp)
    if not rows:
        return ()
    return tuple(str(k) for k in rows[0].keys())


def _table_for(finding: Finding, setup: ProveSetup) -> str:
    """The table this finding reaches, from the candidate first and the seed record second."""
    meta = finding.candidate.metadata
    for key in ("table", "target_table"):
        value = meta.get(key)
        if value:
            return str(value)
    if setup.seed is not None:
        return setup.seed.table
    return ""
