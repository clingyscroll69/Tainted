"""Views over a finished report: priority, standard ids, reproducers, and the silence ledger.

These are read-only projections of a `Report`. They live apart from `report/model.py` so the
report's own shape — the thing 200-odd tests pin — does not move when a new projection is added.
Each is a plain function returning plain data, so any surface can render it and the MCP/website
JSON can carry it without a schema change to the core model.
"""

from __future__ import annotations


from tainted.priority import priority_of, priority_of_candidate, weight_table
from tainted.repro import reproducer_dict
from tainted.report.model import Report
from tainted.standards import ids_for


def prioritized(report: Report) -> list[dict]:
    """Every finding and untried candidate on one 0-100 scale, highest first, arithmetic shown.

    Findings and candidates share the scale so a proven low and a reported critical can be
    compared directly — which is the entire point of the number.
    """
    rows: list[dict] = []
    for f in report.findings:
        p = priority_of(f)
        rows.append(
            {
                "id": f.candidate.id,
                "title": f.candidate.title,
                "status": f.status.value,
                "location": str(f.candidate.location),
                **p.as_dict(),
            }
        )
    for c in report.unproven_candidates:
        p = priority_of_candidate(c)
        rows.append(
            {
                "id": c.id,
                "title": c.title,
                "status": "candidate",
                "location": str(c.location),
                **p.as_dict(),
            }
        )
    rows.sort(key=lambda r: (-r["score"], -0, r["id"]))
    return rows


def priority_legend() -> list[dict]:
    """The published multiplier table, for a surface that wants to show its work."""
    return weight_table()


def standards(report: Report) -> list[dict]:
    """Catalogue identifiers per finding, each tiered proven vs static."""
    out: list[dict] = []
    for f in report.findings:
        ids = ids_for(f)
        out.append(
            {
                "id": f.candidate.id,
                "title": f.candidate.title,
                "tagged": ids.tagged(),
                **ids.as_dict(),
            }
        )
    return out


def reproducers(report: Report) -> list[dict]:
    """A curl line and replay script per proven finding; a reason where one can't be built."""
    out: list[dict] = []
    for f in report.proven_findings:
        out.append({"id": f.candidate.id, "title": f.candidate.title, **reproducer_dict(f)})
    return out


def silence_ledger(report: Report) -> dict:
    """What the run did NOT test, and why — promoted to a first-class artifact.

    Everything here already lives in the report; this gathers it into the one place a reader must
    look before treating an empty findings list as a clean bill of health. It states, in order:
    every plane a rung positively cleared (and on what evidence), every coverage note where proof
    did not reach, and the headline count of untested surface.
    """
    skipped_planes = [
        {
            "plane": d.plane.value if d.plane else None,
            "established": d.established,
            "evidence": d.provenance.detail,
            "rung": d.provenance.rung,
        }
        for d in report.applicability
        if not d.applies and d.established
    ]
    ran_under_doubt = [
        {
            "plane": d.plane.value if d.plane else None,
            "evidence": d.provenance.detail,
        }
        for d in report.applicability
        if d.applies and not d.established
    ]
    not_proved = [
        {"check": n.check.value if n.check else None, "detail": n.detail}
        for n in report.coverage
        if not n.proved
    ]
    return {
        "headline": _headline(skipped_planes, not_proved, report),
        "skipped_planes": skipped_planes,
        "ran_under_doubt": ran_under_doubt,
        "not_proved": not_proved,
        "reminder": (
            "An empty findings list is not a clean bill of health. It is the set of holes Tainted "
            "both looked for and could fire at. Everything above is surface it did not, or could "
            "not, prove."
        ),
    }


def _headline(skipped: list, not_proved: list, report: Report) -> str:
    proven = len(report.proven_findings)
    bits = [f"{proven} proven"]
    if skipped:
        bits.append(f"{len(skipped)} plane(s) cleared as absent")
    if not_proved:
        bits.append(f"{len(not_proved)} check(s) not fully proven")
    return "; ".join(bits) + "."
