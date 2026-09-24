"""SARIF 2.1.0 emission, with the two things that make it Tainted's rather than anyone's.

SARIF is the interchange format GitHub code scanning, GitLab and DefectDojo all ingest, so
emitting it is what lets Tainted's findings show up where a team already looks. Two Tainted-
specific things ride along in the standard's own extension points:

  * **proof strength**, per result, in `properties.tainted.proof` and mirrored onto
    `result.level` — a proven finding is an `error`, a merely-reported one a `warning`, a
    fired-and-held one a `note`. A consumer that understands nothing Tainted-specific still sees
    the proven ones ranked above the rest.
  * **the silence ledger**, per run, in `run.properties.tainted.notTested` — the SARIF spec has
    an open proposal (issue #795) for a `notPerformed` assessment outcome; until that lands this
    is the honest place to record what was not tested, rather than letting an empty `results`
    array read as full coverage.

Everything here is plain dict/JSON; no SARIF library, because the shape is small and pinning it
by hand keeps the proof-strength mapping visible.
"""

from __future__ import annotations

import json
from typing import Optional

import tainted
from tainted.models import Finding, FindingStatus
from tainted.priority import priority_of
from tainted.report.enrich import silence_ledger
from tainted.report.model import Report
from tainted.standards import ids_for

# proof strength -> SARIF level. The three proof-establishing statuses are errors; reported is a
# warning; a fired-and-held attack is a note (real information, not an alarm); a candidate that
# reached no outcome is a note too.
_LEVEL: dict[FindingStatus, str] = {
    FindingStatus.PROVEN: "error",
    FindingStatus.FIXED: "note",  # closed; kept for the record, not for action
    FindingStatus.BROKE_IT_SAFELY: "warning",
    FindingStatus.REPORTED: "warning",
    FindingStatus.NOT_REPRODUCED: "note",
    FindingStatus.CANDIDATE: "warning",
}


def _rule_id(finding: Finding) -> str:
    return f"tainted/{finding.check.value}"


def _region(finding: Finding) -> dict:
    loc = finding.candidate.location
    region: dict = {}
    if loc.line:
        region["startLine"] = loc.line
    if loc.end_line:
        region["endLine"] = loc.end_line
    if loc.snippet:
        region["snippet"] = {"text": loc.snippet}
    return region


def _result(finding: Finding) -> dict:
    ids = ids_for(finding)
    p = priority_of(finding)
    loc = finding.candidate.location
    physical: dict = {"artifactLocation": {"uri": loc.file}}
    region = _region(finding)
    if region:
        physical["region"] = region
    proof = finding.proof
    return {
        "ruleId": _rule_id(finding),
        "level": _LEVEL.get(finding.status, "warning"),
        "message": {"text": finding.candidate.title},
        "locations": [{"physicalLocation": physical}],
        "partialFingerprints": {"taintedFindingId": finding.candidate.id},
        "properties": {
            "tainted": {
                "proof": finding.status.value,
                "tier": ids.tier.value,
                "priority": p.score,
                "priorityExplanation": p.explanation,
                "standardIds": ids.tagged(),
                "proofNotes": proof.notes if proof else "",
            }
        },
    }


def _rules(report: Report) -> list[dict]:
    seen: dict[str, dict] = {}
    for f in report.findings:
        rid = _rule_id(f)
        if rid not in seen:
            seen[rid] = {
                "id": rid,
                "name": f.check.value,
                "shortDescription": {"text": f"Tainted {f.check.value} check"},
            }
    return list(seen.values())


def to_sarif(report: Report) -> dict:
    """The report as a SARIF 2.1.0 log, proof strength and silence ledger included."""
    results = [_result(f) for f in report.findings]
    run = {
        "tool": {
            "driver": {
                "name": "Tainted",
                "informationUri": "https://github.com/clingyscroll69/tainted",
                "version": tainted.__version__,
                "rules": _rules(report),
            }
        },
        "results": results,
        "properties": {
            "tainted": {
                # The silence ledger, so an empty results array is never mistaken for coverage.
                "notTested": silence_ledger(report),
                "proofStrengthLegend": {
                    "error": "proven — an attack ran and the hole was real",
                    "warning": "reported — argued from the code, not fired",
                    "note": "fired and held, fixed, or an untried candidate",
                },
            }
        },
    }
    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [run],
    }


def to_sarif_json(report: Report, indent: Optional[int] = 2) -> str:
    return json.dumps(to_sarif(report), indent=indent)
