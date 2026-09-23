"""Standard identifiers for each check — in two tiers, which is the whole point.

Every scanner tags findings to OWASP and MITRE. Tainted can do something none of them can:
say whether the tag was *earned by firing an attack* or *inferred from a graph*. A compliance
export that flattens those together is the same silence the coverage ledger exists to break,
moved into the row a GRC reader actually pastes into a spreadsheet.

So `ids_for` takes the finding's status as well as its check, and returns the mapping with a
`tier` of PROVEN or STATIC. `TEST_INTEGRITY` deliberately maps to no vulnerability identifier at
all: a surviving mutant is a measurement, not a weakness, and inventing a CWE for it would be the
kind of overclaim the rest of the engine refuses.

**These mappings are maintained by hand.** They are a best-effort reading of the published
catalogues, not a generated artifact, and the catalogue versions they were read against are
recorded in `CATALOGUES` so a stale mapping is visible rather than assumed current.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional

from tainted.models import Check, Finding, FindingStatus

# Which revision of each catalogue the table below was written against. A reader who needs to
# know whether a mapping is current needs this more than they need the mapping.
CATALOGUES = {
    "owasp-asi": "OWASP Top 10 for Agentic Applications, 2025-12",
    "owasp-api": "OWASP API Security Top 10, 2023",
    "owasp-web": "OWASP Top 10, 2021",
    "mitre-atlas": "MITRE ATLAS (agentic techniques, 2026 additions)",
    "cwe": "CWE 4.x",
}


class Tier(str, Enum):
    """How the identifier was earned.

    PROVEN means an attack ran against the target and the hole was real. STATIC means it was
    argued from the code. The same catalogue id can arrive either way and they are not the same
    claim, so the tier travels with it.
    """

    PROVEN = "proven"
    STATIC = "static"


# Statuses that mean an attack actually ran and the hole was real. Kept deliberately identical to
# `report.model._PROOF_ESTABLISHING` — if these two ever disagree, the report and the compliance
# export would disagree about the same finding, which is worse than either being wrong alone.
_PROOF_ESTABLISHING = frozenset(
    {FindingStatus.PROVEN, FindingStatus.FIXED, FindingStatus.BROKE_IT_SAFELY}
)


@dataclass(frozen=True)
class StandardIds:
    """Every catalogue identifier for one finding, plus how far it was proven."""

    check: Check
    tier: Tier
    cwe: tuple[str, ...] = ()
    owasp_web: tuple[str, ...] = ()
    owasp_api: tuple[str, ...] = ()
    owasp_asi: tuple[str, ...] = ()
    mitre_atlas: tuple[str, ...] = ()
    note: str = ""

    @property
    def all_ids(self) -> tuple[str, ...]:
        return self.cwe + self.owasp_web + self.owasp_api + self.owasp_asi + self.mitre_atlas

    def tagged(self) -> list[str]:
        """Each identifier with its tier attached, e.g. `ASI02 (proven)`.

        This is the form a report or a CSV export should print. The bare id is available via
        `all_ids` for a consumer that has its own column for the tier.
        """
        return [f"{i} ({self.tier.value})" for i in self.all_ids]

    def as_dict(self) -> dict:
        return {
            "check": self.check.value,
            "tier": self.tier.value,
            "cwe": list(self.cwe),
            "owasp_web": list(self.owasp_web),
            "owasp_api": list(self.owasp_api),
            "owasp_asi": list(self.owasp_asi),
            "mitre_atlas": list(self.mitre_atlas),
            "note": self.note,
            "catalogues": dict(CATALOGUES),
        }


# --------------------------------------------------------------------------- #
# The table
# --------------------------------------------------------------------------- #
_BASE: dict[Check, dict] = {
    Check.BOLA: {
        "cwe": ("CWE-639", "CWE-285"),
        "owasp_web": ("A01:2021",),
        "owasp_api": ("API1:2023",),
    },
    Check.RLS: {
        # Row-level security is object-level authorization enforced by the database rather than
        # the handler. Same weakness, different enforcement point, so the same API1 entry applies
        # and CWE-1220 carries the "the boundary exists but is too coarse" case.
        "cwe": ("CWE-639", "CWE-1220"),
        "owasp_web": ("A01:2021",),
        "owasp_api": ("API1:2023",),
    },
    Check.CLASSIC_INJECTION: {
        "cwe": ("CWE-89",),  # refined per-kind below
        "owasp_web": ("A03:2021",),
        "owasp_api": ("API8:2023",),
    },
    Check.AGENT_INJECTION: {
        "cwe": ("CWE-77",),
        "owasp_asi": ("ASI01", "ASI02"),
        "mitre_atlas": ("AML.T0051.001",),
    },
    Check.TEST_INTEGRITY: {
        # Deliberately empty. A surviving mutant is a measurement of the test suite, not a
        # weakness in the application, and there is no honest catalogue entry for it.
        "note": (
            "No vulnerability identifier applies. A surviving mutant measures the test suite, "
            "not a weakness in the application. Tainted does not invent an id to fill a column."
        ),
    },
}

# Classic injection splits by kind, because the CWE does. Command injection under a SQL id would
# be wrong in the one field a downstream tool routes on.
_INJECTION_BY_KIND: dict[str, tuple[str, ...]] = {
    "sql": ("CWE-89",),
    "command": ("CWE-78",),
    "template": ("CWE-1336", "CWE-95"),
}

# The sink severity axis the trifecta's third leg feeds (see `tainted.trifecta`): a tool-plane
# scope that can also send data outward earns the exfiltration technique id as well.
_EXFIL_ATLAS = "AML.T0025"


def tier_for(status: FindingStatus) -> Tier:
    """PROVEN only when an attack ran and the hole was real; STATIC otherwise."""
    return Tier.PROVEN if status in _PROOF_ESTABLISHING else Tier.STATIC


def ids_for_check(
    check: Check,
    status: FindingStatus = FindingStatus.CANDIDATE,
    kind: Optional[str] = None,
    can_exfiltrate: bool = False,
) -> StandardIds:
    """Catalogue identifiers for one check, tiered by how far proof reached.

    `kind` refines classic injection (sql / command / template). `can_exfiltrate` adds the
    exfiltration technique to a tool-plane finding whose scope also holds an egress sink — the
    third leg of the lethal trifecta, computed in `tainted.trifecta`.
    """
    base = dict(_BASE.get(check, {}))
    if check is Check.CLASSIC_INJECTION and kind in _INJECTION_BY_KIND:
        base["cwe"] = _INJECTION_BY_KIND[kind]
    atlas = tuple(base.get("mitre_atlas", ()))
    if can_exfiltrate and check is Check.AGENT_INJECTION:
        atlas = atlas + (_EXFIL_ATLAS,)
    return StandardIds(
        check=check,
        tier=tier_for(status),
        cwe=tuple(base.get("cwe", ())),
        owasp_web=tuple(base.get("owasp_web", ())),
        owasp_api=tuple(base.get("owasp_api", ())),
        owasp_asi=tuple(base.get("owasp_asi", ())),
        mitre_atlas=atlas,
        note=str(base.get("note", "")),
    )


def ids_for(finding: Finding) -> StandardIds:
    """`ids_for_check`, reading the kind and the exfiltration flag off the finding itself."""
    return ids_for_check(
        finding.check,
        finding.status,
        kind=finding.candidate.metadata.get("kind"),
        can_exfiltrate=bool(finding.candidate.metadata.get("can_exfiltrate")),
    )
