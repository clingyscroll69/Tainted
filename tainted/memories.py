"""Repo-local triage memories — accepted-risk decisions that quiet the ranker, with one hard rule.

A team re-scans the same repository, and the same handful of candidates it has already decided are
fine come back every time. A memory records that decision — "this route is intentionally public",
keyed to the finding's stable id — and feeds it back so the candidate sinks or is suppressed on the
next run.

The one rule is the whole point, and it is a rule no confidence-scoring tool can state: **a memory
may suppress a candidate or a REPORTED finding, and it may never touch a PROVEN one.** A memory is
a human opinion; a PROVEN finding is a fired exploit. Opinion does not get to override evidence, so
a suppression that lands on something that later turns out to be provable is itself surfaced rather
than silently honoured.

Memories live in `.tainted/memories.json` in the repo, so they travel with the code, review like
code, and never reach Tainted's own servers (there are none). The file is read defensively: a
malformed or absent file means "no memories", never a crash.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from tainted.models import Candidate, Finding, FindingStatus

MEMORIES_PATH = ".tainted/memories.json"

# Statuses a memory must never suppress. Identical set to the proof-establishing statuses used by
# the report and the priority table — evidence is evidence in all three places.
_PROVEN = frozenset(
    {FindingStatus.PROVEN, FindingStatus.FIXED, FindingStatus.BROKE_IT_SAFELY}
)


@dataclass(frozen=True)
class Memory:
    """One accepted-risk decision, keyed to a finding's stable id."""

    finding_id: str
    reason: str
    author: str = ""
    created: str = ""

    def as_dict(self) -> dict:
        return {
            "finding_id": self.finding_id,
            "reason": self.reason,
            "author": self.author,
            "created": self.created,
        }


@dataclass
class MemoryStore:
    memories: dict[str, Memory] = field(default_factory=dict)

    @classmethod
    def load(cls, repo_path: str) -> "MemoryStore":
        """Read `.tainted/memories.json`, tolerating absence and corruption as 'no memories'."""
        path = Path(repo_path) / MEMORIES_PATH
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return cls()
        entries = raw.get("memories", raw) if isinstance(raw, dict) else raw
        store = cls()
        if isinstance(entries, list):
            for e in entries:
                if isinstance(e, dict) and e.get("finding_id"):
                    store.memories[str(e["finding_id"])] = Memory(
                        finding_id=str(e["finding_id"]),
                        reason=str(e.get("reason", "")),
                        author=str(e.get("author", "")),
                        created=str(e.get("created", "")),
                    )
        return store

    def get(self, finding_id: str) -> Optional[Memory]:
        return self.memories.get(finding_id)


@dataclass(frozen=True)
class Suppression:
    """The result of applying a memory to a finding — and, crucially, whether it was refused."""

    finding_id: str
    reason: str
    honoured: bool  # False when the memory tried to suppress evidence
    conflict: str = ""  # why it was refused, when honoured is False

    def as_dict(self) -> dict:
        return {
            "finding_id": self.finding_id,
            "reason": self.reason,
            "honoured": self.honoured,
            "conflict": self.conflict,
        }


def suppressed_candidates(
    candidates: list[Candidate], store: MemoryStore
) -> tuple[list[Candidate], list[Suppression]]:
    """Split candidates into those kept and the memories applied.

    A candidate carries no proof yet, so any matching memory is honoured here — this is the
    normal, cheap path that quiets a static list before proof runs.
    """
    kept: list[Candidate] = []
    applied: list[Suppression] = []
    for c in candidates:
        mem = store.get(c.id)
        if mem is None:
            kept.append(c)
            continue
        applied.append(Suppression(finding_id=c.id, reason=mem.reason, honoured=True))
    return kept, applied


def reconcile_findings(
    findings: list[Finding], store: MemoryStore
) -> tuple[list[Finding], list[Suppression]]:
    """Apply memories to proven-through findings, refusing any that would hide evidence.

    Returns the findings a surface should still show, and the record of every memory applied —
    including the refusals, because a memory that tried and failed to suppress a now-PROVEN
    finding is exactly the thing a reader must see, not the thing to hide.
    """
    shown: list[Finding] = []
    applied: list[Suppression] = []
    for f in findings:
        mem = store.get(f.candidate.id)
        if mem is None:
            shown.append(f)
            continue
        if f.status in _PROVEN:
            # The refusal. The memory said "accepted risk"; the exploit fired anyway.
            applied.append(
                Suppression(
                    finding_id=f.candidate.id,
                    reason=mem.reason,
                    honoured=False,
                    conflict=(
                        f"A memory marked this accepted risk, but the attack was proven "
                        f"({f.status.value}). A memory cannot suppress a fired exploit, so this "
                        f"finding is shown despite the memory."
                    ),
                )
            )
            shown.append(f)
            continue
        applied.append(Suppression(finding_id=f.candidate.id, reason=mem.reason, honoured=True))
    return shown, applied
