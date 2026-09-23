"""A ceiling on a prove run, with a graceful stop.

Agentic proving has no natural end — a repo can have more candidates than anyone wants to pay to
fire at. Unbounded cost is the first objection to running it, so a run can be capped by wall time
and by the number of candidates attempted, and the cap is honoured *between* candidates so a
stop never severs a probe mid-flight.

The stop is graceful in the one way that matters for this tool: it emits **everything proven so
far**, then says plainly how many candidates it did not reach. A run that quietly returned a
short list would be the exact false all-clear the whole engine exists to avoid — "no more
findings" and "I stopped looking" must never look alike.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Budget:
    """Limits for one prove run. `None` on either axis means no limit on that axis."""

    max_seconds: Optional[float] = None
    max_candidates: Optional[int] = None
    _started: Optional[float] = field(default=None, init=False, repr=False)
    _attempted: int = field(default=0, init=False, repr=False)
    _clock: "Optional[object]" = field(default=None, repr=False, init=False)

    def start(self, now: Optional[float] = None) -> "Budget":
        """Begin the clock. Idempotent-safe: calling twice keeps the first start."""
        if self._started is None:
            self._started = now if now is not None else time.monotonic()
        return self

    def note_attempt(self) -> None:
        self._attempted += 1

    @property
    def attempted(self) -> int:
        return self._attempted

    def elapsed(self, now: Optional[float] = None) -> float:
        if self._started is None:
            return 0.0
        current = now if now is not None else time.monotonic()
        return max(0.0, current - self._started)

    def exhausted(self, now: Optional[float] = None) -> Optional[str]:
        """Why the run should stop before the next candidate, or None to continue.

        Checked between candidates, never during one — a half-fired probe proves nothing and a
        budget that produced one would be worse than no budget.
        """
        if self.max_candidates is not None and self._attempted >= self.max_candidates:
            return (
                f"candidate cap reached ({self._attempted} of a {self.max_candidates} limit "
                f"attempted)"
            )
        if self.max_seconds is not None and self.elapsed(now) >= self.max_seconds:
            return (
                f"time cap reached ({self.elapsed(now):.0f}s of a {self.max_seconds:.0f}s limit)"
            )
        return None

    @property
    def unlimited(self) -> bool:
        return self.max_seconds is None and self.max_candidates is None


@dataclass
class BudgetOutcome:
    """What a capped run did, and — the load-bearing part — what it did not reach."""

    stopped_early: bool
    reason: str
    attempted: int
    skipped: int  # candidates the cap kept the run from reaching
    elapsed_seconds: float

    def note(self) -> str:
        """A line for a report, honest about the silence a cap creates."""
        if not self.stopped_early:
            return (
                f"Ran to completion: {self.attempted} candidate(s) attempted "
                f"in {self.elapsed_seconds:.0f}s, no budget cap hit."
            )
        return (
            f"Stopped early — {self.reason}. {self.attempted} candidate(s) attempted, "
            f"{self.skipped} not reached. The findings below are everything proven before the "
            f"cap; they are not the whole repository. Raise the budget to reach the rest."
        )

    def as_dict(self) -> dict:
        return {
            "stopped_early": self.stopped_early,
            "reason": self.reason,
            "attempted": self.attempted,
            "skipped": self.skipped,
            "elapsed_seconds": round(self.elapsed_seconds, 2),
            "note": self.note(),
        }


def parse_budget(max_minutes: Optional[float], max_candidates: Optional[int]) -> Optional[Budget]:
    """Build a Budget from surface-supplied limits, or None when neither was given.

    Minutes rather than seconds at the surface, because that is the unit a person reaches for; a
    zero or negative value is treated as no limit rather than an instant stop, since "0 minutes"
    from a default-filled field should not silently mean "prove nothing".
    """
    seconds = max_minutes * 60.0 if max_minutes and max_minutes > 0 else None
    cands = max_candidates if max_candidates and max_candidates > 0 else None
    if seconds is None and cands is None:
        return None
    return Budget(max_seconds=seconds, max_candidates=cands)
