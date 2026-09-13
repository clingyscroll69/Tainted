"""Classic-injection static detector and the danger-split proof model."""

from __future__ import annotations

from pathlib import Path

from tainted.checks.classic_injection import scan_classic_injection
from tainted.models import Check, Severity

FIX = str(Path(__file__).parent / "fixtures" / "classic_injection")


def test_flags_unsafe_sinks_across_languages():
    cands = scan_classic_injection(FIX)
    kinds = [c.metadata["kind"] for c in cands]
    assert "sql" in kinds
    assert "command" in kinds
    assert "template" in kinds
    assert all(c.check == Check.CLASSIC_INJECTION for c in cands)


def test_parameterized_queries_not_flagged():
    cands = scan_classic_injection(FIX)
    snippets = " ".join(c.location.snippet for c in cands)
    # The safe parameterized queries ($1 / %s with a params tuple) must not appear.
    assert "where id = $1" not in snippets
    assert "where id = %s" not in snippets


def test_command_and_template_are_demonstrated_not_executed():
    cands = scan_classic_injection(FIX)
    for c in cands:
        exploit = c.metadata["demonstrated_exploit"]
        assert exploit["executed"] is False  # nothing is executed in the static pass
        if c.metadata["kind"] in ("command", "template"):
            assert c.metadata["live_provable"] is False
            assert "NOT executed" in exploit["description"]
        if c.metadata["kind"] == "sql":
            assert c.metadata["live_provable"] is True


def test_ranked_toward_dangerous_sinks_first():
    cands = scan_classic_injection(FIX)
    # Highest severity (critical command/eval) ranks before lower.
    assert cands[0].severity.rank >= cands[-1].severity.rank
    assert any(c.severity == Severity.CRITICAL for c in cands)
