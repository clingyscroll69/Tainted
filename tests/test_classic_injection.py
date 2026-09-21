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


# --------------------------------------------------------------------------- #
# The f-string sink, on a cursor that is not literally named `cursor`
#
# The pattern was anchored to the receiver name, so it caught `cursor.execute(f"...")` and
# missed `cur.execute(f"...")` and `conn.cursor().execute(f"...")`. An f-string is how modern
# Python interpolates, which made this the most likely shape of the bug to go unreported.
# --------------------------------------------------------------------------- #
_FSTRING_SHAPES = """\
import sqlite3

def a(x):
    cur = sqlite3.connect("d").cursor()
    cur.execute(f"SELECT * FROM t WHERE id = '{x}'")

def b(y):
    sqlite3.connect("d").cursor().execute(f"SELECT * FROM t WHERE id = '{y}'")

def c(z):
    db.session.execute(f"SELECT * FROM t WHERE id = '{z}'")

def d(w):
    cur.execute("SELECT * FROM t WHERE id = '{}'".format(w))
"""


def test_an_f_string_query_is_found_whatever_the_cursor_is_called(tmp_path):
    (tmp_path / "app.py").write_text(_FSTRING_SHAPES)
    lines = {c.location.line for c in scan_classic_injection(str(tmp_path))}
    assert 5 in lines, "cur.execute(f...)"
    assert 8 in lines, "chained .cursor().execute(f...)"
    assert 11 in lines, "db.session.execute(f...)"
    assert 14 in lines, '.format() into execute()'


def test_an_f_string_with_nothing_interpolated_is_not_a_finding(tmp_path):
    """`f"SELECT 1"` pastes nothing in. Widening the pattern must not start reporting it."""
    (tmp_path / "app.py").write_text(
        'import sqlite3\n\ndef a():\n    cur.execute(f"SELECT 1 FROM t")\n'
    )
    assert scan_classic_injection(str(tmp_path)) == []
