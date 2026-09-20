"""Path exclusion: the caller's demo/fixture/specimen list on top of the built-in skips."""

from __future__ import annotations

import textwrap
from pathlib import Path

from tainted import analyze
from tainted.models import Check
from tainted.static.exclude import is_excluded, normalize_patterns


# --------------------------------------------------------------------------- #
# The matcher
# --------------------------------------------------------------------------- #
def test_bare_name_matches_that_segment_anywhere():
    assert is_excluded("tests/fixtures/handlers.py", ["fixtures"])
    assert is_excluded("a/b/demo/x.py", ["demo"])
    assert not is_excluded("src/handlers.py", ["fixtures"])


def test_directory_prefix_excludes_everything_beneath():
    assert is_excluded("tests/a/b.py", ["tests"])
    assert is_excluded("tests/a/b.py", ["tests/*"])
    assert not is_excluded("tooltests/a.py", ["tests"])


def test_glob_is_matched_against_the_path():
    assert is_excluded("surfaces/website/backend/demo.py", ["**/demo.py"])
    assert is_excluded("api/list.ts", ["*.ts"])
    assert not is_excluded("api/list.tsx", ["*.ts"])


def test_no_patterns_excludes_nothing():
    assert not is_excluded("anything/at/all.py", [])


def test_normalize_trims_and_drops_blanks():
    assert normalize_patterns([" tests/ ", "", "  ", "/demo/"]) == ["tests", "demo"]


# --------------------------------------------------------------------------- #
# End to end through analyze()
# --------------------------------------------------------------------------- #
def _write(root: Path, rel: str, text: str) -> None:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(textwrap.dedent(text))


def test_analyze_drops_candidates_in_excluded_dirs(tmp_path):
    # A real handler and a specimen fixture, both with the same injectable shape.
    _write(
        tmp_path,
        "src/handlers.py",
        """
        def unsafe_sql(cursor, uid):
            cursor.execute(f"select * from t where id = {uid}")
        """,
    )
    _write(
        tmp_path,
        "tests/fixtures/specimen.py",
        """
        def unsafe_sql(cursor, uid):
            cursor.execute(f"select * from t where id = {uid}")
        """,
    )

    full = analyze(str(tmp_path), only={Check.CLASSIC_INJECTION})
    files = {c.location.file for c in full.candidates}
    assert any("src/handlers.py" in f for f in files)
    assert any("fixtures/specimen.py" in f for f in files), "baseline: specimen is flagged"

    pruned = analyze(
        str(tmp_path), only={Check.CLASSIC_INJECTION}, exclude=["tests/fixtures"]
    )
    pruned_files = {c.location.file for c in pruned.candidates}
    assert any("src/handlers.py" in f for f in pruned_files), "real code still scanned"
    assert not any(
        "fixtures" in f for f in pruned_files
    ), "excluded specimen must not be reported"


def test_bare_name_exclude_prunes_a_demo_folder(tmp_path):
    _write(
        tmp_path,
        "demo/samples.js",
        'export const q = (db, col) => db.query("select * from items order by " + col);',
    )
    assert any(
        "demo" in c.location.file
        for c in analyze(str(tmp_path), only={Check.CLASSIC_INJECTION}).candidates
    )
    assert not any(
        "demo" in c.location.file
        for c in analyze(
            str(tmp_path), only={Check.CLASSIC_INJECTION}, exclude=["demo"]
        ).candidates
    )
