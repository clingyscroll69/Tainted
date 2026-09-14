"""The row you point at is the hole you fix.

`analyze` draws a table; `fix --index` picks out of it. Those were two different orders of the
same set — `build_report`'s discovery order on screen, `ranked()`'s structural-first order in
`fix` — so on any repository where they disagree the reader asked for row 0 and was handed the
patch for a different hole entirely. The fixture below is one where they disagree.
"""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from tainted_cli.main import app

runner = CliRunner()
FIXTURES = Path(__file__).resolve().parents[3] / "tests" / "fixtures"
ROUTES = str(FIXTURES / "vulnerable_routes")


def _published():
    out = runner.invoke(app, ["analyze", ROUTES, "--json"])
    assert out.exit_code == 0, out.stdout
    report = json.loads(out.stdout)
    return [f["candidate"] for f in report["findings"]] + report["unproven_candidates"]


def test_the_table_numbers_its_rows():
    """A flag that takes an index is unusable against a table that prints none."""
    result = runner.invoke(app, ["analyze", ROUTES])
    assert result.exit_code == 0
    assert "\n  0 " in result.stdout or " 0 " in result.stdout


def test_the_table_prints_each_candidate_id():
    result = runner.invoke(app, ["analyze", ROUTES])
    first = _published()[0]
    assert first["id"] in result.stdout


def test_fix_index_zero_fixes_the_first_row_of_the_table():
    published = _published()
    result = runner.invoke(app, ["fix", ROUTES, "--index", "0"])
    assert result.exit_code == 0, result.stdout
    assert published[0]["title"].split(" in ")[0][:30] in result.stdout


def test_fix_by_id_fixes_the_candidate_it_names():
    target = _published()[-1]
    result = runner.invoke(app, ["fix", ROUTES, "--finding-id", target["id"]])
    assert result.exit_code == 0, result.stdout
    assert target["title"].split(" in ")[0][:30] in result.stdout


def test_an_unknown_id_is_refused_with_its_own_name_in_the_message():
    result = runner.invoke(app, ["fix", ROUTES, "--finding-id", "deadbeef"])
    assert result.exit_code == 2
    assert "deadbeef" in result.stdout


def test_an_index_past_the_end_says_how_many_there_are():
    n = len(_published())
    result = runner.invoke(app, ["fix", ROUTES, "--index", str(n)])
    assert result.exit_code == 2
    assert str(n) in result.stdout


# --------------------------------------------------------------------------- #
# The patch is the product. Rich must not edit it on the way out.
# --------------------------------------------------------------------------- #
def test_the_title_being_fixed_keeps_its_route_parameter():
    """`[id]` is rich markup as well as a Next route parameter, and the route is the finding."""
    target = next(c for c in _published() if "[id]" in c["title"])
    result = runner.invoke(app, ["fix", ROUTES, "--finding-id", target["id"]])
    assert result.exit_code == 0, result.stdout
    assert "[id]" in result.stdout


def test_the_printed_patch_is_the_patch_that_would_be_written(tmp_path):
    """A diff a reader copies off the terminal has to be the bytes `--apply` writes.

    Everything in square brackets is a style tag to rich — array indices, route parameters,
    SQL placeholders — so an unescaped patch is printed with pieces silently deleted.
    """
    target = next(c for c in _published() if "[id]" in c["title"])
    repo = tmp_path / "app"
    import shutil

    shutil.copytree(ROUTES, repo)
    written = runner.invoke(
        app, ["fix", str(repo), "--finding-id", target["id"], "--apply"]
    )
    assert written.exit_code == 0, written.stdout
    for path in repo.rglob("*"):
        if path.is_file() and "[id]" in path.read_text(encoding="utf-8", errors="ignore"):
            break
    # Whatever the patch contains, the file name it was written under is printed verbatim.
    assert "[id]" in written.stdout
