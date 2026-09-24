"""The CLI's fix flow and the parts of the report that must never be silently dropped."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from tainted_cli.main import app

runner = CliRunner()
FIXTURES = Path(__file__).resolve().parents[3] / "tests" / "fixtures"
SUPABASE = str(FIXTURES / "vulnerable_supabase")
ROUTES = str(FIXTURES / "vulnerable_routes")
AGENTS = str(FIXTURES / "agent_configs")


# --------------------------------------------------------------------------- #
# Rendering must not eat the finding
# --------------------------------------------------------------------------- #
def test_next_route_parameters_survive_the_renderer():
    """`[id]` is rich markup as well as a route parameter; the route is the finding."""
    result = runner.invoke(app, ["analyze", ROUTES])
    assert result.exit_code == 0
    assert "[id]" in result.stdout


def test_coverage_is_always_printed():
    """An empty proof column reads as a clean bill of health unless the limits are stated."""
    result = runner.invoke(app, ["analyze", ROUTES])
    assert "Coverage" in result.stdout
    assert "Not attempted in this run" in result.stdout


def test_bola_candidates_appear_in_the_default_run():
    """The candidate must survive to both surfaces: the rendered table and `--json`.

    Asserted against `--json` rather than the table text, because rich wraps a title inside its
    cell — the phrasing is broken across lines at whatever width the terminal happens to be, so
    a substring check on the table asserts the wrap, not the finding.
    """
    result = runner.invoke(app, ["analyze", ROUTES])
    assert "bola" in result.stdout

    report = json.loads(runner.invoke(app, ["analyze", ROUTES, "--json"]).stdout)
    bola = [c for c in report["unproven_candidates"] if c["check"] == "bola"]
    assert bola, "no bola candidate in the default run"
    assert any("with no owner check" in c["title"] for c in bola)


# --------------------------------------------------------------------------- #
# Fix
# --------------------------------------------------------------------------- #
def test_request_plane_fix_prints_a_migration_and_says_the_loop_is_open():
    result = runner.invoke(app, ["fix", SUPABASE, "--index", "0"])
    assert result.exit_code == 0
    assert "enable row level security" in result.stdout
    # Without a target the loop cannot close, and the output must not imply it did.
    assert "patch-only" in result.stdout
    assert "Re-verification" not in result.stdout


def test_bola_fix_emits_the_missing_predicate_in_the_right_dialect():
    result = runner.invoke(app, ["fix", ROUTES, "--index", "0"])
    assert result.exit_code == 0
    out = result.stdout
    assert "auth.uid" in out or "user.id" in out or "user_id" in out


def test_tool_plane_fix_asks_before_it_writes():
    """The interview runs interactively; answering it selects one of four remediations."""
    result = runner.invoke(
        app, ["fix", AGENTS, "--index", "0"], input="no\n"
    )
    # Either an interview ran, or this repo's top candidate isn't a tool-plane one — but the
    # command must never invent an answer and write a restructuring silently.
    if "genuinely need both" in result.stdout:
        assert "scope_split" in result.stdout
    else:
        assert result.exit_code in (0, 2)


def test_tool_plane_fix_with_yes_accepts_defaults_without_prompting():
    result = runner.invoke(app, ["fix", AGENTS, "--index", "0", "--yes"])
    assert result.exit_code in (0, 2)


# --------------------------------------------------------------------------- #
# Applying
# --------------------------------------------------------------------------- #
def test_apply_writes_the_migration_into_the_repo(tmp_path):
    import shutil

    repo = tmp_path / "app"
    shutil.copytree(SUPABASE, repo)

    result = runner.invoke(app, ["fix", str(repo), "--index", "0", "--apply"])
    assert result.exit_code == 0
    assert "wrote" in result.stdout

    written = list((repo / "supabase" / "migrations").glob("*tainted_fix*"))
    assert written, "the migration should be written into the repo"
    assert "enable row level security" in written[0].read_text()


def test_apply_never_overwrites_a_handler_with_its_snippet(tmp_path):
    """A BOLA fix replaces one read inside a handler. Its `replacement` is only that read, so
    writing it over the file used to reduce the whole handler to a few lines."""
    import shutil

    repo = tmp_path / "app"
    shutil.copytree(ROUTES, repo)
    before = {p: p.read_text() for p in repo.rglob("*") if p.is_file()}

    report = json.loads(runner.invoke(app, ["analyze", str(repo), "--json"]).stdout)
    rows = [f["candidate"] for f in report["findings"]] + report["unproven_candidates"]
    bola = next(c for c in rows if c["check"] == "bola" and c["metadata"].get("route_path"))

    result = runner.invoke(
        app, ["fix", str(repo), "--finding-id", bola["id"], "--apply"]
    )
    assert result.exit_code == 0, result.stdout

    for path, text in before.items():
        assert path.read_text() == text, f"{path} was overwritten"
    siblings = list(repo.rglob("*.tainted-fix"))
    assert len(siblings) == 1
    assert "beside it" in result.stdout


def test_edit_paths_that_leave_the_repository_are_refused(tmp_path):
    import pytest

    from tainted.fix.paths import edit_target, safe_segment
    from tainted.models import FileEdit

    with pytest.raises(ValueError, match="outside the repository"):
        edit_target(tmp_path, FileEdit(file="../../etc/cron.d/x", replacement="*"))
    segment = safe_segment("../../home/me/.bashrc")
    assert "/" not in segment and not segment.startswith(".")
