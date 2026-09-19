"""`tainted watch` — the loop has to survive a bad run, coalesce a burst of saves, and stay
out of the directories a build writes.

Every test here drives the real handler with an injected `analyze`, so what is exercised is
the loop's own behaviour rather than a stand-in for it.
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest
from typer.testing import CliRunner

from tainted.models import AnalysisResult, Check
from tainted_cli import watch
from tainted_cli.main import app

runner = CliRunner()
REPO = str(Path(__file__).resolve().parents[3] / "tests" / "fixtures" / "vulnerable_supabase")


class _Event:
    """The shape watchdog hands a handler. A rename also carries a destination."""

    def __init__(self, src: str, dest: str = "", is_directory: bool = False):
        self.src_path = src
        self.dest_path = dest
        self.is_directory = is_directory


def _empty(repo, **kwargs):
    return AnalysisResult(repo_path=str(repo))


def _handler(analyze, repo: str = "/repo"):
    return watch._Rerun(repo, None, None, analyze=analyze)


def _until(done, deadline_s: float = 0.5):
    """A `should_continue` that stops when `done()`, with a deadline so a loop that never
    settles fails the test instead of hanging it."""
    end = time.monotonic() + deadline_s
    return lambda: not done() and time.monotonic() < end


def test_a_run_that_raises_does_not_stop_the_watch(capsys):
    """In production `run` is called from watchdog's dispatch thread, which catches nothing:
    one Gemini 503 used to kill the observer while the CLI sat there looking alive."""
    calls = []

    def analyze(repo, **kwargs):
        calls.append(repo)
        if len(calls) == 1:
            raise RuntimeError("boom")
        return _empty(repo)

    handler = _handler(analyze)
    handler.run()
    assert len(calls) == 1
    assert "boom" in capsys.readouterr().out

    handler.on_any_event(_Event("/repo/app.py"))
    watch._run_loop(handler, _until(lambda: len(calls) >= 2), quiet_period=0.01, poll=0.02)
    assert len(calls) == 2


def test_changes_during_a_run_coalesce_into_one_rerun():
    """A branch switch or a dev-server rebuild writes many files while a run is in flight.
    That is one re-run, not one per file."""
    calls = []
    handler = None

    def analyze(repo, **kwargs):
        calls.append(repo)
        if len(calls) == 1:
            for i in range(5):
                handler.on_any_event(_Event(f"/repo/src/mod{i}.py"))
        return _empty(repo)

    handler = _handler(analyze)
    handler.run()
    watch._run_loop(handler, _until(lambda: len(calls) >= 3), quiet_period=0.01, poll=0.02)
    assert len(calls) == 2


@pytest.mark.parametrize(
    "path, triggers",
    [
        ("/repo/app/api/invoices/[id]/route.ts", True),
        ("/repo/src/models.py", True),
        ("/repo/supabase/migrations/0001.sql", True),
        ("/repo/package.json", True),
        ("/repo/README.md", False),
        ("/repo/node_modules/react/index.js", False),
        ("/repo/.next/static/chunks/main.js", False),
        ("/repo/dist/bundle.js", False),
        ("/repo/build/out.js", False),
        ("/repo/.git/hooks/thing.py", False),
        ("/repo/.venv/lib/python3.11/site-packages/x.py", False),
        ("/repo/reports/mutation/mutation.json", False),
        ("/repo/coverage/lcov-report/block.js", False),
    ],
)
def test_only_hand_written_source_triggers_a_rerun(path, triggers):
    handler = _handler(_empty)
    handler.on_any_event(_Event(path))
    assert handler.wait_for_change(0, 0) is triggers


def test_a_directory_event_is_not_a_change():
    handler = _handler(_empty)
    handler.on_any_event(_Event("/repo/src", is_directory=True))
    assert handler.wait_for_change(0, 0) is False


def test_an_atomic_save_lands_by_its_destination_path():
    """Editors save by writing a temp file and renaming it over the original. The event's
    source is the temp name; only its destination says a watched file changed."""
    handler = _handler(_empty)
    handler.on_any_event(_Event("/repo/src/.app.py.tmp", dest="/repo/src/app.py"))
    assert handler.wait_for_change(0, 0) is True


def test_watch_refuses_the_check_that_writes_to_the_repo():
    """`test_integrity` runs Stryker, which writes reports/mutation/mutation.json *inside*
    the repository — a watched file. Watching it is an unbounded loop."""
    with pytest.raises(ValueError, match="test_integrity"):
        watch.watch_repo(REPO, only={Check.TEST_INTEGRITY})


def test_cli_watch_refuses_only_test_integrity():
    result = runner.invoke(app, ["watch", REPO, "--only", "test_integrity"])
    assert result.exit_code == 2
    assert "test_integrity" in result.output


def test_a_real_watchdog_event_reaches_the_handler(tmp_path):
    """Everything above hands the handler a hand-made event. This one goes through watchdog
    itself, so the attributes those tests assume are the ones it actually sends."""
    from watchdog.observers import Observer

    (tmp_path / "node_modules").mkdir()
    handler = _handler(_empty, repo=str(tmp_path))
    observer = Observer()
    observer.schedule(handler, str(tmp_path), recursive=True)
    observer.start()
    try:
        (tmp_path / "node_modules" / "vendor.js").write_text("x = 1\n")
        assert handler.wait_for_change(0.6, 0.01) is False

        (tmp_path / "app.py").write_text("x = 1\n")
        assert handler.wait_for_change(2.0, 0.05) is True
    finally:
        observer.stop()
        observer.join()
