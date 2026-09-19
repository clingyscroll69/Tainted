"""`tainted watch`. Re-runs `analyze` each time a file a person edited changes."""

from __future__ import annotations

import threading
from pathlib import Path
from typing import Callable, Optional

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from tainted import analyze as core_analyze
from tainted.llm.gemini import get_default_client
from tainted.models import Check
from tainted.report import build_report
from tainted_cli.render import _e, console, render_report

_WATCH_EXTS = (".ts", ".tsx", ".js", ".jsx", ".py", ".sql", ".json")

# Directories whose contents are written by a build, a package manager or a tool — never by
# the person at the keyboard. Watching them means a dev server rebuilding, or `npm install`,
# or a branch switch, each spend a full re-analysis on code nobody changed. `.git` is here for
# the same reason: git's own writes are not edits.
_IGNORED_DIRS = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        "node_modules",
        ".next",
        ".nuxt",
        ".svelte-kit",
        ".turbo",
        ".parcel-cache",
        "dist",
        "build",
        "out",
        "target",
        "coverage",
        "reports",
        ".venv",
        "venv",
        "__pycache__",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".tox",
        ".mutmut-cache",
    }
)

# Checks that write to the repository they are measuring, and so cannot be watched: the write
# is itself a change, which triggers the next run. Named here rather than inside `watch_repo`
# so the CLI can refuse the flag before anything starts.
REFUSED_IN_WATCH = frozenset({Check.TEST_INTEGRITY})

_QUIET_PERIOD_S = 0.5  # how long a burst has to be over before a re-run starts
_POLL_S = 0.25  # how often the loop checks whether it should still be running


def refusal_reason(only: Optional[set[Check]]) -> Optional[str]:
    """Why this `--only` cannot be watched, or None if it can."""
    refused = sorted(c.value for c in (only or set()) & REFUSED_IN_WATCH)
    if not refused:
        return None
    return (
        f"{', '.join(refused)} cannot run under `watch`. The mutation campaign writes into "
        "the repository it is measuring — Stryker leaves reports/mutation/mutation.json, and "
        "both tools rewrite the source they mutate — so every run triggers the next one. Run "
        "`tainted analyze --only test_integrity` instead."
    )


def _is_source_change(path: str, repo: str) -> bool:
    """Whether this path is source a person edits, rather than something a tool emitted."""
    p = Path(path)
    if not p.name.endswith(_WATCH_EXTS):
        return False
    try:
        parts = p.relative_to(repo).parts
    except ValueError:
        # Outside the tree we were handed: judge the whole path rather than claim it is clean.
        parts = p.parts
    return not any(part in _IGNORED_DIRS for part in parts[:-1])


class _Rerun(FileSystemEventHandler):
    """Turns file events into exactly one pending re-run.

    The handler never analyses anything itself. Watchdog dispatches events on its own thread
    and `EventDispatcher.run` catches nothing but `queue.Empty`, so work done here is work
    that can end the observer; all this does is raise a flag the main loop reads.
    """

    def __init__(
        self,
        repo: str,
        only: Optional[set[Check]] = None,
        skip: Optional[set[Check]] = None,
        analyze: Optional[Callable] = None,
    ):
        self.repo = repo
        self.only = only
        self.skip = skip
        self._analyze = analyze or core_analyze
        self._dirty = threading.Event()

    def on_any_event(self, event) -> None:
        if getattr(event, "is_directory", False):
            return
        # Both ends of a rename: most editors save by writing a temp file and renaming it over
        # the original, so the source is a name nobody watches and only the destination says
        # which file actually changed.
        candidates = (str(event.src_path), str(getattr(event, "dest_path", "") or ""))
        if any(p and _is_source_change(p, self.repo) for p in candidates):
            self._dirty.set()

    def wait_for_change(self, timeout: float, quiet_period: float) -> bool:
        """Block until a watched file changed *and* the burst has settled.

        The debounce is trailing. The leading-edge one it replaces stamped the clock when a
        run started, so every event queued behind a run longer than the window — which is most
        runs — fired a run of its own, and one `git checkout` became a chain of them. Here a
        burst sets one flag, and the flag clears only once nothing new has arrived for
        `quiet_period`.
        """
        if not self._dirty.wait(timeout):
            return False
        while True:
            self._dirty.clear()
            if not self._dirty.wait(quiet_period):
                return True

    def run(self) -> None:
        console.clear()
        try:
            llm = get_default_client(reload=True)
            result = self._analyze(
                self.repo, llm=llm if llm.available else None, only=self.only, skip=self.skip
            )
            render_report(build_report(result))
        except Exception as exc:  # noqa: BLE001 - reported, because the watch outlives it
            # One transient failure — a 503 from the model, a half-written file caught
            # mid-save — is not a reason to stop watching. Say what happened and wait for the
            # next change, which is usually the edit that fixes it.
            console.print(f"[red]analyze failed: {_e(exc)}[/red]")
        console.print("[dim]Watching for changes. Press Ctrl-C to stop.[/dim]")


def _run_loop(
    handler: _Rerun,
    should_continue: Callable[[], bool],
    quiet_period: float = _QUIET_PERIOD_S,
    poll: float = _POLL_S,
) -> None:
    while should_continue():
        if handler.wait_for_change(poll, quiet_period):
            handler.run()


def watch_repo(
    repo: str,
    only: Optional[set[Check]] = None,
    skip: Optional[set[Check]] = None,
    quiet_period: float = _QUIET_PERIOD_S,
) -> None:
    reason = refusal_reason(only)
    if reason:
        raise ValueError(reason)

    handler = _Rerun(repo, only, skip)
    handler.run()  # Run once before watching starts.
    observer = Observer()
    observer.schedule(handler, repo, recursive=True)
    observer.start()
    try:
        _run_loop(handler, lambda: True, quiet_period=quiet_period)
    except KeyboardInterrupt:
        pass
    finally:
        observer.stop()
        observer.join()
