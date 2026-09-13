"""`tainted watch`. Re-runs `analyze` each time a file changes."""

from __future__ import annotations

import time
from typing import Optional

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from tainted import analyze as core_analyze
from tainted.llm.gemini import get_default_client
from tainted.models import Check
from tainted.report import build_report
from tainted_cli.render import console, render_report

_WATCH_EXTS = (".ts", ".tsx", ".js", ".jsx", ".py", ".sql", ".json")


class _Rerun(FileSystemEventHandler):
    def __init__(self, repo: str, only, skip):
        self.repo = repo
        self.only = only
        self.skip = skip
        self._last = 0.0

    def on_any_event(self, event):
        if event.is_directory or not str(event.src_path).endswith(_WATCH_EXTS):
            return
        now = time.time()
        if now - self._last < 0.5:  # Ignore bursts of saves within half a second.
            return
        self._last = now
        self.run()

    def run(self):
        console.clear()
        llm = get_default_client(reload=True)
        result = core_analyze(
            self.repo, llm=llm if llm.available else None, only=self.only, skip=self.skip
        )
        render_report(build_report(result))
        console.print("[dim]Watching for changes. Press Ctrl-C to stop.[/dim]")


def watch_repo(
    repo: str, only: Optional[set[Check]] = None, skip: Optional[set[Check]] = None
) -> None:
    handler = _Rerun(repo, only, skip)
    handler.run()  # Run once before watching starts.
    observer = Observer()
    observer.schedule(handler, repo, recursive=True)
    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
