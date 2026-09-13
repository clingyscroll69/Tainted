"""Pre-commit gate. Blocks a commit when a possible hole is severe enough.

Runs `analyze`: static, fast, no target. Exits non-zero when a possible hole is at or above the
configured severity. Wire it into `.pre-commit-hooks.yaml` or a plain git hook.
"""

from __future__ import annotations

import sys

import typer

from tainted import analyze as core_analyze
from tainted.models import Severity
from tainted.report import build_report
from tainted_cli.render import console, render_report

gate = typer.Typer(add_completion=False)


@gate.command()
def main(
    repo: str = typer.Argument(".", help="Repository path"),
    fail_on: str = typer.Option("high", help="Minimum severity that blocks the commit"),
):
    """Exits 1 if a possible hole is at or above `fail_on`."""
    threshold = Severity(fail_on.lower())
    result = core_analyze(repo)  # No LLM needed. Structural holes are enough to block the commit.
    render_report(build_report(result))
    blocking = [c for c in result.candidates if c.severity.rank >= threshold.rank]
    if blocking:
        console.print(
            f"[bold red]Commit blocked:[/bold red] found {len(blocking)} possible hole(s) "
            f"at or above {threshold.value}."
        )
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    gate()
