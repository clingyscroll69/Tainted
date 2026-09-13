"""Renders reports and findings to the terminal, using rich."""

from __future__ import annotations

from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table

from tainted.models import Finding, Severity
from tainted.report import Report

console = Console()


def _e(text: object) -> str:
    """Escape rich markup in anything derived from the target's own source.

    Not cosmetic: Next.js route parameters are written `[id]`, which rich reads as a style tag
    and silently deletes. A report that prints `/api/invoices/` for a route actually served at
    `/api/invoices/[id]` has lost the very thing the finding is about.
    """
    return escape(str(text))

_SEV_STYLE = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}


def render_report(report: Report) -> None:
    s = report.summary
    console.print(
        Panel.fit(
            f"[bold]{_e(report.repo_path)}[/bold]\n"
            f"candidates: {s.total_candidates}   "
            f"proven: [red]{s.proven}[/red]   reported: {s.reported}   "
            f"fixed: [green]{s.fixed}[/green]   not-reproduced: {s.not_reproduced}",
            title="Tainted",
        )
    )

    # Show why each plane ran or was skipped.
    for d in report.applicability:
        plane = d.plane.value if d.plane else "?"
        state = "skipped (absent)" if not d.applies else "runs"
        established = "established" if d.established else "under doubt"
        console.print(
            f"  plane [bold]{_e(plane)}[/bold]: {state} — {established} "
            f"[dim](rung {d.provenance.rung}: {_e(d.provenance.detail)})[/dim]"
        )

    candidates = report.unproven_candidates or [f.candidate for f in report.findings]
    if not candidates and not report.findings:
        console.print("\n[green]No candidates found.[/green]")
        return

    table = Table(title="\nFindings", show_lines=False, expand=True)
    table.add_column("Sev", no_wrap=True)
    table.add_column("Check", no_wrap=True)
    table.add_column("Title")
    table.add_column("Location", no_wrap=True)

    items = report.findings if report.findings else candidates
    for item in items:
        cand = getattr(item, "candidate", item)
        sev = cand.severity
        table.add_row(
            f"[{_SEV_STYLE[sev]}]{sev.value.upper()}[/]",
            _e(cand.check.value),
            _e(cand.title),
            _e(cand.location),
        )
    console.print(table)

    for f in report.proven_findings:
        _render_proof(f)

    _render_mutation(report)
    _render_coverage(report)


def _render_mutation(report: Report) -> None:
    """Shows the test-integrity score as a plain number."""
    m = report.mutation
    if m is None:
        return
    if not m.available:
        console.print(f"\n[dim]Test integrity: not measured. {_e(m.note)}[/dim]")
        return
    pct = f"{m.score:.0%}" if m.score is not None else "n/a"
    style = "red" if (m.score or 1) < 0.6 else "yellow" if (m.score or 1) < 0.8 else "green"
    console.print(
        f"\n[bold]Test integrity[/bold] ({m.tool}): [{style}]{pct} of mutants killed[/{style}]. "
        f"{m.survived} of {m.total} changed lines have no test that would catch a bug there."
    )


def _render_coverage(report: Report) -> None:
    """Shows what was proven and what was not. Always printed, so a gap does not look clean."""
    if not report.coverage:
        return
    console.print("\n[bold]Coverage[/bold] [dim](what was proven, and what was not)[/dim]")
    for note in report.coverage:
        mark = "[green]proven[/green]" if note.proved else "[yellow]reported[/yellow]"
        check = note.check.value if note.check else "—"
        console.print(f"  {mark} [bold]{_e(check)}[/bold]: [dim]{_e(note.detail)}[/dim]")


def render_reverification(fix_result) -> None:
    """Shows both assertions side by side. 'fixed' and 'broke it safely' must look different."""
    console.print("\n[bold]Re-verification[/bold]")
    for a in fix_result.assertions:
        mark = "[green]PASS[/green]" if a.passed else "[red]FAIL[/red]"
        console.print(f"  {mark} {_e(a.name)}: [dim]{_e(a.detail)}[/dim]")

    status = fix_result.resulting_status.value
    if status == "fixed":
        console.print("\n[bold green]FIXED[/bold green]. The attack fails now. The owner still has access.")
    elif status == "broke_it_safely":
        console.print(
            "\n[bold yellow]BROKE IT SAFELY[/bold yellow]. The attack fails. The real owner "
            "lost access too."
        )
    else:
        console.print(f"\n[bold red]NOT FIXED[/bold red]: {status}.")


def _render_proof(f: Finding) -> None:
    p = f.proof
    if p is None:
        return
    ex = p.exploit
    lines = [f"[bold red]PROVEN[/bold red] {_e(f.candidate.title)}"]
    if ex and ex.url:
        lines.append(f"  {_e(ex.method)} {_e(ex.url)}")
        for k, v in ex.headers.items():
            lines.append(f"  {_e(k)}: {_e(v)}")
    if ex and ex.payload:
        lines.append(f"  payload: {_e(ex.payload)}")
    lines.append(f"  → {_e(p.notes)}")
    if p.response_body:
        body = p.response_body[:300]
        lines.append(f"  response: {_e(body)}")
    console.print(Panel("\n".join(lines), border_style="red"))


# --------------------------------------------------------------------------- #
# Tutorial
# --------------------------------------------------------------------------- #
def render_tutorial_index(lessons: list[dict]) -> None:
    """List the topics. Shown by `tainted tutorial` with no argument."""
    console.print(
        Panel.fit(
            "Short walkthroughs of the local loop. Each one ends with something real on "
            "screen.\nRun [bold]tainted tutorial <topic>[/bold] to read one.",
            title="Tainted tutorial",
        )
    )
    table = Table(show_header=True, header_style="bold", box=None, pad_edge=False)
    table.add_column("topic", style="bold cyan", no_wrap=True)
    table.add_column("title")
    table.add_column("what you get", style="dim")
    for lesson in lessons:
        table.add_row(
            _e(lesson["topic"]), _e(lesson["title"]), _e(lesson.get("summary", ""))
        )
    console.print(table)


def render_tutorial(lesson: dict) -> None:
    """Print one lesson: heading, body, the command to run, and what to expect back."""
    console.print(
        Panel.fit(
            f"[bold]{_e(lesson['title'])}[/bold]\n{_e(lesson.get('summary', ''))}",
            title=f"tutorial: {_e(lesson['topic'])}",
        )
    )
    for i, step in enumerate(lesson.get("steps", []), start=1):
        console.print(f"\n[bold cyan]{i}.[/bold cyan] [bold]{_e(step['heading'])}[/bold]")
        console.print(f"   {_e(step['body'])}")
        command = step.get("command")
        if command:
            for n, line in enumerate(str(command).splitlines()):
                lead = "[green]$[/green]" if n == 0 else " "
                console.print(f"   {lead} [bold]{_e(line)}[/bold]")
        expect = step.get("expect")
        if expect:
            console.print(f"   [dim]→ {_e(expect)}[/dim]")
    nxt = lesson.get("next")
    if nxt:
        console.print(f"\n[dim]Next: {_e(nxt)}[/dim]")
