"""The `tainted` command. A Typer wrapper over the core engine."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

import typer

from tainted import analyze as core_analyze
from tainted import fix as core_fix
from tainted import prove as core_prove
from tainted.dynamic.replay import SupabaseReplay
from tainted.dynamic.target import Account, ProveSetup, SeedRecord, Target  # noqa: F401
from tainted.llm.gemini import get_default_client
from tainted.models import Check, FindingStatus, Severity
from tainted.report import build_report
from tainted_cli.render import console, render_report, render_reverification

app = typer.Typer(
    add_completion=False,
    help="Tainted finds where a stranger's data reaches somewhere dangerous. It proves the hole is real, then fixes it.",
)


def _parse_checks(value: Optional[str]) -> Optional[set[Check]]:
    if not value:
        return None
    out: set[Check] = set()
    for token in value.split(","):
        token = token.strip().lower()
        try:
            out.add(Check(token))
        except ValueError:
            raise typer.BadParameter(
                f"Unknown check '{token}'. Choose from: {', '.join(c.value for c in Check)}"
            )
    return out


def _llm_or_none():
    llm = get_default_client(reload=True)
    return llm if llm.available else None


@app.command()
def analyze(
    repo: Path = typer.Argument(..., exists=True, file_okay=False, help="Path to the repository to scan"),
    only: Optional[str] = typer.Option(None, help="Run only these checks (comma-separated)"),
    skip: Optional[str] = typer.Option(None, help="Skip these checks (comma-separated)"),
    url: Optional[str] = typer.Option(
        None,
        help=(
            "Base URL of the running app. When the code alone cannot tell if a route needs "
            "login, Tainted sends one request without logging in to check."
        ),
    ),
    json_out: bool = typer.Option(False, "--json", help="Print the report as JSON"),
):
    """Scan the repo without running anything. Lists possible holes, ranked by how bad they are."""
    result = core_analyze(
        str(repo),
        llm=_llm_or_none(),
        only=_parse_checks(only),
        skip=_parse_checks(skip),
        target=Target(url=url) if url else None,
    )
    report = build_report(result)
    if json_out:
        typer.echo(report.model_dump_json(indent=2))
    else:
        render_report(report)


@app.command()
def prove(
    repo: Path = typer.Argument(..., exists=True, file_okay=False),
    url: str = typer.Option(..., help="Base URL of the running app or Supabase project"),
    login_a: str = typer.Option(..., "--login-a", help="Account A, as email:password"),
    login_b: str = typer.Option(..., "--login-b", help="Account B, as email:password"),
    seed: Optional[str] = typer.Option(None, help="Seed record, as table:id"),
    anon_key: Optional[str] = typer.Option(None, help="Supabase anon key"),
    ownership_token: Optional[str] = typer.Option(
        None, help="Proves you own the target when it isn't localhost"
    ),
    autodiscover: bool = typer.Option(
        False,
        help=(
            "When you don't give --seed, Tainted uses Playwright to walk the app as account A "
            "and find one. It clears a form field itself when it can; otherwise the field "
            "stays as is."
        ),
    ),
):
    """Run real attacks against the running app. Off localhost, you must prove you own the target first."""
    llm = _llm_or_none()
    setup = _build_setup(url, login_a, login_b, seed, anon_key)
    result = core_analyze(str(repo), llm=llm, target=setup.target)

    verified = setup.target.is_local
    if not verified and ownership_token:
        from tainted.ownership import verify

        verified = bool(verify(setup.target, expected_token=ownership_token))
    try:
        findings = core_prove(
            result,
            setup,
            ownership_verified=verified,
            llm=llm,
            autodiscover=autodiscover,
        )
    except PermissionError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=2)

    render_report(build_report(result, findings))
    if any(
        f.status == FindingStatus.PROVEN and f.severity.rank >= Severity.HIGH.rank
        for f in findings
    ):
        raise typer.Exit(code=1)


@app.command()
def fix(
    repo: Path = typer.Argument(..., exists=True, file_okay=False),
    index: int = typer.Option(0, help="Index of the possible hole to fix, in the order `analyze` lists them"),
    apply: bool = typer.Option(False, help="Write the fix to disk instead of just printing the diff"),
    url: Optional[str] = typer.Option(
        None,
        help=(
            "Base URL of the running app. If you give this, Tainted re-runs the attack after "
            "the fix to check it now fails, and checks real users still have access."
        ),
    ),
    login_a: Optional[str] = typer.Option(None, "--login-a", help="Account A, as email:password"),
    login_b: Optional[str] = typer.Option(None, "--login-b", help="Account B, as email:password"),
    seed: Optional[str] = typer.Option(None, help="Seed record, as table:id"),
    anon_key: Optional[str] = typer.Option(None, help="Supabase anon key"),
    yes: bool = typer.Option(
        False, "--yes", help="Skip the questions and accept the defaults"
    ),
):
    """Write the fix for a finding. If you give a target, re-check that the hole is closed."""
    from tainted.models import Finding

    llm = _llm_or_none()
    result = core_analyze(str(repo), llm=llm)
    candidates = result.ranked()
    if index >= len(candidates):
        console.print(f"[red]No possible hole at index {index}. Found {len(candidates)}.[/red]")
        raise typer.Exit(code=2)

    candidate = candidates[index]
    finding = Finding(candidate=candidate)
    console.print(f"[bold]Fixing:[/bold] {candidate.title}\n")

    # The tool plane fix can't be decided from code alone. Ask the user first.
    answers = None
    if candidate.check is Check.AGENT_INJECTION:
        answers = _run_interview(candidate, accept_defaults=yes)

    setup = None
    if url and login_a and login_b:
        setup = _build_setup(url, login_a, login_b, seed, anon_key)

    try:
        result_fix = core_fix(
            finding,
            setup=setup,
            replay_after=SupabaseReplay(setup.target) if setup else None,
            answers=answers,
            llm=llm,
            repo_path=str(repo) if candidate.check is Check.AGENT_INJECTION else None,
        )
    except (ValueError, NotImplementedError) as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=2)

    for edit in result_fix.edits:
        console.print(f"[bold]--- {edit.file}[/bold]\n{edit.replacement}")
    console.print(f"[dim]{result_fix.notes}[/dim]")

    if apply:
        for edit in result_fix.edits:
            path = repo / edit.file
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(edit.replacement, encoding="utf-8")
            console.print(f"[green]wrote {path}[/green]")

    if result_fix.assertions:
        render_reverification(result_fix)
        if not result_fix.all_assertions_passed:
            raise typer.Exit(code=1)


def _run_interview(candidate, accept_defaults: bool = False):
    """Ask the questions the code cannot answer on its own."""
    from tainted.fix import InterviewAnswer, resolve_tool_plane_fix, tool_plane_interview

    console.print(
        "[dim]This fix depends on facts only you know. Answer a few questions before "
        "Tainted writes it.[/dim]\n"
    )
    answers = []
    for q in tool_plane_interview(candidate):
        if accept_defaults:
            choice = q.options[0]
        else:
            choice = typer.prompt(
                f"{q.question} [{'/'.join(q.options)}]", default=q.options[0]
            )
            while choice not in q.options:
                choice = typer.prompt(f"Choose one of {q.options}.", default=q.options[0])
        answers.append(InterviewAnswer(key=q.key, choice=choice))

    console.print(
        f"\n[bold]Remediation:[/bold] {resolve_tool_plane_fix(answers).value}\n"
    )
    return answers


@app.command()
def watch(
    repo: Path = typer.Argument(..., exists=True, file_okay=False),
    only: Optional[str] = typer.Option(None),
    skip: Optional[str] = typer.Option(None),
):
    """Re-run analyze each time a watched file changes."""
    from tainted_cli.watch import watch_repo

    watch_repo(str(repo), only=_parse_checks(only), skip=_parse_checks(skip))


@app.command()
def tutorial(
    topic: Optional[str] = typer.Argument(
        None, help="Which walkthrough to read. Omit to list them."
    ),
):
    """Walk through the local loop, one short lesson at a time."""
    from tainted_cli.render import render_tutorial, render_tutorial_index
    from tainted_cli.tutorial import LESSONS

    if topic is None:
        render_tutorial_index(LESSONS)
        return

    wanted = topic.strip().lower()
    for lesson in LESSONS:
        if lesson["topic"] == wanted:
            render_tutorial(lesson)
            return
    raise typer.BadParameter(
        f"No tutorial topic '{topic}'. Choose from: "
        + ", ".join(lesson["topic"] for lesson in LESSONS)
    )


@app.command()
def version():
    """Print the Tainted engine's version."""
    import tainted

    typer.echo(f"tainted {tainted.__version__}")


# --------------------------------------------------------------------------- #
def _build_setup(
    url: str, login_a: str, login_b: str, seed: Optional[str], anon_key: Optional[str]
) -> ProveSetup:
    def _acct(label: str, spec: str) -> Account:
        email, _, password = spec.partition(":")
        return Account(label=label, email=email, password=password)

    seed_record = None
    if seed:
        table, _, rid = seed.partition(":")
        seed_record = SeedRecord(table=table, id=rid)

    return ProveSetup(
        target=Target(url=url, anon_key=anon_key),
        account_a=_acct("A", login_a),
        account_b=_acct("B", login_b),
        seed=seed_record,
    )


if __name__ == "__main__":
    app()
