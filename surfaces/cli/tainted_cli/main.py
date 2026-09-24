"""The `tainted` command. A Typer wrapper over the core engine."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer

from tainted import analyze as core_analyze
from tainted import fix as core_fix
from tainted import lockout_check as core_lockout
from tainted.invariants import check_invariants as core_invariants
from tainted.dynamic.replay import SupabaseReplay
from tainted.dynamic.target import Account, ProveSetup, SeedRecord, Target  # noqa: F401
from tainted.llm.gemini import get_default_client
from tainted.models import Check, FindingStatus, Severity
from tainted.report import build_report, select_candidate
from tainted_cli.render import _e, console, render_report, render_reverification

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
    autodiscover: bool = typer.Option(
        False,
        help=(
            "When you don't give --seed, Tainted uses Playwright to walk the app as account A "
            "and find one. It clears a form field itself when it can; otherwise the field "
            "stays as is."
        ),
    ),
    max_minutes: Optional[float] = typer.Option(
        None, help="Stop after this many minutes, keeping every hole proven so far."
    ),
    max_candidates: Optional[int] = typer.Option(
        None, help="Stop after attempting this many candidates."
    ),
):
    """Run real attacks against the running app, inside a Docker sandbox. Localhost only."""
    from tainted.budget import parse_budget

    setup = _build_setup(url, login_a, login_b, seed, anon_key)
    budget = parse_budget(max_minutes, max_candidates)

    # Localhost only, and derived rather than asserted. There is no token path to reach: the
    # CLI points at an app you are running, so if the target is not local the honest answer is
    # to refuse rather than to ask the caller to vouch for themselves.
    if not setup.target.is_local:
        console.print(
            f"[red]{_e(setup.target.url)} is not localhost. The CLI proves against an app "
            f"running on this machine; point it at one, or use the website for a remote "
            f"target.[/red]"
        )
        raise typer.Exit(code=2)

    from tainted.execution.base import SandboxUnavailable
    from tainted.execution.docker import DockerExecutor

    # Host networking, so `localhost` in the container IS this machine's localhost and the URL
    # never has to be rewritten. See the design doc's network split.
    executor = DockerExecutor(network="host")
    try:
        outcome = executor.prove(
            str(repo),
            setup,
            ownership_verified=True,  # derived above: the target is genuinely local
            autodiscover=autodiscover,
            budget=budget,
        )
    except SandboxUnavailable as exc:
        console.print(f"[red]{_e(exc)}[/red]")
        raise typer.Exit(code=2)
    except PermissionError as exc:
        console.print(f"[red]{_e(exc)}[/red]")
        raise typer.Exit(code=2)

    report = outcome.report
    render_report(report)
    if outcome.budget and outcome.budget.get("stopped_early"):
        console.print(f"[yellow]{_e(outcome.budget['note'])}[/yellow]")
    findings = report.findings
    if any(
        f.status == FindingStatus.PROVEN and f.severity.rank >= Severity.HIGH.rank
        for f in findings
    ):
        raise typer.Exit(code=1)


@app.command()
def fix(
    repo: Path = typer.Argument(..., exists=True, file_okay=False),
    finding_id: Optional[str] = typer.Option(
        None,
        "--finding-id",
        help="The ID column from `analyze`. Names the hole itself, so it cannot drift.",
    ),
    index: int = typer.Option(
        0, help="The # column from `analyze`. Only meaningful for that exact run."
    ),
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
    # Addressed through the engine's own helper, so the row `analyze` drew and the candidate
    # fixed here are the same candidate. Selecting from `ranked()` while the table rendered
    # `build_report`'s order meant they were routinely not.
    try:
        candidate = select_candidate(result, finding_id=finding_id, index=index)
    except LookupError as exc:
        console.print(f"[red]{_e(exc)}[/red]")
        raise typer.Exit(code=2)
    finding = Finding(candidate=candidate)
    console.print(f"[bold]Fixing:[/bold] {_e(candidate.title)} [dim]({_e(candidate.id)})[/dim]\n")

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
        console.print(f"[red]{_e(exc)}[/red]")
        raise typer.Exit(code=2)

    # The patch is the product, so it leaves here byte for byte. Two things would otherwise
    # edit it on the way out: rich reads anything in square brackets as a style tag and deletes
    # it (`[id]` in a Next route, an array index, a SQL placeholder), and it re-wraps long lines
    # at the terminal width, which breaks a path in half. `_e` stops the first, `soft_wrap` the
    # second. A diff a reader copies off the terminal must be the bytes `--apply` writes.
    for edit in result_fix.edits:
        console.print(f"[bold]--- {_e(edit.file)}[/bold]", soft_wrap=True)
        console.print(_e(edit.replacement), soft_wrap=True)
    console.print(f"[dim]{_e(result_fix.notes)}[/dim]")

    if apply:
        for edit in result_fix.edits:
            path = repo / edit.file
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(edit.replacement, encoding="utf-8")
            console.print(f"[green]wrote {_e(path)}[/green]", soft_wrap=True)

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
    from tainted_cli.watch import refusal_reason, watch_repo

    wanted = _parse_checks(only)
    # Refused here rather than deep in the loop, so the flag fails like a flag: a usage error
    # before anything is scanned or watched.
    reason = refusal_reason(wanted)
    if reason:
        raise typer.BadParameter(reason)
    watch_repo(str(repo), only=wanted, skip=_parse_checks(skip))


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
def sarif(
    repo: Path = typer.Argument(..., exists=True, file_okay=False),
    only: Optional[str] = typer.Option(None, help="Run only these checks (comma-separated)"),
    skip: Optional[str] = typer.Option(None, help="Skip these checks (comma-separated)"),
):
    """Emit the analysis as SARIF 2.1.0, with proof strength and the silence ledger.

    Prints to stdout so you can redirect it into your CI's Security tab. Proof strength rides on
    each result's level (proven = error), and everything the run did not test rides on the run's
    properties, so an empty results array is never mistaken for full coverage.
    """
    from tainted.report.sarif import to_sarif_json

    result = core_analyze(
        str(repo), llm=_llm_or_none(), only=_parse_checks(only), skip=_parse_checks(skip)
    )
    typer.echo(to_sarif_json(build_report(result)))


@app.command(name="mutate-security")
def mutate_security(
    repo: Path = typer.Argument(..., exists=True, file_okay=False),
    test_cmd: Optional[str] = typer.Option(
        None, help="Command to run the suite, e.g. 'pytest -q'. Without it, mutants are listed but not run."
    ),
):
    """Remove each authorization check and report the ones no test catches.

    Only surviving security mutants are shown — a line whose ownership predicate could vanish and
    your suite would stay green. Without a --test-cmd the checks are found but not run, and none is
    claimed killed, in keeping with the rule that an un-run check never reads as a passed one.
    """
    from tainted.checks.security_mutation import run_security_mutation

    cmd = test_cmd.split() if test_cmd else None
    result = run_security_mutation(str(repo), test_cmd=cmd)
    console.print(f"[bold]{_e(result.note)}[/bold]")
    for m in result.survived:
        console.print(
            f"  [yellow]survived[/yellow] {_e(m.file)}:{m.line} "
            f"[{_e(m.operator.name)}]  {_e(m.original)}"
        )
    if result.ran and result.survived:
        raise typer.Exit(code=1)


@app.command()
def ledger(
    repo: Path = typer.Argument(..., exists=True, file_okay=False),
    url: Optional[str] = typer.Option(None, help="Base URL, to enable the behavioral probe rung"),
):
    """Show what Tainted did NOT test, and why — the silence ledger as a first-class artifact."""
    from tainted.report.enrich import silence_ledger

    target = Target(url=url) if url else None
    result = core_analyze(str(repo), llm=_llm_or_none(), target=target)
    led = silence_ledger(build_report(result))
    console.print(f"[bold]{_e(led['headline'])}[/bold]\n")
    for row in led["skipped_planes"]:
        console.print(f"  [dim]plane cleared as absent:[/dim] {_e(row['plane'])} — {_e(row['evidence'])}")
    for row in led["not_proved"]:
        console.print(f"  [yellow]not fully proven:[/yellow] {_e(row['check'])} — {_e(row['detail'])}")
    console.print(f"\n[dim]{_e(led['reminder'])}[/dim]")


@app.command()
def lockout(
    url: str = typer.Option(..., help="Base URL of the running app"),
    login_a: str = typer.Option(..., "--login-a", help="email:password for the owner"),
    seed: str = typer.Option(..., help="table:id of a record the owner owns"),
    route: Optional[str] = typer.Option(None, help="The route that serves it, e.g. /api/invoices/[id]"),
    anon_key: Optional[str] = typer.Option(None, help="Supabase anon key, if the app uses one"),
):
    """Check whether your security locked out your own users.

    The opposite failure from a vulnerability, and the one nothing else reports. A policy that
    blocks the attack and also blocks the owner is secure and broken, and this asks that question
    on its own — no finding required, any time you like.
    """
    setup = _build_setup(url, login_a, login_a, seed, anon_key)
    if route and setup.seed:
        setup.seed.route_path = route
    result = core_lockout(setup)

    if not result.checked:
        console.print("[yellow]Nothing was tested.[/yellow] This is not a pass.")
        for row in result.undecided:
            console.print(f"  [dim]{_e(row['resource'])}:[/dim] {_e(row['reason'])}")
        raise typer.Exit(code=2)

    for c in result.checked:
        tag = "[red]locked out[/red]" if c.owner_locked_out else "[green]reachable[/green]"
        console.print(f"  {tag} {_e(c.resource)} [dim]via {_e(c.via)}[/dim] — {_e(c.detail)}")
    console.print(f"\n[bold]{_e(result.as_dict()['detail'])}[/bold]")
    if result.locked_out:
        raise typer.Exit(code=1)


@app.command()
def invariants(
    repo: Path = typer.Argument(..., exists=True, file_okay=False),
    rule: list[str] = typer.Option(..., "--rule", help="A rule in plain English. Repeatable."),
    url: str = typer.Option(..., help="Base URL of the running app"),
    login_b: str = typer.Option(..., "--login-b", help="email:password for the attacking account"),
    seed: Optional[str] = typer.Option(None, help="table:id of a record to aim at"),
    anon_key: Optional[str] = typer.Option(None, help="Supabase anon key, if the app uses one"),
):
    """Test rules you write in plain English against the running app.

    Each rule comes back violated, held, or NOT TESTED — and the third one is the point. A rule
    Tainted could not build an attack for is not a rule that held, so it is never reported as one.
    """
    setup = _build_setup(url, login_b, login_b, seed, anon_key)
    report = core_invariants(list(rule), str(repo), setup, llm=_llm_or_none())

    for r in report.results:
        colour = {"violated": "red", "held": "green", "not_tested": "yellow"}[r.verdict.value]
        console.print(f"  [{colour}]{_e(r.verdict.value)}[/{colour}] {_e(r.rule)}")
        console.print(f"    [dim]{_e(r.detail)}[/dim]")
    console.print(f"\n[bold]{_e(report.as_dict()['headline'])}[/bold]")
    console.print(f"[dim]{_e(report.as_dict()['reminder'])}[/dim]")
    if report.violated:
        raise typer.Exit(code=1)


@app.command()
def receipt(
    repo: Path = typer.Argument(..., exists=True, file_okay=False),
    secret: Optional[str] = typer.Option(
        None, envvar="TAINTED_RECEIPT_SECRET", help="Signing key. Without one the receipt is unsigned."
    ),
):
    """Emit a signed receipt: what was fired, what worked, and what was never tried.

    The signature covers the untested surface as well as the findings, so the admissions cannot be
    deleted from a document that still verifies. Prints JSON to stdout.
    """
    import json as _json

    from tainted.receipt import build_receipt, sign as _sign

    result = core_analyze(str(repo), llm=_llm_or_none())
    rec = build_receipt(build_report(result))
    signature = _sign(rec, secret.encode("utf-8")) if secret else None
    typer.echo(_json.dumps(rec.as_dict(signature), indent=2))


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
