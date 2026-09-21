"""Classic injection: raw SQL, shell commands, and templates built from request data.

This check finds raw queries, dynamic ORDER BY clauses, shell-outs, and templates that skip
the safe, parameterized path. Tainted proves SQL injection by running it against your live app.
Command and template injection are only demonstrated, never run, since running them could
break your app.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

from tainted.models import (
    Candidate,
    Check,
    Confidence,
    Exploit,
    Plane,
    Provenance,
    Register,
    Severity,
    SourceLocation,
)
from tainted.static.exclude import is_excluded
from tainted.static.routes import discover_routes
from tainted.static.semgrep import semgrep_injection_candidates

_SKIP_DIRS = {"node_modules", ".git", "dist", "build", ".next", "__pycache__", ".venv"}


@dataclass
class SinkPattern:
    kind: str  # "sql" | "command" | "template"
    pattern: re.Pattern
    title: str
    severity: Severity
    live_provable: bool  # SQLi is; command/template are demonstrated-not-executed


# Markers that show a request value was pasted into the raw construct, not a fixed string.
_INTERP = r"(?:\$\{|\+\s*\w|%\s*\(|%\s|f['\"]|\.format\(|`.*\$\{)"

_PATTERNS: list[SinkPattern] = [
    # --- SQL: a raw query built by pasting in a value, and the ORDER BY you can't bind. --- #
    SinkPattern(
        "sql",
        re.compile(r"\.(?:query|execute|raw|unsafe)\s*\(\s*(?:`[^`]*\$\{|['\"].*?['\"]\s*[+%])", re.I),
        "Raw SQL query with a value pasted directly in",
        Severity.HIGH,
        True,
    ),
    SinkPattern(
        "sql",
        re.compile(r"order\s+by\s*[\"'`]?\s*(?:\$\{|\+|%s|['\"]\s*\+)", re.I),
        "ORDER BY built from request data (column names can't be parameterized)",
        Severity.HIGH,
        True,
    ),
    SinkPattern(
        "sql",
        # Any receiver, not just one literally named `cursor`: `cur`, `conn.cursor()` and
        # `db.session` are all as common, and anchoring to the name meant the most likely
        # spelling of this bug was the one shape that went unreported. The trailing `\{`
        # requires something actually interpolated, so a plain `f"SELECT 1"` stays quiet.
        # The quote is captured and matched by backreference, because SQL puts the *other*
        # quote inside the string all the time (`id = '{x}'`); a plain [^'"]* stops dead on it.
        re.compile(
            r"\.(?:execute|executemany|query|raw|unsafe)\s*\(\s*f(['\"])(?:(?!\1).)*\{", re.I
        ),
        "Python query built with an f-string",
        Severity.HIGH,
        True,
    ),
    SinkPattern(
        "sql",
        # `.format()` is the same paste with older syntax, and was missed for the same reason.
        re.compile(
            r"\.(?:execute|executemany|query|raw|unsafe)\s*\(\s*['\"].*?['\"]\s*\.format\s*\(",
            re.I,
        ),
        "Python query built with .format()",
        Severity.HIGH,
        True,
    ),
    # --- Command execution. --- #
    SinkPattern(
        "command",
        re.compile(r"child_process\.(?:exec|execSync)\s*\(\s*(?:`[^`]*\$\{|['\"].*?['\"]\s*\+)", re.I),
        "child_process.exec() run with a value pasted directly in",
        Severity.CRITICAL,
        False,
    ),
    SinkPattern(
        "command",
        re.compile(r"(?:os\.system|subprocess\.(?:call|run|Popen))\s*\([^)]*" + _INTERP, re.I),
        "Python shell command run with a value pasted directly in",
        Severity.CRITICAL,
        False,
    ),
    SinkPattern(
        "command",
        re.compile(r"subprocess\.\w+\([^)]*shell\s*=\s*True", re.I),
        "subprocess call with shell=True",
        Severity.HIGH,
        False,
    ),
    # --- Template rendering and code evaluation. --- #
    SinkPattern(
        "template",
        re.compile(r"render_template_string\s*\(\s*(?:f['\"]|[^)]*\+)", re.I),
        "Flask renders a template built from user input",
        Severity.HIGH,
        False,
    ),
    SinkPattern(
        "template",
        re.compile(r"\b(?:eval|new Function)\s*\(\s*(?:`[^`]*\$\{|[A-Za-z_]\w*\s*[+)])"),
        "Code run from a variable, via eval() or new Function()",
        Severity.CRITICAL,
        False,
    ),
]

_DEMO_PAYLOAD = {
    "sql": "' OR '1'='1' -- ",
    "command": "; id #",
    "template": "{{7*7}}",
}


def _demonstrated_exploit(kind: str, live_provable: bool) -> Exploit:
    return Exploit(
        description=(
            f"Tainted built this {kind} injection attack using `{_DEMO_PAYLOAD[kind]}`."
            + (
                " It can run this same attack against your live app."
                if live_provable
                else " The attack was built but NOT executed. Running it could break your app."
            )
        ),
        payload=_DEMO_PAYLOAD[kind],
        executed=False,  # this static pass never runs anything; live SQL injection runs in `prove`
    )


def scan_classic_injection(repo_path: str, exclude: Sequence[str] = ()) -> list[Candidate]:
    """Scan for classic injection: a fast regex pass, then Semgrep confirms which hits are real.

    A regex hit alone can't tell a request value from a fixed string; Semgrep can. Each
    possible hole is then matched to the route that reaches it, so Tainted has an address to attack.
    """
    root = Path(repo_path)
    candidates: list[Candidate] = []
    exts = {".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".py"}

    for path in root.rglob("*"):
        if not path.is_file() or path.suffix not in exts:
            continue
        if any(part in _SKIP_DIRS for part in path.parts):
            continue
        rel = str(path.relative_to(root))
        if exclude and is_excluded(rel, exclude):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for i, line in enumerate(text.splitlines(), start=1):
            for sp in _PATTERNS:
                if sp.pattern.search(line):
                    candidates.append(_candidate(sp, rel, i, line.strip()))

    # Semgrep's confirmed flows. Where one lands on a line the regex pass already found,
    # it upgrades that candidate instead of duplicating it: same bug, better evidence.
    _merge_taint_confirmations(candidates, semgrep_injection_candidates(repo_path, exclude=exclude))

    _attach_routes(candidates, repo_path, exclude)
    # Sorted with raw-query and shell constructs first, Semgrep-confirmed first within each severity.
    candidates.sort(
        key=lambda c: (-c.severity.rank, not c.metadata.get("taint_confirmed", False))
    )
    return candidates


def _merge_taint_confirmations(
    candidates: list[Candidate], confirmed: list[Candidate]
) -> None:
    """Merge Semgrep's confirmed findings into the regex hits, adding any it found on its own."""
    index = {(c.location.file, c.location.line): c for c in candidates}
    for hit in confirmed:
        existing = index.get((hit.location.file, hit.location.line))
        if existing is None:
            candidates.append(hit)
            continue
        existing.metadata["taint_confirmed"] = True
        existing.metadata["semgrep_rule"] = hit.metadata.get("semgrep_rule")
        existing.confidence = hit.confidence
        existing.provenance.extend(hit.provenance)
        existing.description += (
            " Semgrep confirmed it: this value comes from the request, "
            "not from a fixed string."
        )


def _attach_routes(candidates: list[Candidate], repo_path: str, exclude: Sequence[str] = ()) -> None:
    """Attach the route that reaches each possible hole, when one exists.

    Without a route, Tainted has no URL to send an attack to, so it can't prove anything.
    """
    routes = discover_routes(repo_path, exclude)
    by_file: dict[str, list] = {}
    for route in routes:
        by_file.setdefault(route.file, []).append(route)

    for cand in candidates:
        for route in by_file.get(cand.location.file, []):
            span_start = route.line
            span_end = route.line + route.body.count("\n")
            if span_start <= cand.location.line <= span_end or route.framework in (
                "next-pages",
                "next-app",
            ):
                cand.metadata["route_path"] = route.path
                cand.metadata["method"] = route.method
                break


def _candidate(sp: SinkPattern, file: str, line: int, snippet: str) -> Candidate:
    return Candidate(
        check=Check.CLASSIC_INJECTION,
        plane=Plane.REQUEST,
        title=sp.title,
        description=(
            f"At {file}:{line}, a {sp.kind} operation looks like it takes a value straight from the request. "
            + (
                "Tainted can run this SQL injection attack against your live app."
                if sp.live_provable
                else "Tainted only builds this attack. It does not run it."
            )
        ),
        location=SourceLocation(file=file, line=line, snippet=snippet),
        sink=sp.kind,
        severity=sp.severity,
        provenance=[
            Provenance(origin=Register.STRUCTURE, detail=f"classic-injection sink: {sp.kind}")
        ],
        confidence=Confidence(
            score=0.6, rationale="interpolation into a raw sink; taint not yet confirmed"
        ),
        metadata={
            "kind": sp.kind,
            "live_provable": sp.live_provable,
            "demonstrated_exploit": _demonstrated_exploit(sp.kind, sp.live_provable).model_dump(),
        },
    )
