"""Semgrep taint mode — dataflow the single-handler scan cannot see.

The route scan in `routes.py` reads one handler at a time, so it only finds a parameter reaching
a query when both are in the same function. Real code routes the id through a helper:

    export async function GET(_req, { params }) {
      return Response.json(await loadInvoice(params.id));   // handler
    }
    async function loadInvoice(id) {
      return supabase.from("invoices").select("*").eq("id", id).single();   // two files away
    }

Semgrep's interprocedural taint tracking follows that. It is an **additive** source of
candidates, never a replacement: Semgrep is an optional dependency (it is heavy), and when it is
absent this module reports that plainly and the route scan carries the plane alone. A missing
optional tool must degrade the analysis legibly, not silently.

The rules stop at the flow. Whether the read is *safe* depends on an ownership predicate in the
surrounding handler, so every hit is post-filtered through `routes.scoping_signals` — the same
definition of "the predicate names the owner" the route scan uses.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Optional, Sequence

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
from tainted.static.routes import identity_signals, scoping_signals

RULES_DIR = Path(__file__).parent / "rules"
BOLA_RULES = RULES_DIR / "bola.yaml"
INJECTION_RULES = RULES_DIR / "injection.yaml"

# A runner is injectable so the parsing and candidate construction are testable without
# installing (or waiting on) a real Semgrep run.
SemgrepRunner = Callable[[Path, str], "SemgrepRun"]

_TIMEOUT_S = 600


@dataclass
class SemgrepRun:
    available: bool
    findings: list[dict[str, Any]]
    note: str = ""


def semgrep_available() -> bool:
    return shutil.which("semgrep") is not None


def _default_runner(rules: Path, repo_path: str, exclude: Sequence[str] = ()) -> SemgrepRun:
    if not semgrep_available():
        return SemgrepRun(
            available=False,
            findings=[],
            note="semgrep not installed — interprocedural taint skipped (pip install 'tainted[semgrep]').",
        )
    try:
        exclude_args: list[str] = []
        for pat in exclude:
            exclude_args += ["--exclude", pat]
        proc = subprocess.run(
            [
                "semgrep",
                "--config",
                str(rules),
                "--json",
                "--quiet",
                "--no-git-ignore",
                "--metrics",
                "off",
                *exclude_args,
                repo_path,
            ],
            capture_output=True,
            text=True,
            timeout=_TIMEOUT_S,
        )
    except FileNotFoundError:
        return SemgrepRun(False, [], "semgrep not installed.")
    except subprocess.TimeoutExpired:
        return SemgrepRun(False, [], "semgrep timed out.")
    # Semgrep exits 1 when it has findings; only >1 is a real failure.
    if proc.returncode > 1:
        return SemgrepRun(False, [], f"semgrep failed: {proc.stderr.strip()[:300]}")
    try:
        data = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError:
        return SemgrepRun(False, [], "semgrep returned non-JSON output.")
    return SemgrepRun(True, data.get("results", []))


def parse_results(payload: str) -> list[dict[str, Any]]:
    """Parse a `semgrep --json` document into its results list."""
    data = json.loads(payload)
    return data.get("results", [])


# --------------------------------------------------------------------------- #
# BOLA candidates
# --------------------------------------------------------------------------- #
def semgrep_bola_candidates(
    repo_path: str, runner: Optional[SemgrepRunner] = None, exclude: Sequence[str] = ()
) -> list[Candidate]:
    """Taint flows from a request parameter to a database read, minus the ones already scoped."""
    run = runner(BOLA_RULES, repo_path) if runner else _default_runner(BOLA_RULES, repo_path, exclude)
    if not run.available:
        return []

    candidates: list[Candidate] = []
    for result in run.findings:
        region = _region(repo_path, result)
        if scoping_signals(region):
            continue  # the predicate names the owner — this flow is scoped
        candidates.append(_bola_candidate(result, region))
    return candidates


def _bola_candidate(result: dict[str, Any], region: str) -> Candidate:
    path = result.get("path", "")
    start = result.get("start", {}) or {}
    line = int(start.get("line", 0) or 0)
    extra = result.get("extra", {}) or {}
    snippet = _clip(extra.get("lines", ""))
    identity = identity_signals(region)

    return Candidate(
        check=Check.BOLA,
        plane=Plane.REQUEST,
        title=f"Request parameter reaches a database read unscoped ({Path(path).name}:{line})",
        description=(
            "Semgrep traced a request-supplied value into a database read with no predicate "
            "naming the owning user. This flow crosses function boundaries, so the read and the "
            "parameter need not be in the same handler. "
            + (
                f"The surrounding code does read the caller's identity ({', '.join(identity)}) "
                "without constraining the query by it."
                if identity
                else "No caller identity appears in the surrounding code."
            )
        ),
        location=SourceLocation(file=path, line=line, snippet=snippet),
        source="request parameter (taint source)",
        sink=snippet,
        severity=Severity.HIGH if identity else Severity.MEDIUM,
        provenance=[
            Provenance(
                origin=Register.STRUCTURE,
                detail=f"semgrep taint rule `{result.get('check_id', '?')}`",
            )
        ],
        confidence=Confidence(
            score=0.6, rationale="interprocedural taint flow with no owner predicate on the path"
        ),
        metadata={
            "semgrep_rule": result.get("check_id"),
            "identity_signals": identity,
            "route_path": None,
            "method": "GET",
        },
    )


# --------------------------------------------------------------------------- #
# Classic-injection candidates
# --------------------------------------------------------------------------- #
_DEMO_PAYLOAD = {"sql": "' OR '1'='1' -- ", "command": "; id #", "template": "{{7*7}}"}
_LIVE_PROVABLE = {"sql": True, "command": False, "template": False}
_SEVERITY = {"sql": Severity.HIGH, "command": Severity.CRITICAL, "template": Severity.HIGH}


def semgrep_injection_candidates(
    repo_path: str, runner: Optional[SemgrepRunner] = None, exclude: Sequence[str] = ()
) -> list[Candidate]:
    """Taint-confirmed injection flows — user input actually reaching a raw sink.

    These are strictly stronger than the regex pre-pass, which cannot tell an interpolated
    request value from an interpolated constant, so they carry a higher confidence.
    """
    run = runner(INJECTION_RULES, repo_path) if runner else _default_runner(INJECTION_RULES, repo_path, exclude)
    if not run.available:
        return []

    candidates: list[Candidate] = []
    for result in run.findings:
        extra = result.get("extra", {}) or {}
        kind = (extra.get("metadata", {}) or {}).get("tainted_kind", "sql")
        if kind not in _DEMO_PAYLOAD:
            continue
        candidates.append(_injection_candidate(result, kind))
    return candidates


def _injection_candidate(result: dict[str, Any], kind: str) -> Candidate:
    path = result.get("path", "")
    line = int((result.get("start", {}) or {}).get("line", 0) or 0)
    extra = result.get("extra", {}) or {}
    snippet = _clip(extra.get("lines", ""))
    live = _LIVE_PROVABLE[kind]

    exploit = Exploit(
        description=(
            f"{kind} injection demonstrated with payload `{_DEMO_PAYLOAD[kind]}`."
            + (
                " Provable live via the request harness."
                if live
                else " Held at demonstration, not run. Running it could be destructive."
            )
        ),
        payload=_DEMO_PAYLOAD[kind],
        executed=False,
    )

    return Candidate(
        check=Check.CLASSIC_INJECTION,
        plane=Plane.REQUEST,
        title=f"User input reaches a {kind} sink (taint-confirmed)",
        description=(
            f"Semgrep traced user input into a raw {kind} construct. Unlike a pattern match, "
            f"this is a confirmed flow: the value reaching the sink comes from the request. "
            + (
                "SQL injection is provable live on the running target."
                if live
                else "Command and template injection are demonstrated, never executed."
            )
        ),
        location=SourceLocation(file=path, line=line, snippet=snippet),
        source="request input (taint source)",
        sink=kind,
        severity=_SEVERITY[kind],
        provenance=[
            Provenance(
                origin=Register.STRUCTURE,
                detail=f"semgrep taint rule `{result.get('check_id', '?')}`",
            )
        ],
        confidence=Confidence(
            score=0.85, rationale="taint-confirmed flow, not a pattern match on interpolation"
        ),
        metadata={
            "kind": kind,
            "live_provable": live,
            "taint_confirmed": True,
            "semgrep_rule": result.get("check_id"),
            "demonstrated_exploit": exploit.model_dump(),
        },
    )


# --------------------------------------------------------------------------- #
def _region(repo_path: str, result: dict[str, Any], window: int = 25) -> str:
    """The lines around a finding — where an ownership predicate would live if there were one."""
    path = result.get("path", "")
    file_path = Path(path)
    if not file_path.is_absolute():
        file_path = Path(repo_path) / path
    try:
        lines = file_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return (result.get("extra", {}) or {}).get("lines", "")
    start = int((result.get("start", {}) or {}).get("line", 1) or 1)
    end = int((result.get("end", {}) or {}).get("line", start) or start)
    lo = max(0, start - 1 - window)
    hi = min(len(lines), end + window)
    return "\n".join(lines[lo:hi])


def _clip(text: str, limit: int = 200) -> str:
    return " ".join((text or "").split())[:limit]
