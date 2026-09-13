"""Test integrity: how much of your test suite actually checks anything.

Tainted measures this with mutation testing (Stryker for JS/TS, mutmut for Python). Each tool
changes one line and reruns your suite; a mutant that survives is a line no test was watching.
The `CommandRunner` is swappable so tests can check the parsing without a real, slow mutation run.
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Callable, Optional

if TYPE_CHECKING:  # named in the return annotation below; imported lazily to keep this
    from tainted.models import Candidate, MutationSummary  # module free of a cycle via models

CommandRunner = Callable[[list[str], str], "CommandResult"]


@dataclass
class CommandResult:
    returncode: int
    stdout: str = ""
    stderr: str = ""
    tool_missing: bool = False


@dataclass
class SurvivingMutant:
    file: str
    line: int
    mutator: str
    original: str = ""
    mutated: str = ""


@dataclass
class MutationResult:
    tool: str
    available: bool
    total: int = 0
    killed: int = 0
    survived: int = 0
    survivors: list[SurvivingMutant] = field(default_factory=list)
    note: str = ""

    @property
    def score(self) -> Optional[float]:
        """Mutation score = killed / total. None when nothing ran."""
        return (self.killed / self.total) if self.total else None


def _default_runner(cmd: list[str], cwd: str) -> CommandResult:
    try:
        proc = subprocess.run(
            cmd, cwd=cwd, capture_output=True, text=True, timeout=1800
        )
    except FileNotFoundError:
        return CommandResult(returncode=127, tool_missing=True)
    except subprocess.TimeoutExpired:
        return CommandResult(returncode=124, stderr="mutation run timed out")
    return CommandResult(proc.returncode, proc.stdout, proc.stderr)


# --------------------------------------------------------------------------- #
# Report parsers
# --------------------------------------------------------------------------- #
def parse_stryker(report_json: str) -> MutationResult:
    """Parse a Stryker mutation-report.json (the `files -> mutants[]` schema)."""
    data = json.loads(report_json)
    result = MutationResult(tool="stryker", available=True)
    files = data.get("files", {})
    for fname, fentry in files.items():
        for m in fentry.get("mutants", []):
            result.total += 1
            status = m.get("status", "")
            if status == "Killed":
                result.killed += 1
            elif status in ("Survived", "NoCoverage"):
                result.survived += 1
                loc = m.get("location", {}).get("start", {})
                result.survivors.append(
                    SurvivingMutant(
                        file=fname,
                        line=loc.get("line", 0),
                        mutator=m.get("mutatorName", "?"),
                        mutated=m.get("replacement", ""),
                    )
                )
    return result


def parse_mutmut(list_output: str) -> MutationResult:
    """Parse `mutmut results` style output: lines like `survived: 12` and per-mutant rows."""
    result = MutationResult(tool="mutmut", available=True)
    for line in list_output.splitlines():
        line = line.strip()
        m = _MUTMUT_ROW.match(line)
        if m:
            result.total += 1
            status = m.group("status").lower()
            if status.startswith("killed"):
                result.killed += 1
            elif status.startswith("survived"):
                result.survived += 1
                result.survivors.append(
                    SurvivingMutant(
                        file=m.group("file"), line=int(m.group("line")), mutator=status
                    )
                )
    return result


import re  # noqa: E402 (kept near its sole use)

_MUTMUT_ROW = re.compile(
    r"^(?P<status>survived|killed)\s+(?P<file>[\w./-]+):(?P<line>\d+)", re.I
)


# --------------------------------------------------------------------------- #
# Runner selection
# --------------------------------------------------------------------------- #
def detect_tool(repo_path: str) -> Optional[str]:
    root = Path(repo_path)
    if (root / "package.json").exists():
        return "stryker"
    if any(root.rglob("*.py")):
        return "mutmut"
    return None


def run_mutation_testing(
    repo_path: str, runner: Optional[CommandRunner] = None
) -> MutationResult:
    """Run mutation testing with the appropriate tool and return the single measurement."""
    runner = runner or _default_runner
    tool = detect_tool(repo_path)
    if tool is None:
        return MutationResult(tool="none", available=False, note="No JS/TS or Python test suite found.")

    if tool == "stryker":
        res = runner(["npx", "stryker", "run", "--reporters", "json"], repo_path)
        if res.tool_missing:
            return MutationResult(tool="stryker", available=False, note="Stryker not installed.")
        report = Path(repo_path) / "reports" / "mutation" / "mutation.json"
        if report.exists():
            return parse_stryker(report.read_text(encoding="utf-8"))
        return MutationResult(tool="stryker", available=True, note="No report produced.")

    # mutmut
    res = runner(["mutmut", "run"], repo_path)
    if res.tool_missing:
        return MutationResult(tool="mutmut", available=False, note="mutmut not installed.")
    listing = runner(["mutmut", "results"], repo_path)
    return parse_mutmut(listing.stdout)


# --------------------------------------------------------------------------- #
# The engine's entry point
# --------------------------------------------------------------------------- #
def measure_test_integrity(
    repo_path: str, runner: Optional[CommandRunner] = None
) -> tuple["MutationSummary", list["Candidate"]]:
    """Run the mutation campaign and return the score plus one possible hole per surviving mutant.

    A surviving mutant is not a vulnerability, so these stay LOW severity and never block a build.
    Each one exists so you can look at that line and decide whether a test is missing.
    """
    from tainted.models import (
        Candidate,
        Check,
        Confidence,
        MutationSummary,
        Provenance,
        Register,
        Severity,
        SourceLocation,
    )

    result = run_mutation_testing(repo_path, runner=runner)
    summary = MutationSummary(
        tool=result.tool,
        available=result.available,
        total=result.total,
        killed=result.killed,
        survived=result.survived,
        score=result.score,
        note=result.note,
    )

    candidates: list[Candidate] = []
    for mutant in result.survivors:
        candidates.append(
            Candidate(
                check=Check.TEST_INTEGRITY,
                plane=None,
                title=f"No test caught a change to {mutant.file}:{mutant.line} ({mutant.mutator})",
                description=(
                    f"Changing this line ({mutant.mutator}) did not fail any test. Either this "
                    f"behavior is intended and no test checks it, or it is a bug your tests "
                    f"missed. Only you can say which."
                ),
                location=SourceLocation(file=mutant.file, line=mutant.line),
                source="mutation testing",
                sink="unasserted behavior",
                structural=True,  # the surviving mutant IS the evidence; nothing to rank
                severity=Severity.LOW,
                provenance=[
                    Provenance(
                        origin=Register.PROOF,
                        detail=f"{result.tool}: mutant survived the suite",
                    )
                ],
                confidence=Confidence(
                    score=1.0, rationale="the mutant survived — this is a measurement, not a guess"
                ),
                metadata={
                    "mutator": mutant.mutator,
                    "original": mutant.original,
                    "mutated": mutant.mutated,
                    "tool": result.tool,
                },
            )
        )
    return summary, candidates
