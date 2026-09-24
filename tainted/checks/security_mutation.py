"""Security-targeted mutation: delete the ownership check, then see if any test notices.

General mutation testing flips arbitrary lines. This flips exactly the lines that enforce
authorization, and reports **only** the security mutants that survived — ignoring the overall
mutation score, which is a different question. The operators are the inverse of the scoping
signals the route parser already trusts:

  * **drop-owner-eq** — strip a `.eq('user_id', user.id)` (and its `.match({...})` cousin) off a
    query chain, leaving the id-only read that is the BOLA shape;
  * **rls-using-true** — widen a policy's `using (auth.uid() = owner)` to `using (true)`;
  * **invert-authz-guard** — flip an `if (!authorized) return 403` so the guard never triggers.

A surviving security mutant means: this authorization check could vanish and your suite would
stay green. That is a measurement, kept at LOW severity like the rest of test integrity — it is
not itself a vulnerability. The engine's own answer to "so what?" is the other half: the mutated
source is exactly what `prove` fires a real exploit at, turning "no test caught this" into "no
test caught this **and** the attack lands". This module produces the mutants and judges survival
through an injectable runner; wiring it to a live prove is the orchestrator's job.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional, Sequence

from tainted.checks.test_integrity import CommandRunner, _default_runner
from tainted.static.exclude import is_excluded

_SKIP_DIRS = {"node_modules", ".git", "dist", "build", ".next", "__pycache__", ".venv"}


@dataclass(frozen=True)
class SecurityOperator:
    name: str
    description: str


DROP_OWNER_EQ = SecurityOperator(
    "drop-owner-eq", "remove the owner predicate from a query, leaving an id-only read"
)
RLS_USING_TRUE = SecurityOperator(
    "rls-using-true", "widen a row-level-security policy to `using (true)`"
)
INVERT_AUTHZ_GUARD = SecurityOperator(
    "invert-authz-guard", "flip an authorization guard so it never denies"
)


@dataclass
class SecurityMutant:
    """One authorization check, removed. `killed` is filled once a suite has run against it."""

    file: str
    line: int
    operator: SecurityOperator
    original: str
    mutated: str
    killed: Optional[bool] = None  # None until run; True = a test caught it; False = it survived

    def as_dict(self) -> dict:
        return {
            "file": self.file,
            "line": self.line,
            "operator": self.operator.name,
            "original": self.original,
            "mutated": self.mutated,
            "killed": self.killed,
        }


# --- the three operators, as (matcher, rewrite) over a single source line --- #

# .eq('user_id', ...) or .match({ user_id: ... }) — the owner predicate on a query chain.
_OWNER_EQ = re.compile(
    r"\.eq\(\s*['\"`](?:user_id|userId|owner|owner_id|ownerId|author_id|authorId|created_by|"
    r"createdBy|account_id|accountId|profile_id|profileId)['\"`]\s*,[^)]*\)",
    re.I,
)
# using (auth.uid() = owner) / using (owner_id = auth.uid()) in a policy line.
_RLS_USING = re.compile(r"using\s*\(([^;]*?auth\s*\.\s*uid\s*\(\s*\)[^;]*?)\)", re.I)
# if (!authorized) / if not authorized / if (!user) — a deny guard.
_AUTHZ_GUARD = re.compile(
    r"\bif\s*\(\s*!\s*(authorized|isAuthorized|allowed|isOwner|owner|user|canAccess)\b",
    re.I,
)
_AUTHZ_GUARD_PY = re.compile(
    r"\bif\s+not\s+(authorized|is_authorized|allowed|is_owner|owner|user|can_access)\b",
    re.I,
)


def _mutate_line(line: str) -> Optional[tuple[SecurityOperator, str]]:
    """The first applicable operator's rewrite of one line, or None."""
    m = _OWNER_EQ.search(line)
    if m:
        return DROP_OWNER_EQ, line[: m.start()] + line[m.end() :]
    m = _RLS_USING.search(line)
    if m:
        return RLS_USING_TRUE, line[: m.start()] + "using (true)" + line[m.end() :]
    m = _AUTHZ_GUARD.search(line)
    if m:
        return INVERT_AUTHZ_GUARD, line[: m.start()] + line[m.start():].replace("!", "", 1)
    m = _AUTHZ_GUARD_PY.search(line)
    if m:
        # `if not authorized` -> `if authorized` (drop the sole `not `)
        return INVERT_AUTHZ_GUARD, re.sub(r"\bnot\s+", "", line, count=1)
    return None


_EXTS = {".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".py", ".sql"}


def discover_security_mutants(
    repo_path: str, exclude: Sequence[str] = ()
) -> list[SecurityMutant]:
    """Every authorization check in the tree that one of the three operators can remove."""
    root = Path(repo_path)
    mutants: list[SecurityMutant] = []
    for path in root.rglob("*"):
        if not path.is_file() or path.suffix not in _EXTS:
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
            result = _mutate_line(line)
            if result is None:
                continue
            operator, mutated = result
            if mutated.strip() == line.strip():
                continue  # a rewrite that changed nothing is not a mutant
            mutants.append(
                SecurityMutant(
                    file=rel, line=i, operator=operator,
                    original=line.strip(), mutated=mutated.strip(),
                )
            )
    return mutants


# A judge decides whether a suite killed a mutant. Injectable, exactly like the mutation runner in
# test_integrity, so survival can be exercised hermetically without applying a patch or running a
# real test suite. A real judge writes the mutated line, runs the suite, and reports pass/fail.
MutantJudge = Callable[[SecurityMutant, str], bool]


def _apply(text: str, mutant: SecurityMutant) -> str:
    lines = text.splitlines()
    idx = mutant.line - 1
    if 0 <= idx < len(lines):
        indent = lines[idx][: len(lines[idx]) - len(lines[idx].lstrip())]
        lines[idx] = indent + mutant.mutated
    return "\n".join(lines)


def _default_judge_factory(runner: CommandRunner, test_cmd: list[str], repo_path: str) -> MutantJudge:
    """A judge that writes the mutant, runs the suite, restores the file, and reports the kill.

    A mutant is *killed* when the suite fails after the authorization check is removed — that is
    the suite noticing. A suite that stays green has not noticed, so the mutant survived.
    """
    def judge(mutant: SecurityMutant, _mutated_text: str) -> bool:
        path = Path(repo_path) / mutant.file
        try:
            original = path.read_text(encoding="utf-8")
        except OSError:
            return False
        try:
            path.write_text(_apply(original, mutant), encoding="utf-8")
            result = runner(test_cmd, repo_path)
        finally:
            try:
                path.write_text(original, encoding="utf-8")
            except OSError:
                pass
        if result.tool_missing:
            return False
        return result.returncode != 0

    return judge


@dataclass
class SecurityMutationResult:
    total: int = 0
    survived: list[SecurityMutant] = field(default_factory=list)
    ran: bool = False
    note: str = ""

    @property
    def killed(self) -> int:
        return self.total - len(self.survived)

    def as_dict(self) -> dict:
        return {
            "total": self.total,
            "killed": self.killed,
            "survived": [m.as_dict() for m in self.survived],
            "ran": self.ran,
            "note": self.note,
        }


def run_security_mutation(
    repo_path: str,
    judge: Optional[MutantJudge] = None,
    runner: Optional[CommandRunner] = None,
    test_cmd: Optional[list[str]] = None,
    exclude: Sequence[str] = (),
) -> SecurityMutationResult:
    """Find every removable authorization check and report the ones a test suite does not catch.

    With no judge and no test command, the mutants are found but not run — reported as
    unassessed rather than falsely all-killed, in keeping with the rule that an un-run check
    never reads as a passed one.
    """
    mutants = discover_security_mutants(repo_path, exclude)
    if not mutants:
        return SecurityMutationResult(
            total=0, ran=False, note="No removable authorization checks were found to mutate."
        )
    if judge is None:
        if test_cmd is None:
            return SecurityMutationResult(
                total=len(mutants),
                survived=mutants,
                ran=False,
                note=(
                    "Found removable authorization checks but ran no suite against them. Supply a "
                    "test command to learn which survive; until then none is claimed killed."
                ),
            )
        judge = _default_judge_factory(runner or _default_runner, test_cmd, repo_path)

    survived: list[SecurityMutant] = []
    for m in mutants:
        m.killed = judge(m, _apply_text_for(repo_path, m))
        if not m.killed:
            survived.append(m)
    return SecurityMutationResult(
        total=len(mutants),
        survived=survived,
        ran=True,
        note=(
            f"{len(mutants)} authorization check(s) mutated; {len(survived)} survived — no test "
            f"caught their removal."
        ),
    )


def _apply_text_for(repo_path: str, mutant: SecurityMutant) -> str:
    try:
        text = (Path(repo_path) / mutant.file).read_text(encoding="utf-8")
    except OSError:
        return ""
    return _apply(text, mutant)
