"""The automated fix, delivered as a pull request.

CI is the one surface that can close the whole loop by itself, because it has all three things
at once: a working tree to write to, a preview deployment to prove against, and a mechanism for
proposing a change that a human still approves. So here `fix` becomes a branch, a commit, and a
PR whose body carries the proof that the hole was open and the re-proof that it is shut.

Two deliberate restrictions:

  * **Only deterministic fixes are opened as PRs.** Request-plane and classic-injection
    remediations are determined by the code. Tool-plane fixes are architecturally
    underdetermined — an unattended pipeline cannot answer "does this agent need both
    capabilities?", and a PR that guesses is worse than a comment that asks.
  * **Only proven findings.** A PR that changes a security boundary on the strength of a
    suspicion spends the reviewer's trust without evidence.
"""

from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

from tainted.fix.paths import edit_target
from tainted.models import Check, Finding, FindingStatus, FixResult

# Fixes the code fully determines. Everything else needs a human to decide something first.
DETERMINISTIC_CHECKS = {Check.BOLA, Check.RLS, Check.CLASSIC_INJECTION}

Runner = Callable[[list[str], str], "subprocess.CompletedProcess"]


@dataclass
class PullRequestResult:
    opened: bool
    branch: str = ""
    url: str = ""
    note: str = ""
    files_written: list[str] = field(default_factory=list)


def _run(cmd: list[str], cwd: str) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=120)


def eligible(findings: list[Finding]) -> list[Finding]:
    """The findings an unattended pipeline may safely propose a fix for."""
    return [
        f
        for f in findings
        if f.status is FindingStatus.PROVEN and f.check in DETERMINISTIC_CHECKS
    ]


def branch_name(findings: list[Finding]) -> str:
    checks = "-".join(sorted({f.check.value for f in findings}))
    run_id = os.environ.get("GITHUB_RUN_ID", "local")
    return f"tainted/fix-{checks}-{run_id}"


def apply_edits(repo: str, fixes: list[FixResult]) -> list[str]:
    """Write each fix's edits into the working tree, returning the paths touched.

    Additive files (a new migration) are written whole. An edit that replaces a snippet inside
    an existing file is written as a sibling `.tainted-fix` file instead of being spliced in:
    a regex-guided splice into someone's handler is exactly the kind of automated edit that
    looks right in a diff and is wrong in the build.
    """
    written: list[str] = []
    root = Path(repo).resolve()
    for fix in fixes:
        for edit in fix.edits:
            # Shared with the CLI's `--apply`: the sibling rule, and a refusal for any path
            # that would land outside the checkout.
            path = edit_target(root, edit)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(edit.replacement, encoding="utf-8")
            written.append(str(path.relative_to(root)))
    return written


def open_pull_request(
    repo: str,
    findings: list[Finding],
    fixes: list[FixResult],
    runner: Optional[Runner] = None,
    base: Optional[str] = None,
) -> PullRequestResult:
    """Branch, commit the fixes, push, and open a PR carrying the proof and the re-proof."""
    runner = runner or _run
    candidates = eligible(findings)
    if not candidates:
        return PullRequestResult(
            opened=False,
            note=(
                "No proven finding with a deterministic fix. Tool-plane findings need the "
                "interview answered by a human and are reported, not auto-fixed."
            ),
        )

    branch = branch_name(candidates)
    written = apply_edits(repo, fixes)
    if not written:
        return PullRequestResult(opened=False, branch=branch, note="No edits to commit.")

    base = base or os.environ.get("GITHUB_BASE_REF") or "main"
    steps = [
        ["git", "checkout", "-b", branch],
        ["git", "add", *written],
        ["git", "-c", "user.name=tainted", "-c", "user.email=tainted@localhost",
         "commit", "-m", _commit_message(candidates)],
        ["git", "push", "--set-upstream", "origin", branch],
    ]
    for step in steps:
        proc = runner(step, repo)
        if proc.returncode != 0:
            return PullRequestResult(
                opened=False,
                branch=branch,
                files_written=written,
                note=f"`{' '.join(step[:2])}` failed: {(proc.stderr or '').strip()[:300]}",
            )

    proc = runner(
        [
            "gh", "pr", "create",
            "--base", base,
            "--head", branch,
            "--title", _title(candidates),
            "--body", pr_body(candidates, fixes),
        ],
        repo,
    )
    if proc.returncode != 0:
        return PullRequestResult(
            opened=False,
            branch=branch,
            files_written=written,
            note=f"Branch pushed, but `gh pr create` failed: {(proc.stderr or '').strip()[:300]}",
        )
    return PullRequestResult(
        opened=True, branch=branch, url=(proc.stdout or "").strip(), files_written=written
    )


def _title(findings: list[Finding]) -> str:
    if len(findings) == 1:
        return f"Tainted: fix {findings[0].candidate.title}"
    return f"Tainted: fix {len(findings)} proven finding(s)"


def _commit_message(findings: list[Finding]) -> str:
    lines = [_title(findings), ""]
    for f in findings:
        lines.append(f"- {f.candidate.check.value}: {f.candidate.title} ({f.candidate.location})")
    return "\n".join(lines)


def pr_body(findings: list[Finding], fixes: list[FixResult]) -> str:
    """The PR body: what was open, the request that proved it, and what the fix re-proved."""
    lines = [
        "## 🩸 Tainted — proven findings, with fixes",
        "",
        "Each finding below was **proven by carrying out the attack** against this PR's preview "
        "deployment, not inferred. The fix is then re-verified against the same target.",
        "",
    ]
    fix_by_title = {f.finding.candidate.title: f for f in fixes}

    for finding in findings:
        cand = finding.candidate
        lines.append(f"### {cand.title}")
        lines.append(f"`{cand.location}` — severity **{cand.severity.value}**")
        lines.append("")

        proof = finding.proof
        if proof and proof.exploit and proof.exploit.url:
            lines += [
                "<details><summary>The request that proved it</summary>",
                "",
                "```http",
                f"{proof.exploit.method} {proof.exploit.url}",
                *[f"{k}: {v}" for k, v in proof.exploit.headers.items()],
                "```",
                "",
                f"> {proof.notes}",
                "",
                "</details>",
                "",
            ]

        fix = fix_by_title.get(cand.title)
        if fix and fix.assertions:
            lines.append("**Re-verification**")
            lines.append("")
            for a in fix.assertions:
                mark = "✅" if a.passed else "❌"
                lines.append(f"- {mark} `{a.name}` — {a.detail}")
            lines.append("")
            if fix.resulting_status is FindingStatus.BROKE_IT_SAFELY:
                lines.append(
                    "> ⚠️ **The attack is blocked but legitimate access broke too.** Secure and "
                    "broken. Do not merge as-is."
                )
                lines.append("")
        elif fix:
            lines.append(f"_{fix.notes}_")
            lines.append("")

    lines += [
        "---",
        "",
        "<sub>Both assertions matter: a policy that blocks the attacker *and* the real owner "
        "is secure and broken, so Tainted checks that account A can still read its own record "
        "before calling anything fixed.</sub>",
    ]
    return "\n".join(lines)
