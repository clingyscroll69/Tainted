"""CI entrypoint — analyze, prove against the preview, and emit a report + gate.

Configuration is by environment (so it works uniformly in GitHub Actions and GitLab CI):

  TAINTED_REPO           repository path (default: cwd)
  TAINTED_TARGET_URL     the running preview deploy URL (enables prove)
  TAINTED_ANON_KEY       Supabase anon key (optional)
  TAINTED_LOGIN_A/B      "email:password" for the two accounts (enables BOLA proof)
  TAINTED_SEED           "table:id" seed record (enables the targeted probe)
  TAINTED_OIDC_TOKEN     OIDC identity token (ownership for a non-local target)
  TAINTED_FAIL_ON        minimum severity that fails the job (default: high)
  TAINTED_ONLY           comma-separated checks to run, and nothing else (test_integrity is
                         opt-in: it runs only when named here)
  TAINTED_SKIP           comma-separated checks to leave out
  TAINTED_FIX            "1" to open a PR with the deterministic fixes; the PR's own
                         preview deploy re-proves them
  TAINTED_TUTORIAL       "1" to print the setup walkthrough and exit without scanning
                         (or a topic slug, to print just that lesson)
  GITHUB_STEP_SUMMARY    if set, the markdown report is appended there
  GEMINI_API_KEY         optional; enables the meaning register

Exit code is non-zero when a finding at/above TAINTED_FAIL_ON is proven — a red pipeline is the
catch nobody asked for.
"""

from __future__ import annotations

import os
import sys

from tainted import analyze as core_analyze
from tainted import prove as core_prove
from tainted.dynamic.target import Account, ProveSetup, SeedRecord, Target
from tainted.llm.gemini import get_default_client
from tainted.models import Check, FindingStatus, Severity
from tainted.report import build_report
from tainted_ci.oidc import verify_github_ownership
from tainted_ci.render import render_markdown, render_next_steps, render_tutorial


def _llm_or_none():
    llm = get_default_client(reload=True)
    return llm if llm.available else None


def _checks_from_env(name: str) -> set[Check] | None:
    """A comma-separated check list, or None when unset. Raises ValueError naming the stray."""
    tokens = [t.strip().lower() for t in os.environ.get(name, "").split(",") if t.strip()]
    if not tokens:
        return None
    out: set[Check] = set()
    for token in tokens:
        try:
            out.add(Check(token))
        except ValueError:
            raise ValueError(
                f"{name}: unknown check '{token}'. Choose from: "
                + ", ".join(c.value for c in Check)
            ) from None
    return out


def _setup_from_env() -> ProveSetup | None:
    url = os.environ.get("TAINTED_TARGET_URL", "").strip()
    if not url:
        return None
    login_a = os.environ.get("TAINTED_LOGIN_A", "")
    login_b = os.environ.get("TAINTED_LOGIN_B", "")
    seed = os.environ.get("TAINTED_SEED", "")

    def _acct(label, spec):
        email, _, pw = spec.partition(":")
        return Account(label=label, email=email, password=pw)

    seed_record = None
    if seed:
        table, _, rid = seed.partition(":")
        seed_record = SeedRecord(table=table, id=rid)

    return ProveSetup(
        target=Target(url=url, anon_key=os.environ.get("TAINTED_ANON_KEY") or None),
        account_a=_acct("A", login_a),
        account_b=_acct("B", login_b),
        seed=seed_record,
    )


def run() -> int:
    # A pipeline that is not configured yet has nothing to scan worth reading. Let it ask
    # for the walkthrough instead, from inside the same container the job already runs.
    wanted = os.environ.get("TAINTED_TUTORIAL", "").strip().lower()
    if wanted and wanted not in ("0", "false", "no"):
        print(render_tutorial(None if wanted in ("1", "true", "yes") else wanted))
        return 0

    repo = os.environ.get("TAINTED_REPO", ".")
    raw_fail_on = os.environ.get("TAINTED_FAIL_ON", "high").strip().lower()
    try:
        fail_on = Severity(raw_fail_on)
    except ValueError:
        # Same reason as a misspelt check below: a gate that cannot read its threshold must
        # say so, not die on a traceback nobody reads as a configuration error.
        print(
            f"::error::TAINTED_FAIL_ON: unknown severity '{raw_fail_on}'. Choose from: "
            + ", ".join(s.value for s in Severity)
        )
        return 2
    try:
        only = _checks_from_env("TAINTED_ONLY")
        skip = _checks_from_env("TAINTED_SKIP")
    except ValueError as exc:
        # A misspelt check must not quietly widen or narrow the scan; the gate would then pass
        # on work it never did.
        print(f"::error::{exc}")
        return 2
    llm = _llm_or_none()

    setup = _setup_from_env()
    result = core_analyze(
        repo, llm=llm, target=setup.target if setup else None, only=only, skip=skip
    )
    findings = []

    prove_note = "prove skipped: no TAINTED_TARGET_URL"
    if setup is not None:
        verified = setup.target.is_local
        detail = "local target"
        if not verified:
            ownership = verify_github_ownership(setup.target, asserted_url=setup.target.url)
            verified = bool(ownership)
            detail = ownership.detail
        if verified:
            findings = core_prove(result, setup, ownership_verified=True, llm=llm)
            prove_note = f"proved against {setup.target.url} ({detail})"
        else:
            prove_note = f"prove refused: ownership not verified ({detail})"

    # Write the fix and propose it as a reviewable change. Its proof comes from its own preview:
    # the fix PR's CI deploys the patched app and this job proves against it again.
    fix_note = ""
    if os.environ.get("TAINTED_FIX", "").lower() in ("1", "true", "yes") and findings:
        fix_note = _open_fix_pr(repo, findings, setup)

    report = build_report(result, findings)
    markdown = render_markdown(report, prove_note)
    if fix_note:
        markdown += f"\n\n{fix_note}\n"
    # Say what this run could not reach, and what to set to reach it. A summary with no
    # proof column reads as a clean bill of health when it may only mean nothing was tried.
    markdown += "\n\n" + render_next_steps(_gap(setup, findings, prove_note)) + "\n"
    _emit(markdown)

    blocking = [
        f
        for f in findings
        if f.status == FindingStatus.PROVEN and f.severity.rank >= fail_on.rank
    ]
    if blocking:
        print(f"::error::Tainted proved {len(blocking)} finding(s) at/above {fail_on.value}.")
        return 1
    # If nothing was proved but static candidates are severe, still gate (analyze-only PRs).
    if not findings:
        severe = [c for c in result.candidates if c.severity.rank >= fail_on.rank]
        if severe:
            print(f"::warning::{len(severe)} static candidate(s) at/above {fail_on.value}.")
    return 0


def _gap(setup: ProveSetup | None, findings, prove_note: str) -> str:
    """Which rung of the setup this run stopped at — the key into the next-steps text."""
    if setup is None:
        return "no_target"
    if prove_note.startswith("prove refused"):
        return "ownership_refused"
    if not setup.account_a.email or not setup.account_b.email:
        return "no_accounts"
    return "all_configured"


def _open_fix_pr(repo: str, findings, setup) -> str:
    """Generate deterministic fixes and open one PR carrying the evidence of the hole."""
    from tainted import fix as core_fix
    from tainted_ci.pull_request import eligible, open_pull_request

    targets = eligible(findings)
    if not targets:
        return (
            "<sub>Auto-fix: nothing eligible. Only *proven* findings with a fix the code fully "
            "determines are opened as PRs; tool-plane fixes need a human to answer the "
            "interview first.</sub>"
        )

    # Not re-proved here: this run's preview is the unfixed app, so the attack would only
    # succeed again. The fix PR's own preview is the patched app, and its run is the proof.
    fixes = [core_fix(finding) for finding in targets]

    try:
        result = open_pull_request(repo, findings, fixes)
    except ValueError as exc:  # an edit whose path would leave the checkout
        return f"<sub>Auto-fix: no PR opened — {exc}</sub>"
    if result.opened:
        return f"<sub>Auto-fix: opened {result.url} on `{result.branch}`.</sub>"
    return f"<sub>Auto-fix: no PR opened — {result.note}</sub>"


def _emit(markdown: str) -> None:
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_path:
        with open(summary_path, "a", encoding="utf-8") as fh:
            fh.write(markdown + "\n")
    print(markdown)


def main() -> None:
    sys.exit(run())


if __name__ == "__main__":
    main()
