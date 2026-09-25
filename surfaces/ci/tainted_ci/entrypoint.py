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
import subprocess
import sys

from tainted import analyze as core_analyze
from tainted import prove as core_prove
from tainted.dynamic.target import Account, ProveSetup, SeedRecord, Target
from tainted.llm.gemini import get_default_client
from tainted.models import Check, FindingStatus, Severity
from tainted.report import build_report
from tainted_ci.oidc import verify_ci_ownership
from tainted_ci.render import (
    render_invariants,
    render_lockout,
    render_markdown,
    render_next_steps,
    render_tutorial,
)


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


def _changed_files(repo: str, base_ref: str) -> set[str]:
    """Files changed against a base ref, via `git diff --name-only`. Empty set on any failure.

    Diff-awareness is opt-in and fails open: if git is unavailable or the base ref cannot be
    resolved, the scan stays whole-repo rather than silently narrowing to nothing, because a
    scan that quietly covered no files is the exact false all-clear this tool exists to avoid.
    """
    try:
        proc = subprocess.run(
            ["git", "-C", repo, "diff", "--name-only", f"{base_ref}...HEAD"],
            capture_output=True, text=True, timeout=60,
        )
    except (OSError, subprocess.SubprocessError):
        return set()
    if proc.returncode != 0:
        return set()
    return {line.strip() for line in proc.stdout.splitlines() if line.strip()}


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

    # Diff-awareness (opt-in). With TAINTED_DIFF_ONLY set and a base ref available, keep only the
    # candidates whose file the PR actually touched — so the gate speaks to this change, not the
    # whole repository's history. Fails open: an unresolvable diff leaves every candidate in.
    if os.environ.get("TAINTED_DIFF_ONLY", "").lower() in ("1", "true", "yes"):
        base_ref = os.environ.get("TAINTED_DIFF_BASE") or os.environ.get("GITHUB_BASE_REF", "")
        if base_ref:
            changed = _changed_files(repo, base_ref)
            if changed:
                result.candidates = [
                    c for c in result.candidates if c.location.file in changed
                ]

    findings = []

    prove_note = "prove skipped: no TAINTED_TARGET_URL"
    # Every request this job sends to the target is gated on this, not only prove's: the
    # invariant and lockout checks below fire at the same app.
    verified = False
    if setup is not None:
        verified = setup.target.is_local
        detail = "local target"
        if not verified:
            ownership = verify_ci_ownership()
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

    # SARIF for the Security tab, when asked. Proof strength rides on each result's level and the
    # silence ledger rides on the run's properties, so an empty results array is never read as
    # full coverage.
    sarif_path = os.environ.get("TAINTED_SARIF", "").strip()
    if sarif_path:
        from tainted.report.sarif import to_sarif_json

        try:
            with open(sarif_path, "w", encoding="utf-8") as fh:
                fh.write(to_sarif_json(report))
            print(f"::notice::Tainted wrote SARIF to {sarif_path}")
        except OSError as exc:
            print(f"::warning::could not write SARIF to {sarif_path}: {exc}")

    # A signed receipt for this run, when asked. The untested surface sits inside the signed
    # payload, so a downstream consumer cannot publish the findings with the admissions removed
    # and still have it verify.
    receipt_path = os.environ.get("TAINTED_RECEIPT", "").strip()
    if receipt_path:
        import json as _json

        from tainted.receipt import build_receipt, sign as _sign_receipt

        secret = os.environ.get("TAINTED_RECEIPT_SECRET", "")
        rec = build_receipt(report)
        signature = _sign_receipt(rec, secret.encode("utf-8")) if secret else None
        try:
            with open(receipt_path, "w", encoding="utf-8") as fh:
                fh.write(_json.dumps(rec.as_dict(signature), indent=2))
            if signature is None:
                print(
                    f"::warning::Tainted wrote an UNSIGNED receipt to {receipt_path} (set "
                    f"TAINTED_RECEIPT_SECRET to sign it). It is a report, not an attestation."
                )
            else:
                print(f"::notice::Tainted wrote a signed receipt to {receipt_path}")
        except OSError as exc:
            print(f"::warning::could not write the receipt to {receipt_path}: {exc}")

    # Rules the repository states about itself, in plain English, fired at the running app. Only
    # when there is a target to fire at — a rule nobody tested comes back not-tested, never held.
    invariant_report = None
    rules_raw = os.environ.get("TAINTED_INVARIANTS", "").strip()
    if rules_raw and setup is not None:
        from tainted.invariants import check_invariants

        rules = [r.strip() for r in rules_raw.replace("|", chr(10)).split(chr(10)) if r.strip()]
        if rules:
            invariant_report = check_invariants(
                rules, repo, setup, llm=llm, ownership_verified=verified
            )

    # Did this change lock the owner out of their own data? Asked only when a seed record makes
    # the answer meaningful.
    lockout_result = None
    if os.environ.get("TAINTED_LOCKOUT", "").lower() in ("1", "true", "yes") and setup is not None:
        from tainted import lockout_check

        lockout_result = lockout_check(setup, ownership_verified=verified)

    markdown = render_markdown(report, prove_note)
    if invariant_report is not None:
        markdown += chr(10) * 2 + render_invariants(invariant_report) + chr(10)
    if lockout_result is not None:
        markdown += chr(10) * 2 + render_lockout(lockout_result) + chr(10)
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
    # A rule the repository declared about itself, broken by a fired request, is as much a gate as
    # a proven finding — it IS a proven finding, aimed by a sentence instead of by a scan.
    if invariant_report is not None and invariant_report.violated:
        print(
            f"::error::Tainted broke {len(invariant_report.violated)} stated rule(s) with a real "
            f"request."
        )
        return 1
    # Locking the owner out fails the build too: a change that secures the data by making it
    # unreachable has not shipped a working feature.
    if lockout_result is not None and lockout_result.locked_out:
        print(
            f"::error::Tainted found {len(lockout_result.locked_out)} resource(s) the owner can "
            f"no longer reach. Secure and broken are not the same result."
        )
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
