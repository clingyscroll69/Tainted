"""Checking that the fix actually worked, by running the attack again.

Request-plane fixes don't reshape anything, so Tainted just runs the same attack again and
checks two things: it fails, and the real owner can still read their own record. A policy
that locks out the real owner is broken even though it's secure.

Tool-plane fixes can reshape the graph itself, so Tainted rebuilds the graph, finds the hole
in whatever form it now takes, and attacks that. This also catches a fix that moves the hole
somewhere else instead of closing it.
"""

from __future__ import annotations

from typing import Optional

from tainted.dynamic.probes import prove_candidate
from tainted.dynamic.replay import SupabaseReplay
from tainted.dynamic.route_probes import RouteProber
from tainted.dynamic.target import ProveSetup
from tainted.models import (
    Check,
    FindingStatus,
    FixResult,
    ReverifyAssertion,
)


# --------------------------------------------------------------------------- #
# Request plane: run the attack again, check both things
# --------------------------------------------------------------------------- #
def reverify_request_plane(
    fix: FixResult,
    setup: ProveSetup,
    replay: SupabaseReplay,
    prober: Optional[RouteProber] = None,
) -> FixResult:
    """Run the attack again against the fixed target and record both checks on the FixResult."""
    finding = fix.finding
    is_route = finding.check is Check.BOLA and finding.candidate.metadata.get("route_path")

    # Check 1: the attack now fails. Run it again through the same door it got through before.
    if is_route:
        prober = prober or RouteProber(setup)
        reproved = prober.prove_route_bola(finding.candidate)
    else:
        reproved = prove_candidate(finding.candidate, setup, replay)
    attack_blocked = reproved.status != FindingStatus.PROVEN
    fix.assertions.append(
        ReverifyAssertion(
            name="attack_now_fails",
            passed=attack_blocked,
            detail=(reproved.proof.notes if reproved.proof else "the probe returned no result"),
        )
    )

    # Check 2: the real owner can still read their own row.
    if is_route and prober is not None:
        legit_ok, legit_detail = prober.legitimate_access_survives()
    else:
        legit_ok, legit_detail = _legitimate_access_survives(setup, replay)
    fix.assertions.append(
        ReverifyAssertion(
            name="legitimate_access_survives", passed=legit_ok, detail=legit_detail
        )
    )

    fix.resulting_status = _classify(attack_blocked, legit_ok)
    fix.finding.status = fix.resulting_status
    return fix


def _legitimate_access_survives(
    setup: ProveSetup, replay: SupabaseReplay
) -> tuple[bool, str]:
    """As account A, read A's own seed row. It must still come back."""
    if setup.seed is None:
        return True, "No seed record supplied — legitimacy check skipped."
    replay.authenticate(setup.account_a)
    resp = replay.select_by_id(
        setup.account_a, setup.seed.table, setup.seed.id, id_column=setup.seed.id_column
    )
    rows = replay.rows(resp)
    got_own = resp.status_code == 200 and any(
        str(r.get(setup.seed.id_column)) == str(setup.seed.id) for r in rows
    )
    if got_own:
        return True, f"Account {setup.account_a.label} still reads its own row."
    return False, (
        f"Account {setup.account_a.label} can no longer read its own row "
        f"(status {resp.status_code}). The fix broke access for the real owner."
    )


def _classify(attack_blocked: bool, legit_ok: bool) -> FindingStatus:
    if attack_blocked and legit_ok:
        return FindingStatus.FIXED
    if attack_blocked and not legit_ok:
        return FindingStatus.BROKE_IT_SAFELY  # secure, but it also locked out the real owner
    return FindingStatus.PROVEN  # the attack still works, so this is not fixed


# --------------------------------------------------------------------------- #
# Tool plane: rebuild the graph, then attack it fresh
# --------------------------------------------------------------------------- #
def reverify_tool_plane(
    fix: FixResult,
    repo_path: str,
    llm=None,
    driver=None,
) -> FixResult:
    """Rebuild the graph from the fixed config and attack whatever it looks like now.

    A tool-plane fix can fail in a way a request-plane fix can't: it can move the hole
    instead of closing it. So the second check is not "legitimate access survives" but
    "no source-and-sink scope reappeared elsewhere in the graph."
    """
    from tainted.checks.tool_plane import analyze_tool_plane, colocated_scopes, label_scopes
    from tainted.dynamic.sandbox import run_sandbox
    from tainted.llm.client import LLMUnavailable
    from tainted.static.tools import discover_scopes

    original_scope = fix.finding.candidate.metadata.get("scope")

    # ---- Re-analyse: what does the graph look like now? ---- #
    scopes = discover_scopes(repo_path)
    if llm is not None:
        try:
            label_scopes(scopes, llm)
        except LLMUnavailable:
            llm = None
    colocated = colocated_scopes(scopes) if llm is not None else []

    still_colocated = [s for s in colocated if s.name == original_scope]
    relocated = [s for s in colocated if s.name != original_scope]

    # ---- Check 1: a fresh attack on the reshaped graph fails ---- #
    if llm is None:
        fix.assertions.append(
            ReverifyAssertion(
                name="fresh_attack_fails",
                passed=False,
                detail=(
                    "No model was available to re-check the reshaped graph or build a fresh "
                    "attack, so this fix is unverified. That does not mean it is wrong. It "
                    "means Tainted has not checked, which is the honest thing to say."
                ),
            )
        )
        fix.resulting_status = FindingStatus.REPORTED
        return fix

    if not still_colocated:
        fix.assertions.append(
            ReverifyAssertion(
                name="fresh_attack_fails",
                passed=True,
                detail=(
                    f"Agent `{original_scope}` no longer holds both tools. The pairing the "
                    f"attack depended on is gone."
                ),
            )
        )
    else:
        scope = still_colocated[0]
        candidates = analyze_tool_plane(repo_path, llm=llm)
        fresh = [c for c in candidates if c.metadata.get("scope") == original_scope]
        if not fresh:
            fix.assertions.append(
                ReverifyAssertion(
                    name="fresh_attack_fails",
                    passed=True,
                    detail="This scope no longer looks attackable after the fix.",
                )
            )
        else:
            try:
                injection = llm.generate_injection(
                    {
                        "scope": scope.name,
                        "sources": [t.as_prompt_dict() for t in scope.sources],
                        "sinks": [t.as_prompt_dict() for t in scope.sinks],
                    }
                )
                result = run_sandbox(fresh[0], scope, injection, driver) if driver else None
            except LLMUnavailable:
                result = None
            if result is None:
                fix.assertions.append(
                    ReverifyAssertion(
                        name="fresh_attack_fails",
                        passed=False,
                        detail="Could not run a fresh attack, so this fix is unverified.",
                    )
                )
            else:
                blocked = result.status != FindingStatus.PROVEN
                fix.assertions.append(
                    ReverifyAssertion(
                        name="fresh_attack_fails",
                        passed=blocked,
                        detail=(result.proof.notes if result.proof else ""),
                    )
                )

    # ---- Check 2: the hole did not just move ---- #
    new_names = {s.name for s in relocated}
    fix.assertions.append(
        ReverifyAssertion(
            name="hole_did_not_relocate",
            passed=not new_names,
            detail=(
                f"A new agent now holds both tools: {', '.join(sorted(new_names))}. "
                f"The fix moved the hole instead of closing it."
                if new_names
                else "No other agent picked up both tools."
            ),
        )
    )

    fix.resulting_status = (
        FindingStatus.FIXED if fix.all_assertions_passed else FindingStatus.PROVEN
    )
    fix.finding.status = fix.resulting_status
    return fix
