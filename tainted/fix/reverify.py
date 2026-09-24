"""Checking that the fix actually worked, by running the attack again.

Request-plane fixes don't reshape anything, so Tainted just runs the same attack again and
checks two things: it fails, and the real owner can still read their own record. A policy
that locks out the real owner is broken even though it's secure.

Tool-plane fixes reshape the graph itself, so Tainted rebuilds the graph as the fix leaves it
and looks for the pairing again, wherever it now sits. That also catches a fix that moves the
hole somewhere else instead of closing it.
"""

from __future__ import annotations

from typing import Optional

import httpx

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
    # Only an attack that ran and was refused counts as blocked. A re-prove that never reached
    # the target (REPORTED) blocked nothing, and reading "not PROVEN" as success turned a dead
    # preview deploy into a FIXED verdict.
    attack_blocked = reproved.status is FindingStatus.NOT_REPRODUCED
    attack_rerun = reproved.status in (FindingStatus.PROVEN, FindingStatus.NOT_REPRODUCED)
    fix.assertions.append(
        ReverifyAssertion(
            name="attack_now_fails",
            passed=attack_blocked,
            detail=(
                (reproved.proof.notes if reproved.proof else "the probe returned no result")
                if attack_rerun
                else "The attack could not be re-run, so the fix is unverified: "
                + (reproved.proof.notes if reproved.proof else "the probe returned no result")
            ),
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

    if attack_rerun:
        fix.resulting_status = _classify(attack_blocked, legit_ok)
    else:
        # Unverified: the finding stands exactly as it did before the fix was written.
        fix.resulting_status = fix.finding.status
    fix.finding.status = fix.resulting_status
    return fix


def _legitimate_access_survives(
    setup: ProveSetup, replay: SupabaseReplay
) -> tuple[bool, str]:
    """As account A, read A's own seed row. It must still come back."""
    if setup.seed is None:
        return True, "No seed record supplied — legitimacy check skipped."
    try:
        replay.authenticate(setup.account_a)
        resp = replay.select_by_id(
            setup.account_a, setup.seed.table, setup.seed.id, id_column=setup.seed.id_column
        )
    except httpx.HTTPError as exc:
        return False, f"Account {setup.account_a.label}'s own read failed after the fix: {exc}"
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
# Tool plane: rebuild the graph as the fix leaves it, then look for the pairing
# --------------------------------------------------------------------------- #
def reverify_tool_plane(fix: FixResult, repo_path: Optional[str] = None) -> FixResult:
    """Rebuild the agent graph as it stands once the fix's edits are in, and re-check it.

    The graph is built in memory, never read back from disk after the fact: the fix's edits
    are new files the developer has not applied yet, so re-reading the repository would only
    re-find the hole the fix closes. It starts from the repository's scopes when one is given
    (or from the candidate's own scope when not), drops any scope an edit's file supersedes,
    adds the scopes the edits declare, and, for a scope split, retires the agent the split
    replaces.

    Roles come from the finding itself: analysis already decided which of these tools read
    untrusted content and which act, so no model is needed to ask again. Two checks follow:

      * the pairing is gone, or, for a fix that keeps it by design, a gate covers every sink;
      * the hole did not relocate: no other agent now holds one of these sources and one of
        these sinks. A split can fail this way, and a re-run attack would never notice.

    A gate is a runtime behavior the sandbox cannot run, so a gated fix whose config is
    complete is REPORTED, never FIXED: complete on paper, unproven in execution.
    """
    import json

    from tainted.fix.interview import ToolRemediation
    from tainted.static.tools import AgentScope, ToolSpec, discover_scopes, parse_mcp_manifest

    candidate = fix.finding.candidate
    scope_name = candidate.metadata.get("scope", "agent")
    sources = {t.strip() for t in (candidate.source or "").split(",") if t.strip()}
    sinks = {t.strip() for t in (candidate.sink or "").split(",") if t.strip()}
    roles = {**{n: "source" for n in sources}, **{n: "sink" for n in sinks}}
    remediation = fix.metadata.get("remediation")
    edited = {e.file for e in fix.edits}

    # ---- The graph before: the repository's scopes, or this one agent ---- #
    if repo_path is not None:
        scopes = [s for s in discover_scopes(repo_path) if s.source_file not in edited]
    else:
        scopes = [
            AgentScope(
                name=scope_name,
                kind=candidate.metadata.get("kind", "mcp"),
                source_file=candidate.location.file,
                tools=[ToolSpec(name=n) for n in sorted(sources | sinks)],
            )
        ]

    # ---- The graph after: the fix's own agents in, the split's original out ---- #
    gates: dict = {}
    added: list[AgentScope] = []
    for edit in fix.edits:
        try:
            data = json.loads(edit.replacement)
        except json.JSONDecodeError:
            continue
        if not isinstance(data, dict):
            continue
        if "tools" in data:
            added.extend(parse_mcp_manifest(data, edit.file))
        for key in ("mediation", "sink_confirmation", "provenance"):
            if isinstance(data.get(key), dict):
                gates[key] = data[key]
    if remediation == ToolRemediation.SCOPE_SPLIT.value and added:
        scopes = [
            s for s in scopes
            if not (s.name == scope_name and s.source_file == candidate.location.file)
        ]
    graph = [
        AgentScope(
            name=s.name,
            kind=s.kind,
            source_file=s.source_file,
            tools=[ToolSpec(name=t.name, role=roles.get(t.name)) for t in s.tools],
            coded=s.coded,
        )
        for s in scopes + added
    ]
    added_ids = {(s.name, s.source_file) for s in added}

    def pairs(s: AgentScope) -> bool:
        held = {t.name for t in s.tools}
        return bool(held & sources) and bool(held & sinks)

    original = [
        s for s in graph if s.name == scope_name and (s.name, s.source_file) not in added_ids
    ]
    original_ids = {id(s) for s in original}
    still_paired = any(pairs(s) for s in original)

    # ---- Check 1: the pairing is gone, or gated on every sink ---- #
    if not still_paired:
        fix.assertions.append(
            ReverifyAssertion(
                name="pairing_gone",
                passed=True,
                detail=(
                    f"In the graph the fix leaves, no single agent `{scope_name}` holds both "
                    f"{', '.join(sorted(sources))} and {', '.join(sorted(sinks))}. The pairing "
                    f"the attack depended on is gone."
                ),
            )
        )
    elif gates:
        uncovered = sorted(sinks - _gated_sinks(gates))
        unmarked = sorted(sources - set(gates.get("provenance", {}).get("taint_sources", sources)))
        missing = uncovered + unmarked
        fix.assertions.append(
            ReverifyAssertion(
                name="gate_covers_every_sink",
                passed=not missing,
                detail=(
                    f"`{scope_name}` keeps both tools by design, and the gate covers "
                    f"{', '.join(sorted(sinks))}."
                    if not missing
                    else f"`{scope_name}` keeps both tools, and the gate leaves "
                    f"{', '.join(missing)} ungated. The attack still has a way through."
                ),
            )
        )
    else:
        fix.assertions.append(
            ReverifyAssertion(
                name="pairing_gone",
                passed=False,
                detail=(
                    f"`{scope_name}` still holds {', '.join(sorted(sources))} and "
                    f"{', '.join(sorted(sinks))}, and nothing gates them."
                ),
            )
        )

    # ---- Check 2: the hole did not just move ---- #
    relocated = sorted({s.name for s in graph if pairs(s) and id(s) not in original_ids})
    searched = (
        "any agent in the repository"
        if repo_path is not None
        else "the agents this fix writes (no repository was given, so no others were searched)"
    )
    fix.assertions.append(
        ReverifyAssertion(
            name="hole_did_not_relocate",
            passed=not relocated,
            detail=(
                f"A new agent now holds both tools: {', '.join(relocated)}. The fix moved the "
                f"hole instead of closing it."
                if relocated
                else f"The pairing did not reappear in {searched}."
            ),
        )
    )

    if not fix.all_assertions_passed:
        fix.resulting_status = (
            FindingStatus.PROVEN
            if fix.finding.status is FindingStatus.PROVEN
            else FindingStatus.REPORTED
        )
    elif still_paired:
        # Gated, completely, on paper. Whether the gate holds is your runtime's to enforce, and
        # the sandbox cannot run it, so this is not a proof that the attack now fails.
        fix.resulting_status = FindingStatus.REPORTED
    else:
        fix.resulting_status = FindingStatus.FIXED
    fix.finding.status = fix.resulting_status
    return fix


def _gated_sinks(gates: dict) -> set[str]:
    """Every sink a gate config names, across the three gate shapes."""
    named: set[str] = set()
    named.update(gates.get("mediation", {}).get("require_human_approval", []))
    named.update(gates.get("sink_confirmation", {}).get("tools", []))
    named.update(gates.get("provenance", {}).get("guarded_sinks", []))
    return named
