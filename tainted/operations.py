"""Composed operations, each built from the three the engine already has.

`analyze` / `prove` / `fix` are the primitives. The features below are compositions of them, kept
here so the orchestrator stays the three-operation spine and every surface imports one place:

  * `preflight`        — refuse to prove until the setup is sound, naming the failed check (A2),
                         including the positive control: A must be able to read A's own record
                         before B's attack on it means anything (B7).
  * `reprove`          — re-fire one finding's exploit on demand, decoupled from patching (A1).
  * `second_opinion`   — prove a patched target with the original exploit: still open, fixed, or
                         secured-but-broken (B2). Same machinery as reprove, different framing.
  * `regression_check` — run the repo's own suite before and after a patch, so FIXED can mean
                         "attack closed AND nothing else broke" (A7).
  * `pairing_diff`     — the new source+sink co-locations a change introduced (B5).
  * `completion_gate`  — a pass/block verdict for a coding agent: no new PROVEN hole (B8).
  * `lockout_check`    — the inverse question, asked on its own: did the policy stop the *owner*?
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Sequence

import httpx

from tainted.checks.test_integrity import CommandRunner, _default_runner
from tainted.dynamic.replay import SupabaseReplay
from tainted.dynamic.route_probes import RouteProber
from tainted.dynamic.target import ProveSetup
from tainted.models import Candidate, Check, Finding, FindingStatus, Severity


# --------------------------------------------------------------------------- #
# A2 / B7 — preflight
# --------------------------------------------------------------------------- #
@dataclass
class PreflightCheck:
    name: str
    passed: bool
    detail: str


@dataclass
class PreflightResult:
    checks: list[PreflightCheck] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return all(c.passed for c in self.checks)

    def first_failure(self) -> Optional[PreflightCheck]:
        return next((c for c in self.checks if not c.passed), None)

    def as_dict(self) -> dict:
        fail = self.first_failure()
        blocking = None if fail is None else {"name": fail.name, "detail": fail.detail}
        return {
            "ok": self.ok,
            "checks": [{"name": c.name, "passed": c.passed, "detail": c.detail} for c in self.checks],
            "blocking": blocking,
        }


def preflight(
    setup: ProveSetup,
    ownership_verified: bool,
    replay: Optional[SupabaseReplay] = None,
    prober: Optional[RouteProber] = None,
    repo_path: Optional[str] = None,
) -> PreflightResult:
    """Check the run is sound before any exploit fires, and name the check that isn't.

    The most valuable check is the positive control (B7): if account A cannot read A's own seed
    record, the target is broken or misconfigured, and a subsequent 'B could not read it either'
    would be filed as NOT_REPRODUCED — a false all-clear. Running it first turns that false
    negative into a named, actionable preflight failure.
    """
    result = PreflightResult()

    # 1. Ownership — the gate must already have been cleared for a non-local target.
    if setup.target.is_local or ownership_verified:
        result.checks.append(
            PreflightCheck("ownership", True, "local target or ownership verified")
        )
    else:
        result.checks.append(
            PreflightCheck(
                "ownership",
                False,
                "non-local target without verified ownership — prove will refuse it",
            )
        )
        return result  # no point probing a target we may not touch

    # 2. Reachability — can we open a connection at all?
    prober = prober or RouteProber(setup)
    try:
        base = setup.target.url.rstrip("/")
        prober._client.get(base, timeout=10.0)
        result.checks.append(PreflightCheck("reachable", True, f"connected to {base}"))
    except httpx.HTTPError as exc:
        result.checks.append(
            PreflightCheck("reachable", False, f"could not reach {setup.target.url}: {exc}")
        )
        return result

    # 3. Baseline auth — can account B authenticate at all? (Only when credentials were given.)
    if setup.account_b.email or setup.account_b.access_token:
        try:
            (replay or SupabaseReplay(setup.target, prober._client)).authenticate(setup.account_b)
            result.checks.append(PreflightCheck("auth_b", True, "account B authenticated"))
        except Exception as exc:  # noqa: BLE001 - auth against an unknown app fails many ways
            result.checks.append(
                PreflightCheck("auth_b", False, f"account B could not authenticate: {exc}")
            )
    else:
        result.checks.append(
            PreflightCheck("auth_b", True, "no credentials supplied — auth check skipped")
        )

    # 4. Positive control (B7): A must be able to read A's own record. If not, the target is
    # broken, and any BOLA result that follows would be meaningless.
    seed = setup.seed
    if seed is not None and (setup.account_a.email or setup.account_a.access_token):
        route, _source = _owner_route(setup, repo_path)
        ok, detail = _positive_control(setup, prober, replay, route)
        result.checks.append(PreflightCheck("positive_control", ok, detail))
    else:
        result.checks.append(
            PreflightCheck(
                "positive_control",
                True,
                "no seed record or account A credentials — positive control skipped",
            )
        )
    return result


def _positive_control(
    setup: ProveSetup,
    prober: RouteProber,
    replay: Optional[SupabaseReplay],
    route: Optional[str] = None,
) -> tuple[bool, str]:
    """As account A, read A's own seed record. It must come back, or nothing downstream is sound."""
    seed = setup.seed
    assert seed is not None  # caller only invokes this when a seed record exists
    route = route or seed.route_path
    if route:
        try:
            url = prober.build_url(route, seed.id)
            resp = prober.request("GET", url, setup.account_a)
        except httpx.HTTPError as exc:
            return False, f"account A's own request failed: {exc}"
        if prober._response_carries_seed(resp, seed.id):
            return True, "account A reads its own record — the boundary test is meaningful"
        return False, (
            f"account A cannot read its own record (status {resp.status_code}). The target is "
            f"broken or the seed is wrong; a BOLA result here would be meaningless."
        )
    # PostgREST path.
    if not _speaks_postgrest(setup):
        return True, (
            "no seed route and no anon key, so there is no door to ask through — positive "
            "control skipped"
        )
    rep = replay or SupabaseReplay(setup.target, prober._client)
    try:
        rep.authenticate(setup.account_a)
        resp = rep.select_by_id(setup.account_a, seed.table, seed.id, id_column=seed.id_column)
    except Exception as exc:  # noqa: BLE001
        return False, f"account A's own read failed: {exc}"
    rows = rep.rows(resp)
    if resp.status_code == 200 and any(str(r.get(seed.id_column)) == str(seed.id) for r in rows):
        return True, "account A reads its own record via PostgREST"
    return False, (
        f"account A cannot read its own record via PostgREST (status {resp.status_code}). "
        f"The BOLA result would be meaningless."
    )


# --------------------------------------------------------------------------- #
# A1 / B2 — reprove and second opinion
# --------------------------------------------------------------------------- #
@dataclass
class ReproveResult:
    finding_id: str
    status: FindingStatus
    detail: str
    attack_blocked: bool
    legitimate_access_ok: Optional[bool] = None

    def as_dict(self) -> dict:
        return {
            "finding_id": self.finding_id,
            "status": self.status.value,
            "detail": self.detail,
            "attack_blocked": self.attack_blocked,
            "legitimate_access_ok": self.legitimate_access_ok,
        }


def _refire(finding: Finding, setup: ProveSetup, prober: RouteProber, replay: SupabaseReplay) -> Finding:
    """Re-run exactly the probe this finding's check uses."""
    from tainted.dynamic.injection_probes import prove_sql_injection
    from tainted.dynamic.probes import prove_candidate

    cand = finding.candidate
    if cand.check is Check.BOLA and cand.metadata.get("route_path"):
        return prober.prove_route_bola(cand)
    if cand.check is Check.CLASSIC_INJECTION:
        return prove_sql_injection(cand, setup, prober)
    return prove_candidate(cand, setup, replay)


def reprove(
    finding: Finding,
    setup: ProveSetup,
    ownership_verified: bool = False,
    prober: Optional[RouteProber] = None,
    replay: Optional[SupabaseReplay] = None,
) -> ReproveResult:
    """Re-fire one finding's exploit on demand, decoupled from patching.

    This is the primitive behind a per-finding revalidation timeline (proven -> fixed ->
    proven-again is a regression) and behind `second_opinion`. It classifies with the same
    three-valued logic the fix loop uses: the attack now failing plus legitimate access surviving
    is FIXED, the attack failing but the owner locked out is BROKE_IT_SAFELY, the attack still
    landing is PROVEN.
    """
    if not setup.target.is_local and not ownership_verified:
        return ReproveResult(
            finding.candidate.id,
            FindingStatus.REPORTED,
            "non-local target without verified ownership — refused to re-fire",
            attack_blocked=False,
        )
    prober = prober or RouteProber(setup)
    replay = replay or SupabaseReplay(setup.target, prober._client)
    refired = _refire(finding, setup, prober, replay)
    attack_blocked = refired.status != FindingStatus.PROVEN

    if not attack_blocked:
        return ReproveResult(
            finding.candidate.id, FindingStatus.PROVEN,
            "the original exploit still lands", attack_blocked=False,
        )

    # REPORTED from a probe means the attack was not asked, not that it failed: a write held
    # back, no seed, an unreachable target. Only a sent-and-refused request is "blocked".
    proof = refired.proof
    sent = bool(proof and proof.exploit and proof.exploit.executed)
    if refired.status is FindingStatus.REPORTED and not sent:
        why = proof.notes if proof and proof.notes else "the probe returned no result"
        return ReproveResult(
            finding.candidate.id, FindingStatus.REPORTED,
            f"the exploit was not re-fired, so nothing is known about the fix: {why}",
            attack_blocked=False,
        )

    # The attack no longer works. Is legitimate access intact?
    is_route = finding.check is Check.BOLA and finding.candidate.metadata.get("route_path")
    legit_ok: Optional[bool]
    if is_route:
        # The route probe already asked as A through the same URL once B was refused: it
        # says NOT_REPRODUCED only when A still reads the record, REPORTED when A cannot.
        legit_ok = refired.status is FindingStatus.NOT_REPRODUCED
        legit_detail = proof.notes if proof else ""
    else:
        legit_ok, legit_detail = _legit_via_postgrest(setup, replay)

    if legit_ok is None:
        # The attack ran and held, and nobody asked whether the owner still gets in. That is
        # NOT_REPRODUCED, not FIXED: FIXED claims both halves.
        status = FindingStatus.NOT_REPRODUCED
    else:
        status = FindingStatus.FIXED if legit_ok else FindingStatus.BROKE_IT_SAFELY
    return ReproveResult(
        finding.candidate.id, status,
        f"attack no longer lands; {legit_detail}",
        attack_blocked=True, legitimate_access_ok=legit_ok,
    )


def _owner_route(setup: ProveSetup, repo_path: Optional[str]) -> tuple[Optional[str], str]:
    """The app route the seed record is served through, and where that answer came from.

    A route the caller named wins. Otherwise it is read off the code: the one GET route whose
    single path identifier reaches a read of the seed's table. No route found is said, not
    papered over, because the owner's own door is the stronger half of the question.
    """
    seed = setup.seed
    if seed is None:
        return None, "no seed record"
    if seed.route_path:
        return seed.route_path, "named with the seed"
    if repo_path is None:
        return None, "no route named with the seed, and no repository to read one from"
    from tainted.static.routes import route_for_table

    route, why = route_for_table(repo_path, seed.table)
    return (route.path if route else None), why


def _speaks_postgrest(setup: ProveSetup) -> bool:
    """Whether PostgREST is a door this target has. Without the anon key the browser sends,
    there is none to ask through, and a refusal there says nothing about the owner."""
    return bool(setup.target.anon_key)


def _legit_via_postgrest(
    setup: ProveSetup, replay: SupabaseReplay
) -> tuple[Optional[bool], str]:
    """Whether A still reads its own row via PostgREST: True, False, or None for not asked."""
    if setup.seed is None:
        return None, "no seed supplied, so the owner's access was not checked"
    if not _speaks_postgrest(setup):
        return None, (
            "no anon key, so this is not a PostgREST target and the owner's access there was "
            "not checked"
        )
    try:
        replay.authenticate(setup.account_a)
        resp = replay.select_by_id(
            setup.account_a, setup.seed.table, setup.seed.id, id_column=setup.seed.id_column
        )
    except Exception as exc:  # noqa: BLE001
        return False, f"account A's own read failed: {exc}"
    rows = replay.rows(resp)
    ok = resp.status_code == 200 and any(
        str(r.get(setup.seed.id_column)) == str(setup.seed.id) for r in rows
    )
    return ok, ("account A still reads its own row" if ok else "account A lost access to its own row")


def second_opinion(
    finding: Finding,
    setup: ProveSetup,
    ownership_verified: bool = False,
    prober: Optional[RouteProber] = None,
    replay: Optional[SupabaseReplay] = None,
) -> ReproveResult:
    """Fire a previously-proven exploit at a patched target (a branch, someone else's autofix).

    Mechanically identical to `reprove`; named separately because the use is different — the
    patch came from outside Tainted, and the question is whether it actually closed the hole or
    merely cleared its author's own scanner. The answer is the three-valued verdict, backed by a
    fired exploit rather than a re-scan.
    """
    return reprove(finding, setup, ownership_verified, prober, replay)


# --------------------------------------------------------------------------- #
# A7 — regression gate
# --------------------------------------------------------------------------- #
@dataclass
class RegressionResult:
    ran: bool
    suite_passed_before: Optional[bool]
    suite_passed_after: Optional[bool]
    detail: str

    @property
    def regressed(self) -> bool:
        """A regression is a suite that passed before the patch and fails after it."""
        return bool(self.suite_passed_before and self.suite_passed_after is False)

    def as_dict(self) -> dict:
        return {
            "ran": self.ran,
            "suite_passed_before": self.suite_passed_before,
            "suite_passed_after": self.suite_passed_after,
            "regressed": self.regressed,
            "detail": self.detail,
        }


def regression_check(
    repo_path: str,
    edits: Sequence,
    test_cmd: Optional[list[str]] = None,
    runner: Optional[CommandRunner] = None,
) -> RegressionResult:
    """Run the repo's own suite before and after applying a fix's edits, then restore the files.

    This is the half the exploit re-fire cannot see: a patch can close the hole and break an
    unrelated feature. With it, FIXED can mean 'attack closed AND nothing else broke'. With no
    test command the check is skipped rather than assumed green — an un-run suite never reads as
    a passed one.
    """
    if not test_cmd:
        return RegressionResult(False, None, None, "no test command supplied; suite not run")
    runner = runner or _default_runner
    before = runner(test_cmd, repo_path)
    if before.tool_missing:
        return RegressionResult(False, None, None, "test tool not found; suite not run")
    passed_before = before.returncode == 0

    originals: dict[str, Optional[str]] = {}
    root = Path(repo_path)
    try:
        for edit in edits:
            fpath = root / edit.file
            try:
                originals[edit.file] = fpath.read_text(encoding="utf-8")
            except OSError:
                originals[edit.file] = None
            fpath.parent.mkdir(parents=True, exist_ok=True)
            fpath.write_text(edit.replacement, encoding="utf-8")
        after = runner(test_cmd, repo_path)
    finally:
        for fname, original in originals.items():
            fpath = root / fname
            try:
                if original is None:
                    fpath.unlink(missing_ok=True)
                else:
                    fpath.write_text(original, encoding="utf-8")
            except OSError:
                pass
    passed_after = after.returncode == 0
    if passed_before and not passed_after:
        detail = "the suite passed before the patch and fails after it — the fix broke something"
    elif not passed_before:
        detail = "the suite was already failing before the patch; regression undecidable"
    else:
        detail = "the suite still passes after the patch"
    return RegressionResult(True, passed_before, passed_after, detail)


# --------------------------------------------------------------------------- #
# B5 — capability pairing diff
# --------------------------------------------------------------------------- #
@dataclass
class PairingDiff:
    new_pairings: list[dict] = field(default_factory=list)

    @property
    def introduced_danger(self) -> bool:
        return bool(self.new_pairings)

    def as_dict(self) -> dict:
        return {
            "introduced_danger": self.introduced_danger,
            "new_pairings": self.new_pairings,
            "note": (
                f"{len(self.new_pairings)} new source-and-sink co-location(s) this change "
                f"introduced — an agent that could not be turned before now can be."
                if self.new_pairings
                else "No new dangerous capability pairing introduced by this change."
            ),
        }


def pairing_diff(base_analysis, head_analysis) -> PairingDiff:
    """The agent scopes co-located in head but not in base — the pairings a change introduced.

    Deterministic given two analyses: it compares the set of tool-plane candidate scopes. It is
    honestly scoped to the repository-declared graph, and says so — a pairing that closes because
    a developer installs a server locally, or because a server rug-pulls its own tool set, does
    not pass through a diff and is out of reach here.
    """
    def scopes(analysis) -> dict[str, Candidate]:
        return {
            c.metadata.get("scope", c.title): c
            for c in analysis.candidates
            if c.check is Check.AGENT_INJECTION
        }

    base = scopes(base_analysis)
    head = scopes(head_analysis)
    new = []
    for name, cand in head.items():
        if name not in base:
            new.append(
                {
                    "scope": name,
                    "title": cand.title,
                    "source": cand.source,
                    "sink": cand.sink,
                    "severity": cand.severity.value,
                }
            )
    return PairingDiff(new_pairings=new)


# --------------------------------------------------------------------------- #
# B8 — completion gate
# --------------------------------------------------------------------------- #
@dataclass
class GateResult:
    passed: bool
    blocking: list[dict] = field(default_factory=list)
    detail: str = ""

    def as_dict(self) -> dict:
        return {"passed": self.passed, "blocking": self.blocking, "detail": self.detail}


def completion_gate(findings: list[Finding], fail_on: Severity = Severity.HIGH) -> GateResult:
    """Block task completion on any PROVEN finding at or above `fail_on`.

    The verdict a coding-agent hook consults: the agent may not mark the task done while an
    exploit it just made possible actually lands. Only PROVEN findings block — a static suspicion
    is not grounds to stop work, which is the distinction that keeps the gate from crying wolf.
    """
    blocking = [
        {
            "id": f.candidate.id,
            "title": f.candidate.title,
            "check": f.check.value,
            "severity": f.severity.value,
        }
        for f in findings
        if f.status == FindingStatus.PROVEN and f.severity.rank >= fail_on.rank
    ]
    if blocking:
        return GateResult(
            passed=False,
            blocking=blocking,
            detail=(
                f"{len(blocking)} proven hole(s) at or above {fail_on.value}. The exploit lands "
                f"against the code as written; the task is not done until it fails."
            ),
        )
    return GateResult(passed=True, detail="No proven hole at or above the threshold.")


# --------------------------------------------------------------------------- #
# Lockout — the inverse question, asked on its own
# --------------------------------------------------------------------------- #
@dataclass
class LockoutFinding:
    """One resource the legitimate owner can no longer reach."""

    resource: str  # the route or table the owner was tested against
    via: str  # "route" | "postgrest"
    owner_locked_out: bool
    detail: str

    def as_dict(self) -> dict:
        return {
            "resource": self.resource,
            "via": self.via,
            "owner_locked_out": self.owner_locked_out,
            "detail": self.detail,
        }


@dataclass
class LockoutResult:
    """Whether the owner still reaches their own data, and what could not be decided.

    `checked` and `undecided` are kept apart deliberately. A resource nobody could test is not a
    resource that passed, and folding the two together would turn a setup problem into a clean
    bill of health — the same mistake the coverage ledger exists to prevent, in miniature.
    """

    checked: list[LockoutFinding] = field(default_factory=list)
    undecided: list[dict] = field(default_factory=list)

    @property
    def locked_out(self) -> list[LockoutFinding]:
        return [c for c in self.checked if c.owner_locked_out]

    @property
    def ok(self) -> bool:
        """True only when something was actually tested and nothing was locked out."""
        return bool(self.checked) and not self.locked_out

    def as_dict(self) -> dict:
        return {
            "ok": self.ok,
            "locked_out": [c.as_dict() for c in self.locked_out],
            "checked": [c.as_dict() for c in self.checked],
            "undecided": self.undecided,
            "detail": self._detail(),
        }

    def _detail(self) -> str:
        if not self.checked:
            return (
                "Nothing was tested, so this says nothing about whether your users can reach "
                "their own data. It is not a pass."
            )
        if self.locked_out:
            return (
                f"{len(self.locked_out)} resource(s) the owner can no longer reach. Secure and "
                f"broken are not the same result, and this is the second one."
            )
        return f"The owner still reaches all {len(self.checked)} tested resource(s)."


def lockout_check(
    setup: ProveSetup,
    ownership_verified: bool = False,
    prober: Optional[RouteProber] = None,
    replay: Optional[SupabaseReplay] = None,
    repo_path: Optional[str] = None,
) -> LockoutResult:
    """Ask, on its own, whether the authorization policy locked out the legitimate owner.

    Tainted already asks this inside the fix loop, where it separates FIXED from
    BROKE_IT_SAFELY. But the question outlives the fix that raised it: a policy tightened by
    hand, by a migration, or by somebody else's autofix can lock real users out of their own
    data, and there is no finding to hang that check on. So this is the same assertion, decoupled
    — run it any time, against any target, with no prior finding required.

    It is the positive control run for its own sake: account A, reading A's own record, through
    the same door the app gives everyone else. A failure here is not a vulnerability and is never
    reported as one. It is the opposite failure, and it is the one no scanner reports at all.
    """
    result = LockoutResult()

    if not setup.target.is_local and not ownership_verified:
        result.undecided.append(
            {
                "resource": setup.target.url,
                "reason": "non-local target without verified ownership — refused to touch it",
            }
        )
        return result

    seed = setup.seed
    if seed is None:
        result.undecided.append(
            {
                "resource": setup.target.url,
                "reason": (
                    "No seed record. Without one record known to belong to account A, a refusal "
                    "cannot be told apart from a record that never existed."
                ),
            }
        )
        return result

    if not (setup.account_a.email or setup.account_a.access_token):
        result.undecided.append(
            {
                "resource": seed.table,
                "reason": "No credentials for account A, so the owner's own access cannot be tried.",
            }
        )
        return result

    prober = prober or RouteProber(setup)
    replay = replay or SupabaseReplay(setup.target, prober._client)

    # The app's own route — the door the owner actually uses. Named with the seed, or read off
    # the code when a repository is given.
    route, source = _owner_route(setup, repo_path)
    if route:
        ok, detail = prober.legitimate_access_survives(route)
        result.checked.append(
            LockoutFinding(
                resource=route,
                via="route",
                owner_locked_out=not ok,
                detail=f"{detail} (Route {source}.)",
            )
        )
    else:
        result.undecided.append({"resource": "app route", "reason": f"Not checked: {source}."})

    # PostgREST, which on the Supabase stack is a door the browser opens directly.
    via_rest, detail = _legit_via_postgrest(setup, replay)
    if via_rest is None:
        # Not a PostgREST target. Asking there anyway would read a 404 as a locked-out owner.
        result.undecided.append({"resource": seed.table, "reason": detail})
    else:
        result.checked.append(
            LockoutFinding(
                resource=seed.table, via="postgrest", owner_locked_out=not via_rest, detail=detail
            )
        )
    return result
