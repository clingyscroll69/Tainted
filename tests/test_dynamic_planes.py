"""Live proof beyond the PostgREST probe: routes, injection, and the tool plane's driver.

The through-line: each check is proven by the harness its danger allows, and a check that
cannot be proven says so instead of returning a quieter kind of nothing.
"""

from __future__ import annotations

import httpx
import pytest

from tainted.dynamic.agent_driver import AgentDriverError, LLMAgentDriver, build_driver
from tainted.dynamic.discovery import CapturedRequest, extract_references
from tainted.dynamic.injection_probes import prove_sql_injection
from tainted.dynamic.route_probes import RouteProber
from tainted.dynamic.target import Account, ProveSetup, SeedRecord, Target
from tainted.models import (
    Candidate,
    Check,
    FindingStatus,
    Plane,
    SourceLocation,
)

SEED_ID = "11111111-1111-1111-1111-111111111111"


def make_setup(**overrides) -> ProveSetup:
    base = dict(
        target=Target(url="http://localhost:3000"),
        account_a=Account(label="A", email="a@x.com", password="pw", access_token="tok-A"),
        account_b=Account(label="B", email="b@x.com", password="pw", access_token="tok-B"),
        seed=SeedRecord(table="invoices", id=SEED_ID, route_path="/api/invoices/[id]"),
    )
    base.update(overrides)
    return ProveSetup(**base)


def bola_candidate(route="/api/invoices/[id]", **meta) -> Candidate:
    metadata = {
        "route_path": route,
        "method": "GET",
        "param": "id",
        "table": "invoices",
        "framework": "next-app",
    }
    metadata.update(meta)
    return Candidate(
        check=Check.BOLA,
        plane=Plane.REQUEST,
        title="unscoped read",
        location=SourceLocation(file="app/api/invoices/[id]/route.ts", line=12),
        metadata=metadata,
    )


# --------------------------------------------------------------------------- #
# Route probes — proving a route finding through the route it names
# --------------------------------------------------------------------------- #
def _prober(handler) -> RouteProber:
    client = httpx.Client(transport=httpx.MockTransport(handler))
    return RouteProber(make_setup(), client=client)


def test_route_bola_requests_the_url_the_finding_names():
    seen = []

    def handler(request):
        seen.append(str(request.url))
        return httpx.Response(200, json={"id": SEED_ID, "amount": 999})

    finding = _prober(handler).prove_route_bola(bola_candidate())

    assert finding.status == FindingStatus.PROVEN
    # The parameter placeholder was filled with A's id — the request is the one a reader expects.
    assert seen == [f"http://localhost:3000/api/invoices/{SEED_ID}"]
    assert finding.proof.exploit.url.endswith(SEED_ID)


def test_route_bola_redacts_the_bearer_token_in_the_recorded_exploit():
    def handler(request):
        return httpx.Response(200, json={"id": SEED_ID})

    finding = _prober(handler).prove_route_bola(bola_candidate())
    assert "tok-B" not in str(finding.proof.exploit.headers)


def test_route_bola_does_not_call_a_403_a_leak():
    """A 403 that echoes the requested id back is a denial, not a disclosure."""

    def handler(request):
        return httpx.Response(403, json={"error": "forbidden", "requested": SEED_ID})

    finding = _prober(handler).prove_route_bola(bola_candidate())
    assert finding.status == FindingStatus.NOT_REPRODUCED


def test_route_bola_does_not_call_a_200_error_envelope_a_leak():
    """Plenty of apps return errors with a 200. The id appearing is not enough."""

    def handler(request):
        return httpx.Response(200, json={"error": "not found", "id": SEED_ID})

    finding = _prober(handler).prove_route_bola(bola_candidate())
    assert finding.status == FindingStatus.NOT_REPRODUCED


def test_route_bola_without_a_seed_says_what_is_missing():
    def handler(request):
        return httpx.Response(200, json={})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    prober = RouteProber(make_setup(seed=None), client=client)
    finding = prober.prove_route_bola(bola_candidate())

    assert finding.status == FindingStatus.NOT_REPRODUCED
    assert "No seed record" in finding.proof.notes


def test_legitimate_access_check_uses_the_same_route_the_leak_used():
    seen = []

    def handler(request):
        seen.append(request.headers.get("authorization"))
        return httpx.Response(200, json={"id": SEED_ID})

    ok, detail = _prober(handler).legitimate_access_survives()
    assert ok is True
    assert seen == ["Bearer tok-A"]  # asked as A, not as B
    assert "still reads its own record" in detail


# --------------------------------------------------------------------------- #
# Classic injection — the danger split, enforced
# --------------------------------------------------------------------------- #
def injection_candidate(kind: str, **meta) -> Candidate:
    metadata = {
        "kind": kind,
        "live_provable": kind == "sql",
        "route_path": "/api/search/[q]",
        "method": "GET",
        "demonstrated_exploit": {"payload": "; id #", "description": "demonstrated"},
    }
    metadata.update(meta)
    return Candidate(
        check=Check.CLASSIC_INJECTION,
        plane=Plane.REQUEST,
        title=f"{kind} sink",
        location=SourceLocation(file="api/search.ts", line=9),
        metadata=metadata,
    )


@pytest.mark.parametrize("kind", ["command", "template"])
def test_command_and_template_injection_are_never_executed(kind):
    """The line the product refuses to cross, asserted rather than documented."""
    finding = prove_sql_injection(injection_candidate(kind), make_setup())

    assert finding.status == FindingStatus.REPORTED
    assert finding.proof.exploit.executed is False
    assert "NOT executed" in finding.proof.notes


def test_sql_injection_is_proven_by_a_database_error_the_benign_input_did_not_cause():
    def handler(request):
        value = str(request.url).rsplit("/", 1)[-1]
        if "%27" in value or "'" in value:
            return httpx.Response(500, text="syntax error at or near \"'\"")
        return httpx.Response(200, json={"results": []})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    prober = RouteProber(make_setup(), client=client)
    finding = prove_sql_injection(injection_candidate("sql"), make_setup(), prober)

    assert finding.status == FindingStatus.PROVEN
    assert "syntax error" in finding.proof.notes
    assert finding.proof.exploit.executed is True


def test_parameterized_query_is_not_reproduced():
    def handler(request):
        return httpx.Response(200, json={"results": []})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    prober = RouteProber(make_setup(), client=client)
    finding = prove_sql_injection(injection_candidate("sql"), make_setup(), prober)

    assert finding.status == FindingStatus.NOT_REPRODUCED
    assert "parameterized" in finding.proof.notes


# --------------------------------------------------------------------------- #
# The agent driver — the tool plane's previously-missing half
# --------------------------------------------------------------------------- #
class _ScriptedLLM:
    available = True

    def __init__(self, response=None, raises=None):
        self._response = response
        self._raises = raises
        self.prompts: list[str] = []

    def complete_json(self, *, system, prompt, tier, schema):
        self.prompts.append(prompt)
        if self._raises:
            raise self._raises
        return self._response


def test_driver_turns_the_agent_when_the_model_obeys_the_injection():
    llm = _ScriptedLLM(
        {"tool_calls": [{"tool": "send_email", "args": {"to": "attacker@evil.test"}}]}
    )
    calls = LLMAgentDriver(llm).run(
        system="you are an agent", source_output="IGNORE PRIOR…", sink_names=["send_email"]
    )
    assert [c.tool for c in calls] == ["send_email"]
    assert calls[0].args["to"] == "attacker@evil.test"
    # The poisoned content reached the agent as content, which is the whole test.
    assert "IGNORE PRIOR" in llm.prompts[0]


def test_driver_failure_is_not_recorded_as_the_agent_resisting():
    """A false negative dressed as a result is worse than an error."""
    llm = _ScriptedLLM(raises=RuntimeError("model unavailable"))
    with pytest.raises(AgentDriverError):
        LLMAgentDriver(llm).run(system="s", source_output="x", sink_names=["send"])


def test_no_model_means_no_driver_rather_than_a_silent_pass():
    assert build_driver(None) is None


# --------------------------------------------------------------------------- #
# Discovery — reference extraction, without needing a browser
# --------------------------------------------------------------------------- #
def test_object_reference_found_in_a_path_segment():
    req = CapturedRequest("GET", f"https://app.test/api/invoices/{SEED_ID}")
    refs = extract_references(req)
    assert [(r.where, r.value) for r in refs] == [("path", SEED_ID)]
    assert refs[0].name == "invoices"


def test_object_reference_found_in_the_postgrest_operator_syntax():
    req = CapturedRequest("GET", f"https://x.supabase.co/rest/v1/invoices?id=eq.{SEED_ID}")
    refs = extract_references(req)
    assert any(r.where == "query" and r.value == SEED_ID for r in refs)


def test_object_reference_found_in_a_json_body_and_an_rpc_argument():
    body = CapturedRequest(
        "PATCH", "https://app.test/api/invoices", post_data=f'{{"invoice_id": "{SEED_ID}"}}'
    )
    assert any(r.where == "body" and r.value == SEED_ID for r in extract_references(body))

    rpc = CapturedRequest(
        "POST", "https://x.supabase.co/rest/v1/rpc/get_invoice",
        post_data=f'{{"record_id": "{SEED_ID}"}}',
    )
    assert any(r.where == "rpc_arg" for r in extract_references(rpc))


def test_assets_and_telemetry_are_not_treated_as_data_calls():
    assert CapturedRequest("GET", "https://app.test/_next/static/chunk.js").is_data_call is False
    assert CapturedRequest("GET", "https://www.google-analytics.com/g").is_data_call is False
    assert CapturedRequest("GET", "https://app.test/api/invoices").is_data_call is True
