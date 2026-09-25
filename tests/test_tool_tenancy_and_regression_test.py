"""Cross-tenant tool access (B02) and the emitted regression test (B08).

Tool tenancy is BOLA on the tool plane, and it inherits the request plane's hard-won distinctions:
unreachable is not resistant, and a response that cannot be attributed to the other tenant is not
a leak. The emitted test inherits `repro`'s: no credential is ever written into a committed file,
and a finding with no executed request produces nothing rather than something invented.
"""

from __future__ import annotations

import json

import pytest

from tainted.checks.tool_tenancy import (
    TenantIdentity,
    ToolResponse,
    analyze_tool_tenancy,
    lookup_tools,
    prove_tool_tenancy,
)
from tainted.models import (
    Candidate,
    Check,
    Exploit,
    Finding,
    FindingStatus,
    Plane,
    ProbeResult,
    Severity,
    SourceLocation,
)
from tainted.regression_test import detect_framework, emit_regression_test
from tainted.repro import NotReproducible
from tainted.static.tools import AgentScope, ToolSpec

A = TenantIdentity(label="A", credentials={"token": "tok-a"})
B = TenantIdentity(label="B", credentials={"token": "tok-b"})


def _scope():
    return AgentScope(
        name="billing",
        kind="mcp",
        source_file="mcp.json",
        tools=[
            ToolSpec(name="get_invoice", description="Fetch an invoice by id", source_file="mcp.json"),
            ToolSpec(name="send_email", description="Send an email", source_file="mcp.json"),
        ],
    )


class FakeInvoker:
    """A shared tool backend with a configurable ownership boundary."""

    def __init__(self, *, enforces: bool, records=None, raises=False):
        self.enforces = enforces
        self.records = records if records is not None else [{"id": "inv-1", "tenant": "A"}]
        self.raises = raises
        self.calls = []

    def invoke(self, *, tool, args, identity):
        self.calls.append((tool, dict(args), identity.label))
        if self.raises:
            raise ConnectionError("backend unreachable")
        if not args:  # the tenant listing its own records
            return ToolResponse(ok=True, records=list(self.records), content=json.dumps(self.records))
        wanted = args.get("id")
        owned = [r for r in self.records if str(r.get("id")) == str(wanted)]
        if self.enforces and identity.label != "A":
            return ToolResponse(ok=False, error="not authorized for this tenant")
        return ToolResponse(ok=True, records=owned, content=json.dumps(owned))


# ----------------------------- static half (B02) ---------------------------- #
def test_only_lookup_tools_become_candidates():
    names = [t.name for t in lookup_tools(_scope())]
    assert names == ["get_invoice"]


def test_hints_match_whole_words_not_fragments():
    """`upload` is not `load`, and "provided" does not name an id."""
    scope = AgentScope(
        name="files",
        kind="mcp",
        source_file="mcp.json",
        tools=[
            ToolSpec(name="upload_file", description="Upload a file to the provided bucket"),
            ToolSpec(name="set_budget", description="Set the video budget inside the plan"),
            ToolSpec(name="getInvoice", description="Returns one invoice by invoiceId"),
            ToolSpec(name="lookup", description="Retrieves customer records by identifier"),
        ],
    )
    assert [t.name for t in lookup_tools(scope)] == ["getInvoice", "lookup"]


def test_a_scope_with_no_sink_still_yields_a_candidate():
    """Co-location makes an agent turnable; it has nothing to do with the backend's authorization."""
    read_only = AgentScope(
        name="reader",
        kind="mcp",
        source_file="mcp.json",
        tools=[ToolSpec(name="get_record", description="fetch a record by id")],
    )
    assert len(analyze_tool_tenancy([read_only])) == 1


def test_candidates_carry_the_tool_plane_and_check():
    c = analyze_tool_tenancy([_scope()])[0]
    assert c.check is Check.TOOL_TENANCY and c.plane is Plane.TOOL
    assert c.metadata["tool"] == "get_invoice"


# ---------------------------- dynamic half (B02) ---------------------------- #
def _candidate():
    return analyze_tool_tenancy([_scope()])[0]


def test_a_backend_that_answers_any_identifier_is_proven():
    invoker = FakeInvoker(enforces=False)
    f = prove_tool_tenancy(_candidate(), invoker, A, B, record_id="inv-1")
    assert f.status is FindingStatus.PROVEN
    assert f.proof.exploit.executed is True
    assert "authorizes on the identifier" in f.proof.notes


def test_a_backend_that_refuses_the_other_tenant_holds():
    invoker = FakeInvoker(enforces=True)
    f = prove_tool_tenancy(_candidate(), invoker, A, B, record_id="inv-1")
    assert f.status is FindingStatus.NOT_REPRODUCED


def test_the_identifier_is_taken_from_tenant_a_never_b():
    """The question is whether B reaches something of A's, so the id must be A's."""
    invoker = FakeInvoker(enforces=False)
    prove_tool_tenancy(_candidate(), invoker, A, B)
    listing = [c for c in invoker.calls if c[1] == {}]
    assert listing and listing[0][2] == "A"


def test_an_unreachable_backend_is_reported_not_resistant():
    invoker = FakeInvoker(enforces=False, raises=True)
    f = prove_tool_tenancy(_candidate(), invoker, A, B, record_id="inv-1")
    assert f.status is FindingStatus.REPORTED
    assert f.status is not FindingStatus.NOT_REPRODUCED


def test_no_records_for_a_means_reported_not_held():
    invoker = FakeInvoker(enforces=False, records=[])
    f = prove_tool_tenancy(_candidate(), invoker, A, B)
    assert f.status is FindingStatus.REPORTED


def test_an_unattributable_answer_is_not_claimed_as_a_leak():
    """A 200 that does not carry A's record proves nothing about the boundary."""

    class EmptyOk(FakeInvoker):
        def invoke(self, *, tool, args, identity):
            if not args:
                return ToolResponse(ok=True, records=[{"id": "inv-1"}])
            return ToolResponse(ok=True, records=[], content="{}")

    f = prove_tool_tenancy(_candidate(), EmptyOk(enforces=False), A, B, record_id="inv-1")
    assert f.status is FindingStatus.NOT_REPRODUCED
    assert "not attributable" in f.proof.notes.lower()


# --------------------------- emitted test (B08) ----------------------------- #
def _proven_finding(executed=True):
    cand = Candidate(
        check=Check.BOLA,
        title="Invoice readable by another account",
        location=SourceLocation(file="app/api/invoices/[id]/route.ts", line=12),
        severity=Severity.HIGH,
        metadata={"seed_id": "42"},
    )
    return Finding(
        candidate=cand,
        status=FindingStatus.PROVEN,
        proof=ProbeResult(
            succeeded=True,
            kind="route_bola",
            exploit=Exploit(
                description="B read A's invoice",
                method="GET",
                url="http://localhost:3000/api/invoices/42",
                headers={"Authorization": "Bearer tok-abc123-secret", "Accept": "application/json"},
                executed=executed,
            ),
        ),
    )


def test_detects_pytest_from_a_python_repo(tmp_path):
    (tmp_path / "pyproject.toml").write_text("[tool.pytest.ini_options]\n", encoding="utf-8")
    assert detect_framework(str(tmp_path)) == "pytest"


def test_detects_vitest_and_jest_from_package_json(tmp_path):
    (tmp_path / "package.json").write_text(json.dumps({"devDependencies": {"vitest": "^1"}}), encoding="utf-8")
    assert detect_framework(str(tmp_path)) == "vitest"
    (tmp_path / "package.json").write_text(json.dumps({"devDependencies": {"jest": "^29"}}), encoding="utf-8")
    assert detect_framework(str(tmp_path)) == "jest"


def test_no_framework_refuses_rather_than_guessing(tmp_path):
    assert detect_framework(str(tmp_path)) is None
    with pytest.raises(ValueError, match="does not run"):
        emit_regression_test(_proven_finding(), str(tmp_path))


def test_emitted_pytest_asserts_the_attack_fails(tmp_path):
    (tmp_path / "pytest.ini").write_text("[pytest]\n", encoding="utf-8")
    t = emit_regression_test(_proven_finding(), str(tmp_path))
    assert t.framework == "pytest"
    assert t.filename.endswith(".py")
    # The direction matters: it passes now and fails when the hole returns.
    assert "assert not leaked" in t.source
    assert "has reopened" in t.source


def test_the_emitted_test_is_valid_python(tmp_path):
    import ast

    (tmp_path / "pytest.ini").write_text("[pytest]\n", encoding="utf-8")
    ast.parse(emit_regression_test(_proven_finding(), str(tmp_path)).source)


def test_no_credential_is_written_into_a_committed_file(tmp_path):
    (tmp_path / "pytest.ini").write_text("[pytest]\n", encoding="utf-8")
    src = emit_regression_test(_proven_finding(), str(tmp_path)).source
    assert "tok-abc123-secret" not in src
    assert "TAINTED_REPLAY_TOKEN" in src


def test_javascript_output_carries_the_right_importer(tmp_path):
    (tmp_path / "package.json").write_text(json.dumps({"devDependencies": {"vitest": "^1"}}), encoding="utf-8")
    src = emit_regression_test(_proven_finding(), str(tmp_path)).source
    assert 'from "vitest"' in src
    assert "tok-abc123-secret" not in src


def test_a_demonstrated_but_unfired_exploit_emits_nothing(tmp_path):
    """Command and template injection are never executed; inventing a test would assert fiction."""
    (tmp_path / "pytest.ini").write_text("[pytest]\n", encoding="utf-8")
    with pytest.raises(NotReproducible):
        emit_regression_test(_proven_finding(executed=False), str(tmp_path))


def _probe_finding(kind, url, status=FindingStatus.PROVEN):
    f = _proven_finding()
    f.candidate.metadata = {}
    f.status = status
    f.proof.kind = kind
    f.proof.exploit.url = url
    return f


def test_a_postgrest_proof_marks_the_record_it_filtered_on(tmp_path):
    """Not the URL's tail: `invoices?id=eq.42` appears in no response, so it guards nothing."""
    (tmp_path / "pytest.ini").write_text("[pytest]\n", encoding="utf-8")
    f = _probe_finding("targeted_bola", "http://x/rest/v1/invoices?id=eq.42&select=*")
    assert emit_regression_test(f, str(tmp_path)).marker == "42"


def test_a_proof_with_no_identifying_value_emits_nothing(tmp_path):
    (tmp_path / "pytest.ini").write_text("[pytest]\n", encoding="utf-8")
    f = _probe_finding("unfiltered_rls", "http://x/rest/v1/invoices?select=*&limit=5")
    with pytest.raises(NotReproducible, match="pass either way"):
        emit_regression_test(f, str(tmp_path))


def test_an_attack_that_held_is_not_turned_into_a_regression_test(tmp_path):
    (tmp_path / "pytest.ini").write_text("[pytest]\n", encoding="utf-8")
    f = _probe_finding("route_bola", "http://x/api/invoices/42", FindingStatus.NOT_REPRODUCED)
    with pytest.raises(NotReproducible, match="not proven"):
        emit_regression_test(f, str(tmp_path))


def test_jest_output_never_hands_expect_a_message(tmp_path):
    """Jest's `expect` takes one argument; a second made every emitted test fail."""
    (tmp_path / "package.json").write_text(json.dumps({"devDependencies": {"jest": "^29"}}), encoding="utf-8")
    src = emit_regression_test(_proven_finding(), str(tmp_path)).source
    assert "expect(leaked).toBe(false)" in src and "expect(\n" not in src
