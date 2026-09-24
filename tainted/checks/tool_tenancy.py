"""Cross-tenant authorization on the tool plane — BOLA, one layer up.

The request plane's oldest bug is that `GET /invoices/42` fetches invoice 42 for whoever asks.
Agent tooling has rebuilt the same bug on a new surface: one MCP server, several tenants, and a
`get_invoice` tool that takes an id and trusts it. The agent is the confused deputy, but the flaw
is ordinary object-level authorization — the server never asked whether *this* caller owns the
thing it is handing over.

This is not the injection check. `tool_plane` asks whether an agent can be *turned* by content it
reads; this asks whether the tool backend enforces a boundary at all, with no injection involved.
An agent that cannot be turned still leaks everything if its tools answer any id they are given.

The proof has the shape the request plane already established, because it is the same proof:

  1. As tenant A, call the read tool and note an identifier that comes back.
  2. As tenant B, call the **same tool on the same server** for A's identifier.
  3. B receiving A's record is the finding. Nothing else is.

Two refusals are built in, both inherited from the request-plane probes because the failure modes
are identical. A tool that errors, or a server that cannot be reached, is REPORTED with the reason
and never NOT_REPRODUCED — an unreachable server did not hold a boundary, it was never asked. And
a response that does not demonstrably carry A's record is not a leak, however suspicious it looks:
attributability is the whole difference between evidence and a guess.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional, Protocol

from tainted.models import (
    Candidate,
    Check,
    Confidence,
    Exploit,
    Finding,
    FindingStatus,
    Plane,
    ProbeResult,
    Provenance,
    Register,
    Severity,
    SourceLocation,
)
from tainted.static.tools import AgentScope, ToolSpec

# Tool names and descriptions that read as "fetch one record by identifier" — the shape that can
# leak across a tenant boundary. A tool that takes no identifier cannot be asked for somebody
# else's record, so it is not a candidate here.
_LOOKUP_HINT = (
    "get",
    "fetch",
    "read",
    "lookup",
    "find",
    "show",
    "retrieve",
    "load",
    "detail",
    "query",
    "search",
    "list",
)
_ID_ARG_HINT = ("id", "_id", "uuid", "key", "ref", "slug", "record", "number")


@dataclass
class TenantIdentity:
    """One tenant's credentials for the shared tool backend.

    `label` names it in the report ("A" / "B"); `credentials` is whatever the invoker needs and is
    never interpreted here — headers, a token, a connection string. Keeping it opaque is what lets
    the same check cover an MCP server, an n8n webhook and an internal tool API without this
    module learning any of their auth schemes.
    """

    label: str
    credentials: dict[str, Any] = field(default_factory=dict)


@dataclass
class ToolResponse:
    """What the backend answered."""

    ok: bool
    content: str = ""
    records: list[dict] = field(default_factory=list)
    error: str = ""


class ToolInvoker(Protocol):
    """Calls one tool on the shared backend as a given tenant.

    Injectable for the same reason every other live harness in this engine is: the check's logic
    has to be exercisable without a live MCP server, and a real invoker is a transport detail.
    """

    def invoke(
        self, *, tool: str, args: dict[str, Any], identity: TenantIdentity
    ) -> ToolResponse: ...


# --------------------------------------------------------------------------- #
# Static half — which tools could leak across a tenant boundary
# --------------------------------------------------------------------------- #
def lookup_tools(scope: AgentScope) -> list[ToolSpec]:
    """Tools in this scope that fetch a record by identifier."""
    return [t for t in scope.tools if _is_lookup(t)]


def _is_lookup(tool: ToolSpec) -> bool:
    name = (tool.name or "").lower()
    desc = (tool.description or "").lower()
    if not any(h in name or h in desc for h in _LOOKUP_HINT):
        return False
    return any(h in name or h in desc for h in _ID_ARG_HINT)


def analyze_tool_tenancy(scopes: list[AgentScope]) -> list[Candidate]:
    """One candidate per lookup tool on a shared backend.

    Deliberately *not* gated on the scope being co-located. Co-location is what makes an agent
    turnable by injection; it has nothing to do with whether the backend checks ownership. A scope
    with a single read tool and no sink at all can still hand tenant B tenant A's records, and
    requiring a sink here would have hidden exactly that case.
    """
    candidates: list[Candidate] = []
    for scope in scopes:
        for tool in lookup_tools(scope):
            candidates.append(
                Candidate(
                    check=Check.TOOL_TENANCY,
                    plane=Plane.TOOL,
                    title=f"`{tool.name}` may answer any tenant's identifier",
                    description=(
                        f"`{tool.name}` in scope `{scope.name}` fetches a record by identifier. "
                        f"If the backend authorizes on the identifier rather than on the caller, "
                        f"one tenant's agent can read another tenant's records through it."
                    ),
                    location=SourceLocation(file=tool.source_file or scope.source_file, line=0),
                    source=f"tenant-supplied identifier to `{tool.name}`",
                    sink=f"{scope.kind}:{scope.name}/{tool.name}",
                    severity=Severity.HIGH,
                    provenance=[
                        Provenance(
                            origin=Register.STRUCTURE,
                            detail=f"{scope.kind} tool graph: `{tool.name}` takes an identifier",
                        )
                    ],
                    confidence=Confidence(
                        score=0.5,
                        rationale=(
                            "A lookup tool is a possible cross-tenant hole, never a confirmed "
                            "one. Only a call as a second tenant decides it."
                        ),
                    ),
                    metadata={"scope": scope.name, "tool": tool.name, "kind": scope.kind},
                )
            )
    return candidates


# --------------------------------------------------------------------------- #
# Dynamic half — two tenants, one backend
# --------------------------------------------------------------------------- #
def prove_tool_tenancy(
    candidate: Candidate,
    invoker: ToolInvoker,
    tenant_a: TenantIdentity,
    tenant_b: TenantIdentity,
    record_id: Optional[str] = None,
    id_arg: str = "id",
) -> Finding:
    """Call one tool as tenant B for a record belonging to tenant A.

    `record_id` is A's record. When it is not supplied, A is asked first and the identifier is
    taken from A's own answer — the same walk-as-A-never-as-B rule the request plane's discovery
    follows, and for the same reason: the question is whether B can reach something *of A's*, so
    the identifier has to be A's to begin with.
    """
    finding = Finding(candidate=candidate)
    tool = candidate.metadata.get("tool") or ""

    if record_id is None:
        record_id, why = _identifier_from_a(invoker, tool, tenant_a, id_arg)
        if record_id is None:
            return _reported(finding, why)

    try:
        resp = invoker.invoke(
            tool=tool, args={id_arg: record_id}, identity=tenant_b
        )
    except Exception as exc:  # noqa: BLE001 - a backend that cannot be called was never asked
        return _reported(
            finding,
            f"The call as tenant {tenant_b.label} could not be made ({exc}). The backend was "
            f"never asked, so nothing is known about the boundary.",
        )

    if not resp.ok:
        finding.status = FindingStatus.NOT_REPRODUCED
        finding.proof = ProbeResult(
            succeeded=False,
            kind="tool_tenancy",
            notes=(
                f"Tenant {tenant_b.label} asked `{tool}` for tenant {tenant_a.label}'s record "
                f"`{record_id}` and was refused ({resp.error or 'no content returned'}). The "
                f"boundary held."
            ),
        )
        return finding

    leaked = _carries_record(resp, record_id)
    exploit = Exploit(
        description=(
            f"Tenant {tenant_b.label} called `{tool}` on the shared {candidate.metadata.get('kind')} "
            f"backend with tenant {tenant_a.label}'s identifier `{record_id}`."
        ),
        payload=f"{tool}({id_arg}={record_id!r}) as tenant {tenant_b.label}",
        executed=True,
    )
    result = ProbeResult(
        succeeded=leaked,
        kind="tool_tenancy",
        exploit=exploit,
        response_body=resp.content[:2000],
        rows_returned=len(resp.records) or None,
        notes=(
            f"Tenant {tenant_b.label} received tenant {tenant_a.label}'s record `{record_id}` "
            f"through `{tool}`. The tool authorizes on the identifier, not on the caller."
            if leaked
            else (
                f"`{tool}` answered tenant {tenant_b.label}, but the response does not carry "
                f"tenant {tenant_a.label}'s record `{record_id}`. Not attributable to a "
                f"cross-tenant read, so it is not claimed as one."
            )
        ),
    )
    finding.proof = result
    if leaked:
        finding.status = FindingStatus.PROVEN
        finding.provenance.append(
            Provenance(origin=Register.PROOF, detail="live probe: tool_tenancy")
        )
        finding.recommended_fix = (
            f"Authorize `{tool}` on the caller's tenant, not on the identifier it was given. "
            f"Scope the backing query by the authenticated tenant so an identifier from another "
            f"tenant returns nothing, rather than checking the identifier's format or existence."
        )
    else:
        finding.status = FindingStatus.NOT_REPRODUCED
    return finding


def _identifier_from_a(
    invoker: ToolInvoker, tool: str, tenant_a: TenantIdentity, id_arg: str
) -> tuple[Optional[str], str]:
    """Ask tenant A for its own records and take an identifier out of the answer."""
    try:
        resp = invoker.invoke(tool=tool, args={}, identity=tenant_a)
    except Exception as exc:  # noqa: BLE001
        return None, f"Tenant {tenant_a.label}'s own call failed ({exc}), so there is no identifier to try."
    if not resp.ok or not resp.records:
        return None, (
            f"Tenant {tenant_a.label} returned no records from `{tool}`, so there is nothing of "
            f"{tenant_a.label}'s for tenant B to ask for. Supply a record id to make this provable."
        )
    for record in resp.records:
        for key in (id_arg, "id", "uuid", "key"):
            if record.get(key):
                return str(record[key]), ""
    return None, (
        f"Tenant {tenant_a.label}'s records carry no recognizable identifier, so no cross-tenant "
        f"call could be aimed."
    )


def _carries_record(resp: ToolResponse, record_id: str) -> bool:
    """Whether the answer demonstrably contains the record that belongs to the other tenant."""
    needle = str(record_id)
    for record in resp.records:
        for value in record.values():
            if str(value) == needle:
                return True
    return needle in (resp.content or "")


def _reported(finding: Finding, why: str) -> Finding:
    """REPORTED, never NOT_REPRODUCED — nothing was asked, so nothing held."""
    finding.status = FindingStatus.REPORTED
    finding.proof = ProbeResult(succeeded=False, kind="tool_tenancy", notes=why)
    finding.provenance.append(
        Provenance(origin=Register.STRUCTURE, detail="static-only: the backend was not reached")
    )
    return finding
