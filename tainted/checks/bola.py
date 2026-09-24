"""BOLA: your app fetches a record and never checks who it belongs to.

Nothing here looks wrong on its own:

    const { data } = await supabase.from("invoices").select("*").eq("id", params.id)

It is wrong because `params.id` can name any invoice, and no check says it has to be the
caller's. Static analysis finds every route with this shape; the model only ranks them, since
proving one costs a single HTTP request and every one gets tried regardless of the ranking.
"""

from __future__ import annotations

from typing import Optional, Sequence

from tainted.llm.client import LLMClient, LLMUnavailable
from tainted.models import (
    Candidate,
    Check,
    Confidence,
    Plane,
    Provenance,
    Register,
    Severity,
    SourceLocation,
)
from tainted.static.routes import RouteHandler, discover_routes


def bola_candidates(routes: list[RouteHandler]) -> list[Candidate]:
    """Every route that reads a record by a request id, with no check on who owns it."""
    candidates: list[Candidate] = []
    for route in routes:
        if not route.reads_db or route.has_ownership_check:
            continue
        param = route.param_reaching_read
        if param is None:
            continue  # a read with no request parameter in it is not an object reference
        candidates.append(_candidate(route, param))
    return candidates


def _candidate(route: RouteHandler, param: str) -> Candidate:
    read = route.db_reads[0]
    table = route.tables[0] if route.tables else None
    severity, rationale = _severity(route)

    return Candidate(
        check=Check.BOLA,
        plane=Plane.REQUEST,
        title=(
            f"`{route.method} {route.path}` reads "
            f"{f'`{table}`' if table else 'a record'} by `{param}` with no owner check"
        ),
        description=(
            f"The handler takes `{param}` from the request and reads the database "
            f"(`{read.expression}`) with no check that the record belongs to the caller. "
            + (
                "It does read the caller's identity "
                f"({', '.join(route.identity_signals)}), but never uses it to limit the "
                "query. Reading identity and not using it is the classic shape of this bug."
                if route.identity_signals
                else "It never reads the caller's identity at all."
            )
        ),
        location=SourceLocation(file=route.file, line=read.line, snippet=read.expression),
        source=f"request parameter `{param}` ({route.method} {route.path})",
        sink=read.expression,
        severity=severity,
        provenance=[
            Provenance(
                origin=Register.STRUCTURE,
                detail=f"{route.framework} route discovery: read reached by `{param}`, no owner predicate",
            )
        ],
        confidence=Confidence(score=0.55, rationale=rationale),
        metadata={
            "table": table,
            "route_path": route.path,
            "method": route.method,
            "param": param,
            "framework": route.framework,
            "identity_signals": route.identity_signals,
            "db_read_kind": read.kind,
        },
    )


def _severity(route: RouteHandler) -> tuple[Severity, str]:
    """Knowing the caller but not using it is the strongest signal short of proof."""
    if route.identity_signals:
        return (
            Severity.HIGH,
            "the handler knows the caller and still does not scope the query by them",
        )
    return (
        Severity.MEDIUM,
        "no owner check, though the route may also be meant to be public. Proof decides",
    )


# --------------------------------------------------------------------------- #
# The model only ranks. It never removes a candidate.
# --------------------------------------------------------------------------- #
def judge_bola_candidates(candidates: list[Candidate], llm: LLMClient) -> list[Candidate]:
    """Attach the model's judgment as a rank score, with its reasoning recorded.

    If the model thinks a possible hole is uninteresting, it sinks in the queue but is
    still tried. If the model is unavailable, the queue falls back to severity order.
    Either way, Tainted records which happened.
    """
    for cand in candidates:
        try:
            verdict = llm.judge_ownership(
                {
                    "route": f"{cand.metadata.get('method')} {cand.metadata.get('route_path')}",
                    "parameter": cand.metadata.get("param"),
                    "query": cand.sink,
                    "table": cand.metadata.get("table"),
                    "identity_available": bool(cand.metadata.get("identity_signals")),
                    "handler_location": str(cand.location),
                }
            )
        except LLMUnavailable:
            return candidates
        try:
            likelihood = min(1.0, max(0.0, float(verdict.get("likelihood", 0.5))))
        except (TypeError, ValueError):
            likelihood = 0.5
        is_ref = bool(verdict.get("is_object_reference", True))
        checked = bool(verdict.get("ownership_check_present", False))
        # If the model sees an owner check the parser missed, it pushes the candidate down the
        # queue but never removes it. The parser and the model can each miss things differently.
        # Only the live attack settles it.
        cand.rank_score = 0.0 if checked else (likelihood if is_ref else likelihood * 0.3)
        cand.provenance.append(
            Provenance(
                origin=Register.MEANING,
                detail=f"LLM ownership judgment (order only): {str(verdict.get('rationale', ''))[:200]}",
            )
        )
    return candidates


# --------------------------------------------------------------------------- #
# Static entry point
# --------------------------------------------------------------------------- #
def analyze_bola(repo_path: str, llm: Optional[LLMClient] = None, exclude: Sequence[str] = ()) -> list[Candidate]:
    """Discover routes, keep the ones missing an ownership predicate, rank them."""
    routes = discover_routes(repo_path, exclude)
    candidates = bola_candidates(routes)
    if llm is not None and candidates:
        judge_bola_candidates(candidates, llm)
    return candidates
