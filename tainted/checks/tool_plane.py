"""The tool plane: an agent tricked by content from one tool into misusing another.

Read email is a source. Send email is a sink. If an agent holds both, text from an
inbox could steer it into sending mail it should not. The LLM labels each tool, then
networkx finds every scope holding both a source and a sink and this pass ranks them
by how dangerous the sink is, ready for dynamic proof.
"""

from __future__ import annotations

from typing import Optional

import networkx as nx

from tainted.llm.client import LLMClient, LLMUnavailable
from tainted.models import (
    Candidate,
    Check,
    Confidence,
    FilteredScope,
    Plane,
    Provenance,
    Register,
    Severity,
    SourceLocation,
)
from tainted.static.tools import AgentScope, discover_scopes

_SEVERITY = {
    "info": Severity.INFO,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
}


# --------------------------------------------------------------------------- #
# Labeling
# --------------------------------------------------------------------------- #
def label_scopes(scopes: list[AgentScope], llm: LLMClient) -> None:
    """Assign source/sink/neither to every tool in place. Requires the LLM."""
    for scope in scopes:
        for tool in scope.tools:
            if tool.role is not None:
                continue
            try:
                result = llm.label_tool(tool.as_prompt_dict())
            except LLMUnavailable:
                raise
            tool.role = result.get("role", "neither")
            tool.severity = result.get("severity")


# --------------------------------------------------------------------------- #
# Co-location graph
# --------------------------------------------------------------------------- #
def build_graph(scopes: list[AgentScope]) -> nx.DiGraph:
    """A directed graph: scope -> source tools and scope -> sink tools.

    A co-located scope is one node with both an incoming source edge and an incoming sink edge.
    networkx is used here so richer reachability, like multi-agent hand-offs, can extend this later.
    """
    g = nx.DiGraph()
    for scope in scopes:
        snode = ("scope", scope.name, scope.source_file)
        g.add_node(snode, kind="scope", scope=scope)
        for tool in scope.tools:
            tnode = ("tool", scope.name, tool.name)
            g.add_node(tnode, kind="tool", role=tool.role, tool=tool)
            g.add_edge(snode, tnode, role=tool.role)
    return g


def colocated_scopes(scopes: list[AgentScope]) -> list[AgentScope]:
    """Scopes holding at least one source and one sink."""
    return [s for s in scopes if s.is_colocated]


# --------------------------------------------------------------------------- #
# Candidates (ranked filter)
# --------------------------------------------------------------------------- #
def _scope_candidate(scope: AgentScope) -> Candidate:
    worst_sink = max(
        scope.sinks,
        key=lambda t: _SEVERITY.get((t.severity or "medium"), Severity.MEDIUM).rank,
    )
    severity = _SEVERITY.get((worst_sink.severity or "medium"), Severity.MEDIUM)
    return Candidate(
        check=Check.AGENT_INJECTION,
        plane=Plane.TOOL,
        title=f"Agent `{scope.name}` could be tricked into misusing a tool",
        description=(
            f"Agent `{scope.name}` can read from {[t.name for t in scope.sources]} "
            f"and act through {[t.name for t in scope.sinks]}. Content it reads could "
            f"steer it into misusing one of those tools."
        ),
        location=SourceLocation(file=scope.source_file, line=0),
        source=", ".join(t.name for t in scope.sources),
        sink=", ".join(t.name for t in scope.sinks),
        severity=severity,
        provenance=[
            Provenance(origin=Register.STRUCTURE, detail="networkx co-location (ranked filter)")
        ],
        confidence=Confidence(
            score=0.4, rationale="co-location is necessary but not sufficient; needs proof"
        ),
        metadata={
            "scope": scope.name,
            "kind": scope.kind,
            "coded": scope.coded,
            "worst_sink": worst_sink.name,
        },
    )


def analyze_tool_plane(
    repo_path: str,
    llm: Optional[LLMClient] = None,
    dropped: Optional[list[FilteredScope]] = None,
) -> list[Candidate]:
    """Discover scopes, label their tools, find co-located ones, and rank the risky ones.

    The LLM labels tools and drops the obviously benign scopes, since dynamic proof is
    expensive to run on every candidate. Without an LLM, every tool stays unlabeled and
    this pass returns nothing rather than guess.

    `dropped`, when given, is filled with the scopes the filter removed and the reason it gave.
    An out-parameter rather than a second return value so every existing caller and test keeps
    working unchanged; the orchestrator passes one so the report can account for them.
    """
    dropped = [] if dropped is None else dropped
    scopes = discover_scopes(repo_path)
    if not scopes or llm is None:
        return []

    label_scopes(scopes, llm)
    colocated = colocated_scopes(scopes)
    if not colocated:
        return []

    # LLM filter: keep only scopes where a real attack looks plausible.
    try:
        decisions = llm.filter_scopes_explained(
            [
                {
                    "scope": s.name,
                    "sources": [t.as_prompt_dict() for t in s.sources],
                    "sinks": [t.as_prompt_dict() for t in s.sinks],
                }
                for s in colocated
            ]
        )
    except LLMUnavailable:
        decisions = [(True, "") for _ in colocated]

    candidates = []
    for scope, (kept, rationale) in zip(colocated, decisions):
        if not kept:
            # Recorded, not discarded. This is the engine's only model-made membership
            # decision, and the report has to be able to say a scope was dropped rather than
            # look the same as a repository that never had it.
            dropped.append(FilteredScope(scope=scope.name, rationale=rationale))
            continue
        cand = _scope_candidate(scope)
        cand.filtered_in = True
        candidates.append(cand)
    # Ranked by sink severity (the filter's ordering hint for dynamic proof).
    candidates.sort(key=lambda c: -c.severity.rank)
    return candidates
