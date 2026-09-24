"""Decides which planes apply to this repo before Tainted runs anything.

Three rungs, each more expensive than the last: static signatures (fast), then the model
reading the code, then a live probe against a route that should require login. A plane is
skipped only when a rung proves it is absent. If every rung is unsure, Tainted runs it anyway.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import httpx

from tainted.dynamic.replay import SupabaseReplay  # noqa: F401 (type clarity for callers)
from tainted.dynamic.target import Target
from tainted.llm.client import LLMClient, LLMUnavailable
from tainted.models import (
    ApplicabilityDecision,
    Confidence,
    Plane,
    Provenance,
    Register,
)

_SKIP_DIRS = {"node_modules", ".git", "dist", "build", ".next", "__pycache__", ".venv"}


# --------------------------------------------------------------------------- #
# Rung 1 — static signatures
# --------------------------------------------------------------------------- #
_REQUEST_SIGNATURES = (
    "@supabase/supabase-js",
    "supabase",
    "auth.uid()",
    "enable row level security",
    "passport",
    "next-auth",
    "@clerk/",
    "jsonwebtoken",
    "flask_login",
    "fastapi.security",
)
_TOOL_SIGNATURES = (
    "langchain",
    "@langchain/",
    "crewai",
    "llamaindex",
    "modelcontextprotocol",
    "mcp.server",
    '"nodes":',  # n8n export
    "flowise",
    "@tool",
    "StructuredTool",
)


def _scan_signatures(repo_path: str, needles: tuple[str, ...]) -> list[str]:
    """Return which needles appear anywhere in the repo's text files. Cheap and shallow."""
    root = Path(repo_path)
    found: set[str] = set()
    exts = {".ts", ".tsx", ".js", ".jsx", ".py", ".json", ".sql", ".yaml", ".yml", ".toml"}
    for path in root.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in exts:
            continue
        if any(part in _SKIP_DIRS for part in path.relative_to(root).parts):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace").lower()
        except OSError:
            continue
        for needle in needles:
            if needle.lower() in text:
                found.add(needle)
        if len(found) == len(needles):
            break
    return sorted(found)


# --------------------------------------------------------------------------- #
# The cascade, per plane
# --------------------------------------------------------------------------- #
def decide_plane(
    plane: Plane,
    repo_path: str,
    llm: Optional[LLMClient] = None,
    target: Optional[Target] = None,
    behavioral_probe: Optional["BehavioralProbe"] = None,
) -> ApplicabilityDecision:
    signatures = _REQUEST_SIGNATURES if plane is Plane.REQUEST else _TOOL_SIGNATURES
    hits = _scan_signatures(repo_path, signatures)

    # Rung 1: a signature hit proves the plane applies. Finding nothing proves nothing,
    # so an empty result here never skips the plane on its own.
    if hits:
        return ApplicabilityDecision(
            plane=plane,
            applies=True,
            established=True,
            provenance=Provenance(
                origin=Register.STRUCTURE, rung=1, detail=f"found: {', '.join(hits)}"
            ),
            confidence=Confidence(score=0.9, rationale="a known signature is present"),
        )

    # Rung 2: let the model read the code.
    if llm is not None:
        decision = _rung2_llm(plane, repo_path, llm)
        if decision is not None:
            return decision

    # Rung 3: behavioral — only when even the model was unsure and a target is up.
    if behavioral_probe is not None and target is not None:
        decision = behavioral_probe.run(plane, target)
        if decision is not None:
            return decision

    # Still unsure after every rung, so Tainted runs the plane. Absence was never proven.
    return ApplicabilityDecision(
        plane=plane,
        applies=True,
        established=False,
        provenance=Provenance(
            origin=Register.STRUCTURE,
            detail="unsure after every check, so Tainted runs it anyway",
        ),
        confidence=Confidence(score=0.3, rationale="nothing proved this plane is absent"),
    )


def _rung2_llm(
    plane: Plane, repo_path: str, llm: LLMClient
) -> Optional[ApplicabilityDecision]:
    question = (
        "Does this application authenticate users and expose an object-authorization surface "
        "(records owned by specific users, fetched by id)?"
        if plane is Plane.REQUEST
        else "Does this application define an agent with tools, where something reads external "
        "data and then takes a consequential action?"
    )
    evidence = _gather_evidence(repo_path)
    try:
        answer = llm.judge_applicability(question, evidence)
    except LLMUnavailable:
        return None
    verdict = answer.get("answer", "inconclusive")
    try:
        conf = min(1.0, max(0.0, float(answer.get("confidence", 0.5))))
    except (TypeError, ValueError):
        conf = 0.5
    rationale = str(answer.get("rationale", ""))
    prov = Provenance(origin=Register.MEANING, rung=2, detail="the model read the code")

    if verdict == "no":
        # The model proves absence. This is the only way to skip a plane at this rung.
        return ApplicabilityDecision(
            plane=plane,
            applies=False,
            established=True,
            provenance=prov,
            confidence=Confidence(score=conf, rationale=rationale),
        )
    if verdict == "yes":
        return ApplicabilityDecision(
            plane=plane,
            applies=True,
            established=True,
            provenance=prov,
            confidence=Confidence(score=conf, rationale=rationale),
        )
    return None  # inconclusive -> descend to rung 3


def _gather_evidence(repo_path: str, max_chars: int = 12000) -> str:
    """Collect migrations, route files, and middleware for the model to read. Bounded."""
    root = Path(repo_path)
    chunks: list[str] = []
    interesting = ("migration", "route", "middleware", "auth", "api", "server", "agent", "tool")
    for path in root.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in (".ts", ".js", ".py", ".sql", ".json"):
            continue
        if any(part in _SKIP_DIRS for part in path.relative_to(root).parts):
            continue
        if not any(k in str(path).lower() for k in interesting):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        chunks.append(f"# {path.relative_to(root)}\n{text[:2000]}")
        if sum(len(c) for c in chunks) > max_chars:
            break
    return "\n\n".join(chunks)[:max_chars]


# --------------------------------------------------------------------------- #
# Rung 3 — behavioral probe (request plane)
# --------------------------------------------------------------------------- #
class BehavioralProbe:
    """Hits a route that should require login, with no credentials at all.

    If that route returns real data anyway, auth is missing or broken. The HTTP client is
    swappable so tests don't need the network.
    """

    def __init__(self, protected_paths: list[str], client: Optional[httpx.Client] = None):
        self.protected_paths = protected_paths
        self._client = client or httpx.Client(timeout=10.0)

    def run(self, plane: Plane, target: Target) -> Optional[ApplicabilityDecision]:
        if plane is not Plane.REQUEST:
            return None  # behavioral rung is defined for the request plane here
        for path in self.protected_paths:
            url = target.rest_base + path
            try:
                resp = self._client.get(url)  # no credentials
            except httpx.HTTPError:
                continue
            if resp.status_code == 200 and resp.text.strip() not in ("", "[]", "{}"):
                return ApplicabilityDecision(
                    plane=plane,
                    applies=True,
                    established=True,
                    provenance=Provenance(
                        origin=Register.PROOF,
                        rung=3,
                        detail=f"a request to {path} with no login returned real data",
                    ),
                    confidence=Confidence(
                        score=0.95, rationale="data went to a request with no login, so auth is missing or broken"
                    ),
                )
        return None  # inconclusive; caller falls through to run-under-doubt
