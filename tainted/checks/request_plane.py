"""The request plane — Broken Object Level Authorization (BOLA) and Row-Level Security (RLS).

Static analysis produces the candidate set; the LLM *ranks* it (never cuts it), because the
proof is a single request and the whole set can be fired — the model being wrong costs a
candidate its place in the queue, not its existence.

Three candidate sources feed one queue:
  * RLS audit (Supabase) — a client-read table with security off or a `true` policy is a
    structural hole confirmed on inspection. No ranking needed to be real.
  * BOLA route analysis — a route takes an id, feeds it to a query, and no predicate names the
    owner. Structure decides membership; the LLM's ownership judgment decides order.
  * Semgrep taint — the same bug where the parameter and the read are in different functions,
    which the per-handler scan cannot see. Additive, and skipped legibly when Semgrep is absent.
"""

from __future__ import annotations

from typing import Optional, Sequence

from tainted.checks.bola import analyze_bola
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
from tainted.static.semgrep import semgrep_bola_candidates
from tainted.static.supabase import SupabaseModel, TableModel, build_model


# --------------------------------------------------------------------------- #
# RLS audit -> candidates
# --------------------------------------------------------------------------- #
def audit_rls(model: SupabaseModel) -> list[Candidate]:
    """Flag every client-read table whose row-level security cannot stop cross-user reads.

    One precondition decides whether this audit can conclude anything: **the schema has to be
    in the repository.** Plenty of Supabase projects are managed from the dashboard, and there
    "no `ENABLE ROW LEVEL SECURITY` found" means the migrations are elsewhere, not that the
    table is unprotected. Reporting those as CRITICAL would flag every table in every such
    repo — the kind of false positive that teaches people to ignore the tool.
    """
    schema_present = any(t.declared for t in model.tables.values())
    candidates: list[Candidate] = []
    for table in model.tables.values():
        if not table.client_read:
            continue  # only tables the browser addresses directly are exposed this way
        candidate = _classify_table(table, schema_present)
        if candidate is not None:
            candidates.append(candidate)
    return candidates


def _classify_table(table: TableModel, schema_present: bool = True) -> Optional[Candidate]:
    site = table.read_sites[0] if table.read_sites else ""
    file, _, line = site.partition(":")
    loc = SourceLocation(file=file or "(migrations)", line=int(line) if line else 0)
    prov_structure = Provenance(
        origin=Register.STRUCTURE, detail="Supabase RLS audit of client-read table"
    )
    owner_column = table.infer_owner_column()
    base_meta = {
        "table": table.name,
        "read_sites": table.read_sites,
        "owner_column": owner_column,
        "columns": table.columns,
    }

    # Case 1 — RLS disabled entirely. The browser reads the table with no boundary at all.
    if not table.rls_enabled:
        if not schema_present:
            # No migrations in the repo: the schema is managed elsewhere. This is a candidate
            # for the live probe to settle, not a structural hole confirmed on inspection.
            return Candidate(
                check=Check.RLS,
                plane=Plane.REQUEST,
                title=f"Client-read table `{table.name}` with no schema in the repository",
                description=(
                    f"The browser reads `{table.name}` directly via `.from().select()`, but no "
                    f"migrations were found, so whether row-level security protects it cannot "
                    f"be established from the source. Run `prove` against the live target to "
                    f"settle it, or point Tainted at the repository holding the migrations."
                ),
                location=loc,
                source="browser (anon key)",
                sink=f".from('{table.name}').select()",
                structural=False,  # NOT confirmed on inspection — the schema is absent
                severity=Severity.MEDIUM,
                provenance=[
                    Provenance(
                        origin=Register.STRUCTURE,
                        detail="client read found; no migrations in repo to audit against",
                    )
                ],
                confidence=Confidence(
                    score=0.3,
                    rationale="absence of migrations is not evidence of absent protection",
                ),
                metadata={**base_meta, "schema_present": False},
            )
        return Candidate(
            check=Check.RLS,
            plane=Plane.REQUEST,
            title=f"Row-level security disabled on client-read table `{table.name}`",
            description=(
                f"The browser reads `{table.name}` directly via `.from().select()`, but the "
                f"table has no `ENABLE ROW LEVEL SECURITY`. Any client can read every row."
            ),
            location=loc,
            source="browser (anon key)",
            sink=f".from('{table.name}').select()",
            structural=True,
            severity=Severity.CRITICAL,
            provenance=[prov_structure],
            confidence=Confidence(score=0.9, rationale="RLS off is unambiguous in the SQL."),
            metadata=base_meta,
        )

    # Case 2 — RLS enabled but no SELECT policy references the owner (permissive or absent).
    permissive = [p for p in table.select_policies if p.is_permissive_true]
    owner_scoped = [p for p in table.select_policies if p.references_auth_uid]
    if permissive and not owner_scoped:
        pol = permissive[0]
        return Candidate(
            check=Check.RLS,
            plane=Plane.REQUEST,
            title=f"Permissive `true` RLS policy on `{table.name}`",
            description=(
                f"`{table.name}` has RLS enabled, but its SELECT policy \"{pol.name}\" uses "
                f"`using (true)`. Every caller passes. That is equivalent to no protection."
            ),
            location=SourceLocation(file=pol.source_file, line=pol.line),
            source="browser (anon key)",
            sink=f".from('{table.name}').select()",
            structural=True,
            severity=Severity.CRITICAL,
            provenance=[prov_structure],
            confidence=Confidence(score=0.9, rationale="`using (true)` passes every row."),
            metadata={**base_meta, "policy": pol.name},
        )

    if not table.has_select_policy:
        # RLS on but no SELECT policy — reads are actually denied by default. Not a leak;
        # more often a functional bug. Report at low severity for the record.
        return Candidate(
            check=Check.RLS,
            plane=Plane.REQUEST,
            title=f"RLS enabled but no SELECT policy on `{table.name}`",
            description=(
                f"`{table.name}` has RLS enabled and the client reads it, but no SELECT policy "
                f"exists — reads are denied by default. Likely a functional break, not a leak."
            ),
            location=loc,
            structural=True,
            severity=Severity.LOW,
            provenance=[prov_structure],
            confidence=Confidence(score=0.6, rationale="Default-deny with a client read path."),
            metadata=base_meta,
        )

    # Otherwise an owner-scoped policy exists — treated as safe here.
    return None


# --------------------------------------------------------------------------- #
# Ranking (the meaning register — order only, never membership)
# --------------------------------------------------------------------------- #
def rank_candidates(candidates: list[Candidate], llm: LLMClient) -> list[Candidate]:
    """Attach `rank_score` to each candidate. Structural holes keep score 1.0 regardless.

    If the LLM is unavailable, ordering falls back to structural-first + severity (see
    `AnalysisResult.ranked`); membership is never affected.
    """
    if not candidates:
        return candidates

    # Structural holes are certain; they lead the queue without consulting the model.
    to_rank = [c for c in candidates if not c.structural]
    for c in candidates:
        if c.structural:
            c.rank_score = 1.0

    if not to_rank:
        return candidates

    try:
        items = [
            {
                "title": c.title,
                "check": c.check.value,
                "source": c.source,
                "sink": c.sink,
                "location": str(c.location),
                "description": c.description,
            }
            for c in to_rank
        ]
        scores = llm.rank(items)
        for c, s in zip(to_rank, scores):
            c.rank_score = s
            c.provenance.append(
                Provenance(origin=Register.MEANING, detail="LLM rank (order only)")
            )
    except LLMUnavailable:
        for c in to_rank:
            c.rank_score = None  # AnalysisResult.ranked falls back deterministically
    return candidates


# --------------------------------------------------------------------------- #
# Static entry point for `analyze`
# --------------------------------------------------------------------------- #
def analyze_request_plane(
    repo_path: str,
    llm: Optional[LLMClient] = None,
    checks: Optional[set[Check]] = None,
    exclude: Sequence[str] = (),
) -> list[Candidate]:
    """Full request-plane static pass: RLS audit + BOLA route analysis + taint, then rank.

    Three candidate sources feed one queue:
      * the RLS audit (structural holes, certain on inspection),
      * route discovery (a read reached by a request parameter with no owner predicate),
      * Semgrep taint, when installed, which sees flows across function boundaries that the
        single-handler scan cannot.
    """
    checks = checks or {Check.BOLA, Check.RLS}
    candidates: list[Candidate] = []

    if Check.RLS in checks:
        candidates.extend(audit_rls(build_model(repo_path, exclude)))

    if Check.BOLA in checks:
        route_candidates = analyze_bola(repo_path, llm=llm, exclude=exclude)
        candidates.extend(route_candidates)
        # Semgrep taint traces a parameter into a query across calls; the single-handler scan
        # above cannot. Merged rather than replaced, and deduplicated by location.
        candidates.extend(
            _new_locations(semgrep_bola_candidates(repo_path, exclude=exclude), candidates)
        )

    if llm is not None:
        # RLS holes are structural (score 1.0, no model call); BOLA candidates were already
        # judged in `analyze_bola`. This ranks whatever is left unscored.
        rank_candidates([c for c in candidates if c.rank_score is None], llm)
    return candidates


def _new_locations(new: list[Candidate], existing: list[Candidate]) -> list[Candidate]:
    """Drop candidates whose file:line another source already reported."""
    seen = {(c.location.file, c.location.line) for c in existing}
    return [c for c in new if (c.location.file, c.location.line) not in seen]
