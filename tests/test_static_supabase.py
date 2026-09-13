"""Static request-plane analysis: the Supabase RLS audit and candidate generation."""

from __future__ import annotations

from tainted.checks.request_plane import analyze_request_plane, audit_rls, rank_candidates
from tainted.models import Check, Severity
from tainted.static.parsing import find_supabase_table_ops
from tainted.static.supabase import build_model, parse_migration_sql, SupabaseModel


# --------------------------------------------------------------------------- #
# tree-sitter client-read discovery
# --------------------------------------------------------------------------- #
def test_finds_supabase_reads_and_writes():
    src = """
    const a = await supabase.from('invoices').select('*').eq('id', id);
    await supabase.from("notes").insert({ body });
    supabase.from(`profiles`).select('id').eq('user_id', u);
    """
    ops = find_supabase_table_ops(src, "typescript")
    by_table = {o.table: o for o in ops}
    assert by_table["invoices"].is_read and not by_table["invoices"].is_write
    assert by_table["notes"].is_write and not by_table["notes"].is_read
    assert by_table["profiles"].is_read  # backtick template string handled


# --------------------------------------------------------------------------- #
# SQL migration parsing
# --------------------------------------------------------------------------- #
def test_parse_rls_enable_and_policies():
    model = SupabaseModel()
    parse_migration_sql(
        """
        create table public.invoices (id uuid primary key, owner uuid);
        alter table public.invoices enable row level security;
        create policy "p" on public.invoices for select using (auth.uid() = owner);
        """,
        "m.sql",
        model,
    )
    inv = model.table("invoices")
    assert inv.declared and inv.rls_enabled
    assert inv.has_select_policy
    assert inv.select_policies[0].references_auth_uid


def test_sql_comments_do_not_match_ddl_regexes():
    model = SupabaseModel()
    parse_migration_sql(
        "-- (no alter table foo enable row level security)\n"
        "create table public.foo (id uuid primary key);",
        "m.sql",
        model,
    )
    # The commented-out ALTER must not register as RLS enabled, and no phantom table appears.
    assert model.table("foo").rls_enabled is False
    assert "" not in model.tables


def test_permissive_true_policy_detected():
    model = SupabaseModel()
    parse_migration_sql(
        'create policy "x" on public.t for select using ( true );', "m.sql", model
    )
    assert model.table("t").select_policies[0].is_permissive_true


# --------------------------------------------------------------------------- #
# Audit -> candidates
# --------------------------------------------------------------------------- #
def test_audit_flags_holes_and_spares_safe_table(vuln_repo):
    model = build_model(vuln_repo)
    candidates = audit_rls(model)
    titles = {c.metadata.get("table"): c for c in candidates}

    # profiles has a correct auth.uid() policy — must NOT be flagged.
    assert "profiles" not in titles
    # notes (RLS off) and invoices (permissive true) are holes.
    assert titles["notes"].check == Check.RLS
    assert titles["notes"].severity == Severity.CRITICAL
    assert titles["invoices"].severity == Severity.CRITICAL
    assert titles["invoices"].structural is True


def test_analyze_orders_structural_first_without_llm(vuln_repo):
    from tainted.models import AnalysisResult

    candidates = analyze_request_plane(vuln_repo)
    result = AnalysisResult(repo_path=vuln_repo, candidates=candidates)
    ranked = result.ranked()
    assert all(c.structural for c in ranked)  # all fixture holes are structural
    # Severity respected within the deterministic fallback.
    assert ranked[0].severity.rank >= ranked[-1].severity.rank


# --------------------------------------------------------------------------- #
# Ranking (meaning register) — order only, never membership
# --------------------------------------------------------------------------- #
def test_rank_is_order_only_never_drops(vuln_repo, fake_llm):
    candidates = audit_rls(build_model(vuln_repo))
    before = len(candidates)
    ranked = rank_candidates(candidates, fake_llm)
    assert len(ranked) == before  # membership unchanged
    # Structural holes are scored 1.0 without consulting the model.
    assert all(c.rank_score == 1.0 for c in ranked if c.structural)
