"""Security-targeted mutation (B3): remove an authorization check, see if a test notices."""

from __future__ import annotations

import textwrap

from tainted.checks.security_mutation import (
    DROP_OWNER_EQ,
    INVERT_AUTHZ_GUARD,
    RLS_USING_TRUE,
    discover_security_mutants,
    run_security_mutation,
)


def _repo(tmp_path):
    (tmp_path / "route.ts").write_text(textwrap.dedent("""
        const { data } = await supabase.from('invoices').select('*')
          .eq('id', params.id).eq('user_id', user.id).single();
        if (!authorized) return res.status(403).end();
    """))
    (tmp_path / "policy.sql").write_text(
        "create policy p on invoices for select using (auth.uid() = owner_id);\n"
    )
    return str(tmp_path)


def test_all_three_operators_fire(tmp_path):
    ops = {m.operator.name for m in discover_security_mutants(_repo(tmp_path))}
    assert {DROP_OWNER_EQ.name, RLS_USING_TRUE.name, INVERT_AUTHZ_GUARD.name} <= ops


def test_drop_owner_eq_removes_the_owner_predicate(tmp_path):
    mutants = discover_security_mutants(_repo(tmp_path))
    m = next(m for m in mutants if m.operator is DROP_OWNER_EQ)
    assert "user_id" not in m.mutated and "params.id" in m.mutated


def test_rls_widens_to_true(tmp_path):
    mutants = discover_security_mutants(_repo(tmp_path))
    m = next(m for m in mutants if m.operator is RLS_USING_TRUE)
    assert "using (true)" in m.mutated and "auth.uid()" not in m.mutated


def test_a_blind_suite_leaves_every_mutant_surviving(tmp_path):
    result = run_security_mutation(_repo(tmp_path), judge=lambda m, t: False)
    assert result.ran and len(result.survived) == result.total and result.killed == 0


def test_a_watching_suite_kills_them(tmp_path):
    result = run_security_mutation(_repo(tmp_path), judge=lambda m, t: True)
    assert result.ran and result.survived == []


def test_no_runner_reports_unassessed_never_all_killed(tmp_path):
    result = run_security_mutation(_repo(tmp_path))
    assert result.ran is False
    assert len(result.survived) == result.total  # unassessed, not claimed killed
    assert "ran no suite" in result.note


def test_empty_repo_finds_nothing_to_mutate(tmp_path):
    (tmp_path / "plain.py").write_text("x = 1\n")
    result = run_security_mutation(str(tmp_path))
    assert result.total == 0 and "No removable" in result.note
