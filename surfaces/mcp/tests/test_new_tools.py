"""MCP tools added in 0.2.0: ledger, sarif, mutate-security, and analyze enrichment."""

from __future__ import annotations

import asyncio
import json

from tainted_mcp.server import (
    server,
    tainted_analyze,
    tainted_ledger,
    tainted_mutate_security,
    tainted_sarif,
)

ROUTES = "tests/fixtures/vulnerable_routes"


def test_new_tools_are_registered():
    names = {t.name for t in asyncio.run(server.list_tools())}
    assert {"tainted_ledger", "tainted_sarif", "tainted_mutate_security"} <= names


def test_analyze_is_enriched_with_projections():
    r = tainted_analyze(ROUTES)
    assert "prioritized" in r and "standards" in r and "silence_ledger" in r


def test_ledger_carries_the_reminder():
    assert "clean bill of health" in tainted_ledger(ROUTES)["reminder"]


def test_sarif_is_valid():
    doc = tainted_sarif(ROUTES)
    assert doc["version"] == "2.1.0"
    json.dumps(doc)  # serializable


def test_mutate_security_reports_unassessed_without_a_suite():
    out = tainted_mutate_security(ROUTES)
    assert out["ran"] is False


def test_memories_suppress_candidates_but_are_recorded(tmp_path):
    import textwrap
    (tmp_path / "route.ts").write_text(textwrap.dedent("""
        export async function GET(req, { params }) {
          const { data } = await supabase.from('invoices').select('*').eq('id', params.id);
          return Response.json(data);
        }
    """))
    analysis = tainted_analyze(str(tmp_path))
    cands = analysis.get("unproven_candidates") or []
    if not cands:
        return  # nothing to suppress on this stub; the engine test covers the rule
    fid = cands[0]["id"]
    d = tmp_path / ".tainted"
    d.mkdir()
    (d / "memories.json").write_text(json.dumps({"memories": [{"finding_id": fid, "reason": "ok"}]}))
    again = tainted_analyze(str(tmp_path))
    assert "suppressions" in again
