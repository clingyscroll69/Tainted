"""The fix a reader asks for is the fix they get.

The browser draws findings in the order `Report` lists them. `/api/fix` used to take the row's
*position* and index `AnalysisResult.ranked()` — a different ordering of the same set, produced
by a second analysis run. On any repo where the two disagree, clicking "Write the fix" on one
finding returned the patch for another; with the model enabled the ranking is not even stable
between the two calls.

These tests pin the contract that replaces it: a candidate carries an id, the id is stable
across separate analyses of the same tree, and the fix endpoint resolves by id.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from backend.app import app
from tainted import analyze as core_analyze
from tainted.report import build_report


# A repository with three candidates whose discovery order and ranked order differ — which is
# what makes the old positional contract fail. Written out rather than reused from the engine
# fixtures so the disagreement is explicit and cannot drift away.
FILES = {
    "app/api/orders/[id]/route.ts": """
import { createServerClient } from '@supabase/ssr'
export async function GET(req, { params }) {
  const { id } = await params
  const db = createServerClient(process.env.URL, process.env.KEY, {})
  const { data } = await db.from('orders').select('*').eq('id', id).single()
  return Response.json(data)
}
""",
    "app/api/admin/route.ts": """
import postgres from 'postgres'
const sql = postgres(process.env.DATABASE_URL)
export async function GET(req) {
  const q = new URL(req.url).searchParams.get('q')
  const rows = await sql.unsafe(`SELECT * FROM users WHERE email LIKE '%${q}%'`)
  return Response.json(rows)
}
""",
    "supabase/migrations/0001_init.sql": """
create table orders (id uuid primary key, user_id uuid references auth.users);
""",
    "package.json": json.dumps(
        {"dependencies": {"next": "15.0.0", "@supabase/ssr": "^0.5.0", "postgres": "^3.4.0"}}
    ),
}


@pytest.fixture
def repo(tmp_path: Path) -> str:
    for rel, body in FILES.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body)
    return str(tmp_path)


@pytest.fixture
def client(monkeypatch) -> TestClient:
    # A local path is a local-mode-only affordance; the fix endpoint is reached through it.
    monkeypatch.setenv("TAINTED_LOCAL_MODE", "1")
    return TestClient(app)


def test_candidate_ids_are_stable_across_analyses(repo: str):
    """Two analyses of one unchanged tree produce the same ids for the same holes.

    This is the whole load-bearing property. If it fails, resolving a fix by id is no better
    than resolving it by position.
    """
    first = {c.id for c in core_analyze(repo).candidates}
    second = {c.id for c in core_analyze(repo).candidates}
    assert first == second
    assert len(first) == len(core_analyze(repo).candidates), "ids must be unique per candidate"


def test_report_order_and_ranked_order_actually_disagree(repo: str):
    """The precondition for the bug. If this ever stops holding, the guard below goes slack."""
    result = core_analyze(repo)
    report = build_report(result)
    report_order = [c.id for c in report.unproven_candidates]
    ranked_order = [c.id for c in result.ranked()]
    assert sorted(report_order) == sorted(ranked_order)
    assert report_order != ranked_order, (
        "this fixture is supposed to order differently in the report than in ranked(); "
        "positional addressing would silently work otherwise"
    )


def test_fix_by_id_returns_the_candidate_that_was_asked_for(repo: str, client: TestClient):
    """Every id in the report resolves to its own finding — the regression test for C4."""
    report = client.post("/api/analyze", json={"repo_path": repo}).json()
    rows = report["unproven_candidates"]
    assert len(rows) >= 3

    for row in rows:
        got = client.post(
            "/api/fix", json={"repo_path": repo, "finding_id": row["id"]}
        )
        assert got.status_code == 200, got.text
        body = got.json()
        # A tool-plane fix answers with an interview instead of edits; neither shape may
        # come back describing some other hole.
        if "finding" in body:
            assert body["finding"]["candidate"]["id"] == row["id"]
            assert body["finding"]["candidate"]["title"] == row["title"]


def test_positional_index_still_works_and_still_agrees(repo: str, client: TestClient):
    """`index` is kept for one release, but it now addresses the order the report published."""
    report = client.post("/api/analyze", json={"repo_path": repo}).json()
    rows = report["unproven_candidates"]
    for i, row in enumerate(rows):
        body = client.post("/api/fix", json={"repo_path": repo, "index": i}).json()
        if "finding" in body:
            assert body["finding"]["candidate"]["id"] == row["id"]


def test_negative_index_is_refused(repo: str, client: TestClient):
    """It used to wrap and hand back the last candidate's patch."""
    r = client.post("/api/fix", json={"repo_path": repo, "index": -1})
    assert r.status_code == 422


def test_unknown_id_is_refused(repo: str, client: TestClient):
    r = client.post("/api/fix", json={"repo_path": repo, "finding_id": "deadbeefdeadbeef"})
    assert r.status_code == 400
    assert "no finding" in r.json()["detail"].lower()


def test_demo_fix_is_addressable_by_id(client: TestClient):
    """The demo is the one path open to everyone; it must honour the same contract."""
    report = client.post("/api/analyze", json={"repo": "demo/demo"}).json()
    rows = report["unproven_candidates"]
    assert rows and all(r["id"] for r in rows)
    body = client.post(
        "/api/fix", json={"repo": "demo/demo", "finding_id": rows[1]["id"]}
    ).json()
    assert body["finding"]["candidate"]["id"] == rows[1]["id"]
