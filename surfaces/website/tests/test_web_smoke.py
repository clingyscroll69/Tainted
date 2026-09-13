"""Website backend smoke tests (run with core + this surface on the path)."""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from backend.app import app

client = TestClient(app)
REPO = str(Path(__file__).resolve().parents[3] / "tests" / "fixtures" / "vulnerable_supabase")


def test_healthz():
    assert client.get("/healthz").json()["ok"] is True


def test_analyze_returns_candidates():
    r = client.post("/api/analyze", json={"repo_path": REPO})
    assert r.status_code == 200
    assert r.json()["summary"]["total_candidates"] >= 2


def test_index_served_with_graph():
    assert "cytoscape" in client.get("/").text


def test_fix_returns_patch():
    r = client.post("/api/fix", json={"repo_path": REPO, "index": 0})
    assert r.status_code == 200
    assert r.json()["edits"]


def test_prove_ownership_gate():
    r = client.post(
        "/api/prove",
        json={"repo_path": REPO, "url": "https://x.vercel.app", "login_a": "a:b", "login_b": "c:d"},
    )
    assert r.status_code == 403
