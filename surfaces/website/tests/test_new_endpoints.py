"""Website endpoints added in 0.2.0: /api/sarif and /api/ledger."""

from __future__ import annotations

from fastapi.testclient import TestClient

from backend.app import app

client = TestClient(app)


def test_sarif_endpoint_on_the_demo():
    r = client.post("/api/sarif", json={"repo": "demo/demo"})
    assert r.status_code == 200
    assert r.json()["version"] == "2.1.0"


def test_ledger_endpoint_on_the_demo():
    r = client.post("/api/ledger", json={"repo": "demo/demo"})
    assert r.status_code == 200
    assert "clean bill of health" in r.json()["reminder"]


def test_sarif_rejects_a_filesystem_path_like_every_other_endpoint():
    # Local mode is on in this suite; a traversal path is still refused by the validators.
    r = client.post("/api/sarif", json={"repo": "../etc"})
    assert r.status_code in (400, 401, 422)  # refused before it can read any path
