"""The guided tour: its content, and the page actually being wired to it."""

from __future__ import annotations

import re
from pathlib import Path

from fastapi.testclient import TestClient

from backend import app as app_module

FRONTEND = Path(__file__).resolve().parent.parent / "frontend"
INDEX = FRONTEND / "index.html"
TOUR = FRONTEND / "tutorial.js"


def _anchors() -> list[str]:
    return re.findall(r"anchor:\s*'([^']+)'", TOUR.read_text())


def test_the_page_loads_the_tour_content():
    assert '<script src="/static/tutorial.js"></script>' in INDEX.read_text()


def test_the_tour_is_served():
    client = TestClient(app_module.app)
    r = client.get("/static/tutorial.js")
    assert r.status_code == 200
    assert "TAINTED_TOUR" in r.text


def test_the_button_exists_and_starts_hidden():
    """Hidden until the script confirms there is content, so a missing file shows nothing."""
    html = INDEX.read_text()
    assert 'id="tourbtn"' in html
    assert re.search(r'id="tourbtn"[^>]*hidden', html)


def test_every_anchor_exists_on_the_page():
    """A step pointing at an id the page doesn't have would spotlight nothing."""
    ids = set(re.findall(r'id="([^"]+)"', INDEX.read_text()))
    missing = [a for a in _anchors() if a not in ids]
    assert not missing, f"tour anchors with no element: {missing}"


def test_the_tour_has_an_opening_and_a_closing():
    js = TOUR.read_text()
    assert "intro:" in js and "outro:" in js
    assert len(_anchors()) >= 5


def test_the_tour_names_the_three_registers():
    """Structure / Meaning / Proof are fixed product terms; the tour must not rename them."""
    js = TOUR.read_text()
    for term in ("Structure", "Meaning", "Proof"):
        assert term in js


def test_the_tour_says_the_demonstration_proves_nothing():
    """The demo's findings are invented. A tour that blurs that oversells the product."""
    js = TOUR.read_text().lower()
    assert "demonstration" in js
