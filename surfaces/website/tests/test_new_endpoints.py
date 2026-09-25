"""The three endpoints the new engine operations reach the browser through.

The gate is the thing under test. `/api/invariants` and `/api/lockout` fire real requests at a
target, so they must inherit exactly the ownership refusal `/api/prove` has — a second door onto
the same capability with a weaker lock would undo the boundary rather than extend it.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from backend.app import app

client = TestClient(app)


def _demo(**extra):
    return {"repo": "demo/demo", **extra}


# ---------------------------------- receipt --------------------------------- #
def test_receipt_carries_its_untested_surface_and_admits_it_is_unsigned():
    r = client.post("/api/receipt", json=_demo())
    assert r.status_code == 200
    body = r.json()
    assert body["version"] == "tainted-receipt/1"
    assert "not_tested" in body
    assert "signature" not in body
    assert "not signed" in body["unsigned"]


def test_a_receipt_of_the_page_s_prove_run_lists_what_fired():
    """An analysis fires nothing; the report of the prove run on screen is what fired."""
    from tainted.models import (
        AnalysisResult, Candidate, Check, Exploit, Finding, FindingStatus, ProbeResult,
        Severity, SourceLocation,
    )
    from tainted.report import build_report

    cand = Candidate(check=Check.BOLA, title="invoice leak", severity=Severity.HIGH,
                     location=SourceLocation(file="app.py", line=1))
    finding = Finding(candidate=cand, status=FindingStatus.PROVEN, proof=ProbeResult(
        succeeded=True, kind="route_bola",
        exploit=Exploit(description="x", url="http://localhost:3000/api/invoices/42", executed=True),
    ))
    report = build_report(AnalysisResult(repo_path=".", candidates=[cand]), [finding])
    body = client.post(
        "/api/receipt", json={**_demo(), "report": report.model_dump(mode="json")}
    ).json()
    assert [r["status"] for r in body["fired"]] == ["proven"]
    assert client.post("/api/receipt", json={**_demo(), "report": {"findings": 3}}).status_code == 422


def test_the_receipt_payload_is_verifiable_by_whoever_signs_it():
    """The server does not sign, but what it returns must be signable and tamper-evident."""
    body = client.post("/api/receipt", json=_demo()).json()

    from tainted.receipt import Receipt, sign, verify_payload

    rec = Receipt(
        repo_path=body["repo"],
        fired=body["fired"],
        not_tested=body["not_tested"],
        catalogues=body["catalogues"],
        version=body["version"],
    )
    sig = sign(rec, b"caller-key")
    assert verify_payload(body, sig, b"caller-key") is True

    body["not_tested"] = {}
    assert verify_payload(body, sig, b"caller-key") is False


# --------------------------------- invariants ------------------------------- #
def test_invariants_without_rules_is_refused():
    r = client.post("/api/invariants", json=_demo(url="http://localhost:3000", rules=[]))
    assert r.status_code == 422


def test_invariants_without_a_target_is_refused():
    r = client.post("/api/invariants", json=_demo(url="", rules=["no cross-user reads"]))
    assert r.status_code == 422


def test_invariants_rejects_a_non_http_target_at_the_model():
    r = client.post(
        "/api/invariants", json=_demo(url="file:///etc/passwd", rules=["no cross-user reads"])
    )
    assert r.status_code == 422


# ---------------------------------- lockout --------------------------------- #
def test_lockout_without_a_target_is_refused():
    r = client.post("/api/lockout", json=_demo(url=""))
    assert r.status_code == 422


def test_lockout_rejects_a_non_http_target_at_the_model():
    r = client.post("/api/lockout", json=_demo(url="ftp://example.com"))
    assert r.status_code == 422


def test_lockout_on_a_local_target_reports_undecided_rather_than_ok():
    """No seed record means nothing was tested, and nothing tested must never come back ok."""
    r = client.post("/api/lockout", json=_demo(url="http://localhost:9"))
    if r.status_code == 200:
        body = r.json()
        assert body["ok"] is False
        assert body["undecided"]
    else:
        # A hosted posture refuses it outright; either way it is not a pass.
        assert r.status_code in (401, 403)


# --------------------------------------------------------------------------- #
# The frontend, wired to the three endpoints
#
# The design system's Lamp Rule says warm ink may appear ONLY where an exploit executed and
# succeeded. Two of these panels can report a failure that is not an exploit, so these tests
# pin that they do not light the lamp for it.
# --------------------------------------------------------------------------- #
from pathlib import Path  # noqa: E402

FRONTEND = Path(__file__).resolve().parent.parent / "frontend" / "index.html"


def _page() -> str:
    return FRONTEND.read_text(encoding="utf-8")


def test_the_three_panels_exist_and_are_wired():
    page = _page()
    for element_id in ("ruleslist", "locklist", "receiptbox", "f-rules", "checklock", "getreceipt"):
        assert f'id="{element_id}"' in page, element_id
    for endpoint in ("/api/invariants", "/api/lockout", "/api/receipt"):
        assert f"'{endpoint}'" in page, endpoint


def test_a_violated_rule_is_the_only_rule_verdict_that_lights_the_lamp():
    """A violated rule IS a fired exploit that succeeded, so it earns the lamp — and held and
    not-tested must not, because nothing succeeded in either."""
    page = _page()
    assert "const RULE_MARK = {violated: 'lamp', held: 'nr', not_tested: ''}" in page


def test_the_owner_access_panel_never_lights_the_lamp():
    """A locked-out owner is the opposite failure: no exploit ran, so no warm ink may appear.

    The panel's marks are `ok` (cyan ring, the verified state) and `shut` (a cold barred dot).
    Neither resolves to the lamp, and the panel says out loud why it stays dark.
    """
    page = _page()
    assert "c.owner_locked_out ? 'shut' : 'ok'" in page
    assert "No lamp here, whatever the result" in page
    # The lockout CSS must not reach for either warm token.
    lock_css = page[page.index(".lock{list-style"):page.index(".lock .why")]
    assert "--lamp" not in lock_css and "--held" not in lock_css


def test_every_state_mark_has_a_word_beside_it():
    """The Stated-State Rule: no state carried by colour or shape alone."""
    page = _page()
    assert "RULE_WORD = {violated: 'Violated', held: 'Held', not_tested: 'Not tested'}" in page
    assert "'LOCKED OUT' : 'REACHABLE'" in page
    # The dots are decorative; the word is the state.
    assert page.count('<span class="dot ' + "' + mark + '" + '" aria-hidden="true">') == 1


def test_nothing_checked_is_never_drawn_as_a_pass():
    page = _page()
    assert "NOT A PASS" in page
    assert "never as a\n            rule that held" in page or "never as a rule that held" in page


def test_the_receipt_panel_prints_the_engines_own_unsigned_sentence():
    """Printed as it comes, not restated — the panel must not stutter the same caveat twice."""
    page = _page()
    assert "ESC(rec.unsigned || '')" in page
    assert page.count("Sign this payload with your own key") == 0
