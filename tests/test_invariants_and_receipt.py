"""Plain-English invariants (B07) and the signed coverage receipt (B05).

The property both share is the one the rest of the market does not have: an explicit third state
for "nobody checked". The invariant checker must never file a translation failure as a rule that
held, and the receipt's signature must cover its own admissions so the silence cannot be edited
out of a document that still verifies.
"""

from __future__ import annotations

import json

import httpx

from tainted.dynamic.route_probes import RouteProber
from tainted.dynamic.target import Account, ProveSetup, SeedRecord, Target
from tainted.invariants import InvariantVerdict, check_invariants
from tainted.llm.client import LLMClient, LLMTier, LLMUnavailable
from tainted.models import (
    Candidate,
    Check,
    Exploit,
    Finding,
    FindingStatus,
    ProbeResult,
    Severity,
    SourceLocation,
)
from tainted.receipt import build_receipt, sign, verify, verify_payload
from tainted.report.model import build_report
from tainted.models import AnalysisResult

RULE = "No user should ever see another user's email address."


class ScriptedLLM(LLMClient):
    """Returns one fixed invariant translation, or raises."""

    def __init__(self, spec=None, raises=None):
        self._spec = spec
        self._raises = raises

    @property
    def available(self) -> bool:
        return True

    def complete_json(self, *, system, prompt, tier: LLMTier, schema):
        raise NotImplementedError

    def compile_invariant(self, rule, routes):
        if self._raises is not None:
            raise self._raises
        return dict(self._spec)


def _setup():
    return ProveSetup(
        target=Target(url="http://localhost:3000", anon_key="anon"),
        account_a=Account(label="A", access_token="tok-a", user_id="uid-a"),
        account_b=Account(label="B", access_token="tok-b", user_id="uid-b"),
        seed=SeedRecord(table="users", id="42"),
    )


def _repo_with_route(tmp_path):
    app = tmp_path / "app.py"
    app.write_text(
        "from flask import Flask\n"
        "app = Flask(__name__)\n\n"
        "@app.route('/api/users/<user_id>')\n"
        "def get_user(user_id):\n"
        "    return db.query('select * from users where id = %s' % user_id)\n",
        encoding="utf-8",
    )
    return str(tmp_path)


def _prober(handler, setup):
    return RouteProber(setup, client=httpx.Client(transport=httpx.MockTransport(handler)))


# ------------------------------ invariants (B07) ---------------------------- #
def test_a_rule_is_violated_when_the_marker_comes_back_on_a_2xx(tmp_path):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"email": "someone@else.com"})

    s = _setup()
    llm = ScriptedLLM({"route_path": "/api/users/<user_id>", "method": "GET", "violation_marker": "email"})
    report = check_invariants([RULE], _repo_with_route(tmp_path), s, llm=llm, prober=_prober(handler, s))

    assert report.results[0].verdict is InvariantVerdict.VIOLATED
    assert report.violated


def test_a_rule_holds_when_the_marker_is_absent(tmp_path):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"id": "42"})

    s = _setup()
    llm = ScriptedLLM({"route_path": "/api/users/<user_id>", "method": "GET", "violation_marker": "email"})
    report = check_invariants([RULE], _repo_with_route(tmp_path), s, llm=llm, prober=_prober(handler, s))
    assert report.results[0].verdict is InvariantVerdict.HELD


def test_an_error_page_echoing_the_marker_is_not_a_violation(tmp_path):
    """A 403 quoting the requested field back is a refusal, not a leak."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, json={"error": "you may not read email"})

    s = _setup()
    llm = ScriptedLLM({"route_path": "/api/users/<user_id>", "method": "GET", "violation_marker": "email"})
    report = check_invariants([RULE], _repo_with_route(tmp_path), s, llm=llm, prober=_prober(handler, s))
    assert report.results[0].verdict is InvariantVerdict.HELD


def test_no_model_is_not_tested_never_held(tmp_path):
    report = check_invariants([RULE], _repo_with_route(tmp_path), _setup(), llm=None)
    assert report.results[0].verdict is InvariantVerdict.NOT_TESTED
    assert report.results[0].verdict.is_evidence is False


def test_a_translation_failure_is_not_tested_never_held(tmp_path):
    s = _setup()
    llm = ScriptedLLM(raises=LLMUnavailable("no key"))
    report = check_invariants([RULE], _repo_with_route(tmp_path), s, llm=llm)
    assert report.results[0].verdict is InvariantVerdict.NOT_TESTED


def test_an_unreachable_target_is_not_tested_never_held(tmp_path):
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused")

    s = _setup()
    llm = ScriptedLLM({"route_path": "/api/users/<user_id>", "method": "GET", "violation_marker": "email"})
    report = check_invariants([RULE], _repo_with_route(tmp_path), s, llm=llm, prober=_prober(handler, s))
    r = report.results[0]
    assert r.verdict is InvariantVerdict.NOT_TESTED
    assert "not recorded as the rule holding" in r.detail


def test_no_marker_means_not_tested(tmp_path):
    """Without a definition of a violation, judging the response would be guesswork."""
    s = _setup()
    llm = ScriptedLLM({"route_path": "/api/users/<user_id>", "method": "GET", "violation_marker": ""})
    report = check_invariants([RULE], _repo_with_route(tmp_path), s, llm=llm)
    assert report.results[0].verdict is InvariantVerdict.NOT_TESTED


def test_non_local_target_without_ownership_fires_nothing(tmp_path):
    s = _setup()
    s.target = Target(url="https://not-mine.com")
    llm = ScriptedLLM({"route_path": "/api/users/<user_id>", "method": "GET", "violation_marker": "email"})
    report = check_invariants([RULE], _repo_with_route(tmp_path), s, llm=llm, ownership_verified=False)
    assert report.results[0].verdict is InvariantVerdict.NOT_TESTED


# ------------------------------- receipt (B05) ------------------------------ #
def _report_with_fired_finding():
    cand = Candidate(
        check=Check.BOLA,
        title="invoice readable by another account",
        location=SourceLocation(file="api.py", line=10),
        severity=Severity.HIGH,
    )
    finding = Finding(
        candidate=cand,
        status=FindingStatus.PROVEN,
        proof=ProbeResult(
            succeeded=True,
            kind="route_bola",
            exploit=Exploit(description="B read A's invoice", url="http://x/api/invoices/42", executed=True),
            response_status=200,
        ),
    )
    analysis = AnalysisResult(repo_path="/repo", candidates=[cand])
    return build_report(analysis, [finding])


def test_a_receipt_verifies_under_its_own_key():
    r = build_receipt(_report_with_fired_finding())
    sig = sign(r, b"secret")
    assert verify(r, sig, b"secret") is True
    assert verify(r, sig, b"other-secret") is False


def test_only_fired_attacks_are_listed_as_fired():
    """A static suspicion must not inflate the half a reader trusts least."""
    report = _report_with_fired_finding()
    report.findings[0].proof.exploit.executed = False
    assert build_receipt(report).fired == []


def test_deleting_the_silence_breaks_the_signature():
    """The property the whole module exists for: you cannot publish only the good half."""
    r = build_receipt(_report_with_fired_finding())
    sig = sign(r, b"secret")
    payload = r.as_dict(sig)

    assert verify_payload(payload, sig, b"secret") is True

    tampered = json.loads(json.dumps(payload))
    tampered["not_tested"] = {}  # strip the admissions, keep the findings
    assert verify_payload(tampered, sig, b"secret") is False


def test_editing_a_finding_breaks_the_signature():
    r = build_receipt(_report_with_fired_finding())
    sig = sign(r, b"secret")
    payload = r.as_dict(sig)
    payload["fired"][0]["succeeded"] = False
    assert verify_payload(payload, sig, b"secret") is False


def test_a_rewritten_digest_does_not_rescue_a_tampered_receipt():
    """Verification recomputes from content; it never trusts the document's own digest."""
    r = build_receipt(_report_with_fired_finding())
    sig = sign(r, b"secret")
    payload = r.as_dict(sig)
    payload["not_tested"] = {}
    payload["digest"] = "0" * 64
    assert verify_payload(payload, sig, b"secret") is False


def test_the_receipt_states_the_narrow_thing_it_proves():
    r = build_receipt(_report_with_fired_finding())
    assert "does not attest that the application is secure" in r.payload()["scope"]
