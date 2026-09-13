"""Watching a run instead of waiting for it.

`prove` blocks for as long as the real attacks take. A caller that asks for NDJSON gets the run
reported as it happens; a caller that does not gets exactly the single JSON body it always got.
The tests that matter here are about honesty rather than plumbing: the stream may not claim
progress an executor cannot observe, and it may not re-order the run to suit a picture.
"""

from __future__ import annotations

import json
import os

import httpx
import pytest
from fastapi.testclient import TestClient

from backend import app as app_module
from backend import demo as demo_mode
from backend.sandbox import CloudflareExecutor, LocalExecutor

client = TestClient(app_module.app)
NDJSON = {"Accept": "application/x-ndjson"}


@pytest.fixture(autouse=True)
def _instant_demo(monkeypatch):
    """The demo's pacing is asserted in test_demo.py; here only its shape is under test."""
    monkeypatch.setenv("TAINTED_DEMO_INSTANT", "1")


def _events(response) -> list[dict]:
    return [json.loads(line) for line in response.text.strip().splitlines()]


def _demo_stream() -> list[dict]:
    r = client.post("/api/prove", json={"repo_path": "demo/demo", "url": ""}, headers=NDJSON)
    assert r.status_code == 200
    return _events(r)


# --------------------------------------------------------------------------- #
# The two deliveries
# --------------------------------------------------------------------------- #
def test_without_the_ndjson_header_prove_is_the_single_json_body_it_always_was():
    r = client.post("/api/prove", json={"repo_path": "demo/demo", "url": ""})
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("application/json")
    assert r.json()["summary"]["proven"] >= 1


def test_asking_for_ndjson_gets_the_run_as_events():
    r = client.post("/api/prove", json={"repo_path": "demo/demo", "url": ""}, headers=NDJSON)
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("application/x-ndjson")


def test_the_stream_is_not_compressed():
    """A compressor holds bytes back until it has enough of them, which for a progress stream
    means holding the whole run until it is over — the exact thing streaming exists to avoid."""
    r = client.post(
        "/api/prove",
        json={"repo_path": "demo/demo", "url": ""},
        headers={**NDJSON, "Accept-Encoding": "gzip"},
    )
    assert r.headers.get("content-encoding") != "gzip"


# --------------------------------------------------------------------------- #
# What the events say
# --------------------------------------------------------------------------- #
def test_the_first_event_says_whether_progress_is_coming_at_all():
    events = _demo_stream()
    assert events[0] == {"event": "open", "streams": True}


def test_one_finding_event_per_candidate_and_the_report_last():
    events = _demo_stream()
    kinds = [e["event"] for e in events]
    assert kinds[0] == "open"
    assert kinds[-1] == "report"
    cands = next(e for e in events if e["event"] == "candidates")["candidates"]
    findings = [e["finding"] for e in events if e["event"] == "finding"]
    assert len(findings) == len(cands)
    # Every finding arrives before the report that contains it.
    assert kinds.index("candidates") < kinds.index("finding") < kinds.index("report")


def test_the_stream_is_in_the_order_the_engine_attempts_them_not_depth_order():
    """`orchestrator.prove` iterates `analysis.ranked()` — structural first, then model rank,
    then severity. The check axis is not in that sort key, so results genuinely arrive out of
    depth order, and the stream must not quietly fix that up. A surface wanting depth order has
    to hold results back itself and be honest that it is doing so."""
    events = _demo_stream()
    ranked = [c["check"] for c in next(e for e in events if e["event"] == "candidates")["candidates"]]
    streamed = [e["finding"]["candidate"]["check"] for e in events if e["event"] == "finding"]
    assert streamed == ranked
    depth_order = ["test_integrity", "classic_injection", "agent_injection", "bola", "rls"]
    by_depth = sorted(streamed, key=depth_order.index)
    assert streamed != by_depth, "the demo no longer exercises out-of-order arrival"


def test_the_streamed_report_is_the_same_report_the_batch_call_returns():
    """The report is the authority. The events are a view of it and may not disagree."""
    batch = client.post("/api/prove", json={"repo_path": "demo/demo", "url": ""}).json()
    streamed = next(e for e in _demo_stream() if e["event"] == "report")["report"]
    assert streamed["summary"] == batch["summary"]
    assert [f["candidate"]["title"] for f in streamed["findings"]] == [
        f["candidate"]["title"] for f in batch["findings"]
    ]


def test_every_streamed_finding_appears_in_the_final_report():
    events = _demo_stream()
    streamed = [e["finding"]["candidate"]["title"] for e in events if e["event"] == "finding"]
    report = next(e for e in events if e["event"] == "report")["report"]
    assert sorted(streamed) == sorted(f["candidate"]["title"] for f in report["findings"])


# --------------------------------------------------------------------------- #
# An executor that cannot watch its own run must say so
# --------------------------------------------------------------------------- #
def test_the_local_executor_streams_and_the_sandboxed_one_does_not():
    assert LocalExecutor.streams is True
    assert CloudflareExecutor.streams is False


def test_a_sandboxed_deployment_reports_no_progress_rather_than_inventing_it(monkeypatch):
    """The worker runs the whole engine behind one request and hands back a finished Report, so
    there is nothing honest to emit before it lands. The `open` event has to admit that: silence
    from a slow run and silence from an unobservable one look identical, and a progress indicator
    that cannot tell them apart will animate toward a finish line nobody measured."""
    report = LocalExecutor().analyze(str(app_module.FRONTEND.parent))

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=report.model_dump(mode="json"))

    executor = CloudflareExecutor(
        "https://sandbox.example", "tok",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    monkeypatch.setattr(app_module, "_executor", executor)

    r = client.post(
        "/api/prove",
        json={"repo_path": str(app_module.FRONTEND.parent), "url": "http://localhost:3000"},
        headers=NDJSON,
    )
    assert r.status_code == 200
    events = _events(r)
    assert events[0] == {"event": "open", "streams": False}
    assert not [e for e in events if e["event"] in ("candidates", "finding")]
    assert events[-1]["event"] == "report"


# --------------------------------------------------------------------------- #
# Failure
# --------------------------------------------------------------------------- #
def test_the_ownership_gate_is_still_a_status_code_not_an_event():
    """The gate runs before the first byte, so refusing a remote target stays a real 403 — a
    refusal buried inside a 200 is a refusal a caller can miss."""
    r = client.post(
        "/api/prove",
        json={"repo_path": ".", "url": "https://not-mine.example"},
        headers=NDJSON,
    )
    assert r.status_code == 403


def test_a_failure_after_the_first_byte_arrives_as_an_error_event(monkeypatch):
    class Broken:
        streams = True

        def prove(self, *a, **k):
            raise RuntimeError("the engine fell over")

    monkeypatch.setattr(app_module, "_executor", Broken())
    r = client.post(
        "/api/prove",
        json={"repo_path": str(app_module.FRONTEND.parent), "url": "http://localhost:3000"},
        headers=NDJSON,
    )
    assert r.status_code == 200  # a status cannot be recalled once the stream has opened
    err = _events(r)[-1]
    assert err["event"] == "error"
    assert err["status"] == 500
    assert "the engine fell over" in err["detail"]


# --------------------------------------------------------------------------- #
# The demo is the path most people watch, so it has to stream too
# --------------------------------------------------------------------------- #
def test_the_demo_reports_each_probe_as_it_happens():
    seen: list = []
    demo_mode.demo_prove_stream(
        on_candidates=lambda cs: seen.append(("candidates", len(cs))),
        on_finding=lambda f: seen.append(("finding", f.candidate.check.value)),
        sleep=lambda _s: None,
    )
    assert seen[0][0] == "candidates"
    assert seen[0][1] == len([s for s in seen if s[0] == "finding"])


def test_the_streamed_demo_and_the_batch_demo_cannot_disagree():
    a = demo_mode.demo_prove_stream(sleep=lambda _s: None)
    b = demo_mode.demo_prove_report(sleep=lambda _s: None)
    assert a.model_dump(mode="json") == b.model_dump(mode="json")
