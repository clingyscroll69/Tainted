"""The index a calling agent reads out of `tainted_analyze` must be the one `tainted_fix` uses.

`tainted_analyze` returns `build_report(...)` — discovery order, findings then untried. `fix` and
`fix_interview` were selecting out of `result.ranked()`, which is a different order of the same
set. An agent that read row 0 off the report and asked to fix index 0 got a patch for some other
hole, and with the model enabled the divergence is not even reproducible between two runs.
"""

from __future__ import annotations

from pathlib import Path

import time

from tainted_mcp.server import (
    _JOBS,
    _JOBS_LOCK,
    _MAX_JOBS,
    _evict_finished,
    _Job,
    tainted_analyze,
    tainted_fix,
    tainted_fix_interview,
)

FIXTURES = Path(__file__).resolve().parents[3] / "tests" / "fixtures"
ROUTES = str(FIXTURES / "vulnerable_routes")


def _published(report: dict) -> list[dict]:
    return [f["candidate"] for f in report["findings"]] + report["unproven_candidates"]


def test_analyze_publishes_stable_ids_for_every_candidate():
    published = _published(tainted_analyze(ROUTES))
    ids = [c["id"] for c in published]
    assert ids and len(set(ids)) == len(ids)
    assert ids == [c["id"] for c in _published(tainted_analyze(ROUTES))]


def test_fix_index_addresses_the_row_analyze_published():
    published = _published(tainted_analyze(ROUTES))
    for i, expected in enumerate(published):
        out = tainted_fix_interview(ROUTES, index=i)
        assert "error" not in out
        # A deterministic check answers with a note; a tool-plane one with questions. Either
        # way the candidate it is talking about is named, and it is this row's.
        assert out.get("candidate", expected["title"]) == expected["title"] or out.get("note")


def test_fix_by_finding_id_addresses_the_candidate_it_names():
    published = _published(tainted_analyze(ROUTES))
    target = published[-1]
    out = tainted_fix(ROUTES, finding_id=target["id"])
    assert "error" not in out, out
    assert out["finding"]["candidate"]["id"] == target["id"]


def test_finding_id_beats_index():
    published = _published(tainted_analyze(ROUTES))
    target = published[-1]
    out = tainted_fix(ROUTES, finding_id=target["id"], index=0)
    assert out["finding"]["candidate"]["id"] == target["id"]


def test_an_unknown_finding_id_is_an_error_naming_it():
    out = tainted_fix(ROUTES, finding_id="deadbeef")
    assert "deadbeef" in out.get("error", "")


def test_an_index_past_the_end_is_still_an_error_object():
    n = len(_published(tainted_analyze(ROUTES)))
    out = tainted_fix(ROUTES, index=n)
    assert "error" in out and str(n) in out["error"]


def test_analyze_will_not_be_talked_into_running_the_repositorys_tests():
    """`test_integrity` runs the target repo's suite through mutmut/Stryker.

    `tainted_analyze` is described to the calling agent as read-only, and a tool whose
    description says read-only must not be one argument away from executing a stranger's code.
    """
    out = tainted_analyze(ROUTES, only="test_integrity")
    assert "error" in out
    assert "test_integrity" in out["error"]


# --------------------------------------------------------------------------- #
# What a long-lived server keeps
# --------------------------------------------------------------------------- #
def test_finished_jobs_are_evicted_and_running_ones_are_not():
    """Over SSE this process outlives the session, so the job table has to have a ceiling."""
    saved = dict(_JOBS)
    try:
        _JOBS.clear()
        for i in range(_MAX_JOBS + 10):
            _JOBS[f"old-{i}"] = _Job(status="done", finished=0.0)  # finished long ago
        _JOBS["live"] = _Job(status="running")
        with _JOBS_LOCK:
            _evict_finished()
        assert "live" in _JOBS, "a running job must never be evicted out from under its poller"
        assert len(_JOBS) <= _MAX_JOBS + 1
    finally:
        _JOBS.clear()
        _JOBS.update(saved)


def test_a_fresh_finished_job_survives_eviction():
    saved = dict(_JOBS)
    try:
        _JOBS.clear()
        _JOBS["fresh"] = _Job(status="done", finished=time.time())
        with _JOBS_LOCK:
            _evict_finished()
        assert "fresh" in _JOBS
    finally:
        _JOBS.clear()
        _JOBS.update(saved)
