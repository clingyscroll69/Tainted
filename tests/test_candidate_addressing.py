"""One list, one set of handles: what a surface shows is what a surface can address.

`build_report` publishes candidates in discovery order and `AnalysisResult.ranked()` sorts them
structural-first then by model score. Both are legitimate orders of the same set, and that is
precisely the trap: a surface that *renders* one and *selects* from the other hands back a patch
for a hole the reader never pointed at. With the model enabled `rank_score` is not stable between
two runs, so the mismatch is not even reproducible.

These tests pin the shared helpers every surface addresses candidates through.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from tainted import analyze
from tainted.report import build_report, published_order, select_candidate

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def _result():
    return analyze(str(FIXTURES / "vulnerable_routes"))


def test_the_two_orders_really_do_disagree():
    """The premise. If this ever stops being true the tests below stop proving anything."""
    result = _result()
    assert [c.id for c in published_order(result)] != [c.id for c in result.ranked()]


def test_published_order_is_the_order_the_report_lists():
    result = _result()
    report = build_report(result)
    expected = [f.candidate for f in report.findings] + list(report.unproven_candidates)
    assert [c.id for c in published_order(result)] == [c.id for c in expected]


def test_index_addresses_the_published_row_not_the_ranked_one():
    result = _result()
    published = published_order(result)
    for i, expected in enumerate(published):
        assert select_candidate(result, index=i).id == expected.id


def test_finding_id_addresses_the_candidate_it_names():
    result = _result()
    for cand in result.candidates:
        assert select_candidate(result, finding_id=cand.id).id == cand.id


def test_finding_id_wins_over_index():
    result = _result()
    last = published_order(result)[-1]
    assert select_candidate(result, finding_id=last.id, index=0).id == last.id


def test_an_index_past_the_end_is_refused_by_name():
    result = _result()
    with pytest.raises(LookupError) as exc:
        select_candidate(result, index=len(result.candidates))
    assert "index" in str(exc.value)


def test_an_unknown_finding_id_is_refused_by_name():
    result = _result()
    with pytest.raises(LookupError) as exc:
        select_candidate(result, finding_id="nope")
    assert "nope" in str(exc.value)


def test_a_negative_index_is_refused_rather_than_wrapping():
    """`candidates[-1]` is a valid Python expression and the wrong candidate."""
    result = _result()
    with pytest.raises(LookupError):
        select_candidate(result, index=-1)


def test_published_order_carries_findings_first():
    """A proved finding is drawn above the untried candidates, so it is addressed that way too."""
    from tainted.models import Finding

    result = _result()
    last = result.candidates[-1]
    findings = [Finding(candidate=last)]
    assert published_order(result, findings)[0].id == last.id
    assert select_candidate(result, index=0, findings=findings).id == last.id
