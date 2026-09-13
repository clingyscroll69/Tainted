"""The CI walkthrough, and the next-steps block that says how far this pipeline reached."""

from __future__ import annotations

import pytest

from tainted_ci.entrypoint import _gap
from tainted_ci.render import render_next_steps, render_tutorial
from tainted_ci.tutorial import LESSONS, NEXT_STEPS
from tainted.dynamic.target import Account, ProveSetup, Target


def test_no_topic_lists_every_lesson():
    out = render_tutorial(None)
    for lesson in LESSONS:
        assert lesson["topic"] in out


def test_every_topic_renders():
    for lesson in LESSONS:
        out = render_tutorial(lesson["topic"])
        assert lesson["title"] in out
        for step in lesson["steps"]:
            assert step["heading"] in out


def test_unknown_topic_names_the_real_ones():
    assert "analyze-only" in render_tutorial("nope")


def test_the_first_lesson_carries_a_runnable_workflow():
    """The point of `analyze-only` is that the reader can paste it and get a gated PR."""
    out = render_tutorial("analyze-only")
    assert "tainted-ci" in out


@pytest.mark.parametrize("gap", sorted(NEXT_STEPS))
def test_next_steps_renders_for_every_gap(gap):
    out = render_next_steps(gap)
    assert "Next steps" in out
    assert NEXT_STEPS[gap] in out


def test_next_steps_falls_back_rather_than_emitting_an_empty_block():
    assert render_next_steps("something-new").strip()


def _setup(email_a="a@x", url="http://localhost:3000"):
    return ProveSetup(
        target=Target(url=url),
        account_a=Account(label="A", email=email_a, password="p"),
        account_b=Account(label="B", email="b@x", password="p"),
    )


def test_gap_is_no_target_without_a_url():
    assert _gap(None, [], "prove skipped: no TAINTED_TARGET_URL") == "no_target"


def test_gap_reports_an_ownership_refusal_over_a_missing_account():
    """A refusal is the more important thing to say, so it must win."""
    assert _gap(_setup(email_a=""), [], "prove refused: ownership not verified (x)") == (
        "ownership_refused"
    )


def test_gap_is_no_accounts_when_the_target_is_set_but_the_logins_are_not():
    assert _gap(_setup(email_a=""), [], "proved against x (local target)") == "no_accounts"


def test_gap_is_all_configured_when_prove_actually_ran():
    assert _gap(_setup(), [], "proved against x (local target)") == "all_configured"
