"""The built-in walkthrough: `tainted tutorial`."""

from __future__ import annotations

from typer.testing import CliRunner

from tainted_cli.main import app
from tainted_cli.tutorial import LESSONS

runner = CliRunner()


def test_no_argument_lists_every_topic():
    result = runner.invoke(app, ["tutorial"])
    assert result.exit_code == 0
    for lesson in LESSONS:
        assert lesson["topic"] in result.stdout


def test_a_topic_renders_its_steps():
    result = runner.invoke(app, ["tutorial", "first-scan"])
    assert result.exit_code == 0
    assert LESSONS[0]["title"] in result.stdout
    assert "tainted analyze" in result.stdout


def test_unknown_topic_names_the_real_ones():
    result = runner.invoke(app, ["tutorial", "nope"])
    assert result.exit_code != 0
    assert "first-scan" in result.output


def test_every_topic_renders():
    """A lesson with a malformed step should fail here, not in front of a reader."""
    for lesson in LESSONS:
        result = runner.invoke(app, ["tutorial", lesson["topic"]])
        assert result.exit_code == 0, lesson["topic"]


def test_the_gate_lesson_does_not_promise_an_attack():
    """`tainted-gate` runs analyze only. A tutorial that implies otherwise oversells proof."""
    body = " ".join(
        step["body"] for lesson in LESSONS if lesson["topic"] == "on-commit"
        for step in lesson["steps"]
    )
    assert "candidate" in body.lower()
