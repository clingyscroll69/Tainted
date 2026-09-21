"""Static-only runs must say the meaning register was off.

Without `GEMINI_API_KEY` every `rank_score` comes back `null` and every provenance says
`structure`, and the CLI printed all of it without a word about why. The reader cannot tell a
repo the model ranked as harmless from one the model never looked at — which is the same
silence the coverage column exists to break, one level up. The website already announces its
configuration gaps at startup; this is that, for the local loop.
"""

from __future__ import annotations

import pytest

from tainted.models import AnalysisResult
from tainted.report import build_report
from tainted_cli import render


@pytest.fixture
def no_key(monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("GOOGLE_API_KEY", raising=False)


def _render(capsys) -> str:
    render.render_report(build_report(AnalysisResult(repo_path=".")))
    return capsys.readouterr().out


def test_a_run_without_a_key_says_the_meaning_register_was_off(no_key, capsys):
    out = _render(capsys)
    assert "GEMINI_API_KEY" in out
    assert "static" in out.lower()


def test_a_run_with_a_key_does_not_nag(monkeypatch, capsys):
    monkeypatch.setenv("GEMINI_API_KEY", "a-key")
    assert "GEMINI_API_KEY" not in _render(capsys)
