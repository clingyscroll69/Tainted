"""Failures that must degrade a run, not end it, and must never read as a result.

Each test here pins a path that used to go wrong: a model call that failed, an agent driver that
could not finish a turn, a repository living under a directory called `build`, a Semgrep path
spelled differently from every other one.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from tainted import analyze, prove
from tainted.dynamic.agent_driver import AgentDriverError
from tainted.dynamic.target import Account, ProveSetup, SeedRecord, Target
from tainted.llm.client import LLMCallFailed, LLMUnavailable
from tainted.models import (
    AnalysisResult,
    Candidate,
    Check,
    FindingStatus,
    Plane,
    SourceLocation,
)
from tainted.report import build_report
from tainted.static.semgrep import SemgrepRun, semgrep_injection_candidates
from tests.conftest import FakeLLM

FIXTURES = Path(__file__).parent / "fixtures"
CONFIGS = str(FIXTURES / "agent_configs")
SEED_ID = "11111111-1111-1111-1111-111111111111"

LABELS = {
    "read_email": {"role": "source", "severity": "info"},
    "send_email": {"role": "sink", "severity": "high"},
}


def _setup() -> ProveSetup:
    return ProveSetup(
        target=Target(url="http://localhost:54321", anon_key="anon"),
        account_a=Account(label="A", access_token="tok-A"),
        account_b=Account(label="B", access_token="tok-B"),
        seed=SeedRecord(table="invoices", id=SEED_ID, owner_column="owner"),
    )


# --------------------------------------------------------------------------- #
# The model
# --------------------------------------------------------------------------- #
def test_a_failed_call_is_an_unavailable_model():
    """Every caller degrades on LLMUnavailable; a failed call has to be one."""
    assert issubclass(LLMCallFailed, LLMUnavailable)


class _LabellingFails(FakeLLM):
    def judge_applicability(self, question, evidence):
        return {"answer": "yes", "confidence": 0.9, "rationale": "fake"}

    def label_tool(self, tool):
        raise LLMCallFailed("429 quota")


def test_a_labelling_failure_is_a_stated_gap_not_a_crash():
    result = analyze(CONFIGS, llm=_LabellingFails())
    assert not result.by_check(Check.AGENT_INJECTION)
    assert result.gaps and result.gaps[0].check is Check.AGENT_INJECTION
    notes = [n.detail for n in build_report(result).coverage]
    assert any("failed while labelling" in n for n in notes)


class _FailingDriver:
    def run(self, *, system, source_output, sink_names):
        raise AgentDriverError("the model turn failed")


def test_a_driver_that_cannot_finish_a_turn_does_not_abort_prove():
    scope_file = "email_assistant.mcp.json"
    analysis = AnalysisResult(
        repo_path=CONFIGS,
        candidates=[
            Candidate(
                check=Check.AGENT_INJECTION,
                plane=Plane.TOOL,
                title="agent",
                location=SourceLocation(file=scope_file),
                metadata={"scope": "email_assistant"},
            )
        ],
    )
    llm = FakeLLM(label_map=LABELS, injection={"payload": "x", "target_sink": "send_email"})
    findings = prove(analysis, _setup(), llm=llm, driver=_FailingDriver())
    assert findings[0].status is FindingStatus.REPORTED
    assert "could not drive" in findings[0].proof.notes


# --------------------------------------------------------------------------- #
# Paths
# --------------------------------------------------------------------------- #
def test_a_repository_under_a_build_directory_is_still_scanned(tmp_path):
    """The skip list names generated trees *inside* a repo, not the folders above it."""
    repo = tmp_path / "build" / "app"
    shutil.copytree(FIXTURES / "vulnerable_routes", repo)
    assert analyze(str(repo), only={Check.BOLA}).by_check(Check.BOLA)


def test_semgrep_paths_become_repo_relative(tmp_path):
    (tmp_path / "api").mkdir()
    (tmp_path / "api" / "x.py").write_text("cursor.execute(f'select {x}')\n")
    result = {
        "path": str(tmp_path / "api" / "x.py"),
        "start": {"line": 1},
        "extra": {"lines": "cursor.execute(...)", "metadata": {"tainted_kind": "sql"}},
        "check_id": "r",
    }
    cands = semgrep_injection_candidates(
        str(tmp_path), runner=lambda rules, repo: SemgrepRun(True, [result])
    )
    assert cands[0].location.file == str(Path("api") / "x.py")


# --------------------------------------------------------------------------- #
# The fix loop
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("name", ["self", "name"])
def test_a_sink_argument_may_carry_any_name(name):
    from tainted.dynamic.sandbox import SinkStub

    stub = SinkStub(name="send")
    stub(**{name: "x"})
    assert stub.calls[0].args == {name: "x"}
