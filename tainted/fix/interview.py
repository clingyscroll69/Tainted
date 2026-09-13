"""Fixes that need something only you know, so Tainted asks first.

For the tool plane, the right fix (scope split, a human gate, confirming each call, or
tracking where data came from) depends on facts only you hold. Tainted asks two or three
questions to pick one. For test integrity, writing a test yourself would assume the current
code is correct, so Tainted asks you instead and never writes the test itself.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from tainted.checks.test_integrity import SurvivingMutant
from tainted.models import Candidate


# --------------------------------------------------------------------------- #
# Tool-plane remediation interview
# --------------------------------------------------------------------------- #
class ToolRemediation(str, Enum):
    SCOPE_SPLIT = "scope_split"  # split the two tools into separate agents
    MEDIATION = "mediation"  # a person or a policy gate approves the risky action
    SINK_CONFIRMATION = "sink_confirmation"  # confirm each risky call before it runs
    PROVENANCE = "provenance"  # track where data came from and block it at the risky call


@dataclass
class InterviewQuestion:
    key: str
    question: str
    options: list[str]


@dataclass
class InterviewAnswer:
    key: str
    choice: str


def tool_plane_interview(candidate: Candidate) -> list[InterviewQuestion]:
    """Two or three questions that pick which of the four fixes applies."""
    scope = candidate.metadata.get("scope", "the agent")
    return [
        InterviewQuestion(
            key="needs_both",
            question=(
                f"Does `{scope}` really need both of these tools to do its job?"
            ),
            options=["no", "yes"],
        ),
        InterviewQuestion(
            key="human_available",
            question="Is a person available to approve the risky action before it runs?",
            options=["yes", "no"],
        ),
        InterviewQuestion(
            key="latency_ok",
            question="Can this action be slower, to add a check before it runs?",
            options=["yes", "no"],
        ),
    ]


def resolve_tool_plane_fix(answers: list[InterviewAnswer]) -> ToolRemediation:
    """Map interview answers to the right fix.

    Tainted asks instead of guessing, the way a security consultant would ask before
    recommending anything.
    """
    a = {ans.key: ans.choice for ans in answers}
    # If the agent doesn't need both tools, the cleanest fix is to split them apart.
    if a.get("needs_both") == "no":
        return ToolRemediation.SCOPE_SPLIT
    # It needs both. Prefer a human gate if one is available.
    if a.get("human_available") == "yes":
        return ToolRemediation.MEDIATION
    # No human, but there's room to slow down: confirm each risky call.
    if a.get("latency_ok") == "yes":
        return ToolRemediation.SINK_CONFIRMATION
    # No human and no room to slow down: track where the data came from and block it at the risky call.
    return ToolRemediation.PROVENANCE


# --------------------------------------------------------------------------- #
# Test-integrity: surface each surviving mutant as a question
# --------------------------------------------------------------------------- #
@dataclass
class MutantQuestion:
    mutant: SurvivingMutant
    question: str
    if_intended: str  # what to do if current behavior is correct
    if_wrong: str  # what it means if not


def mutant_questions(mutants: list[SurvivingMutant]) -> list[MutantQuestion]:
    """One question per surviving mutant. You confirm the test, Tainted never writes it alone."""
    out: list[MutantQuestion] = []
    for m in mutants:
        out.append(
            MutantQuestion(
                mutant=m,
                question=(
                    f"At {m.file}:{m.line}, changing this line ({m.mutator}) did not fail any "
                    f"test. Is the current behavior here intended?"
                ),
                if_intended=(
                    "Add the test below to pin it down. Write it from what you intend, then confirm it."
                ),
                if_wrong=(
                    "Then you found a bug your tests were hiding. The code does something "
                    "no test checks, and it is wrong."
                ),
            )
        )
    return out
