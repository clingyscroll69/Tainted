"""`fix`: write the remediation, then run the attack again to check it failed.

For BOLA, RLS, and classic injection, the code alone tells Tainted the right fix, so it just
writes it and re-runs the attack. For the tool plane, the right fix depends on what you intend,
so Tainted asks you first, then re-checks the graph and proves it again. For test integrity,
only you know if the current behavior is correct, so Tainted asks a question and never writes
the test itself.
"""

from tainted.fix.deterministic import (
    generate_bola_fix,
    generate_injection_fix,
    generate_rls_fix,
)
from tainted.fix.interview import (
    InterviewAnswer,
    InterviewQuestion,
    MutantQuestion,
    ToolRemediation,
    mutant_questions,
    resolve_tool_plane_fix,
    tool_plane_interview,
)
from tainted.fix.reverify import reverify_request_plane, reverify_tool_plane
from tainted.fix.tool_plane_fix import generate_tool_plane_fix

__all__ = [
    "generate_bola_fix",
    "generate_injection_fix",
    "generate_rls_fix",
    "generate_tool_plane_fix",
    "reverify_request_plane",
    "reverify_tool_plane",
    "tool_plane_interview",
    "resolve_tool_plane_fix",
    "mutant_questions",
    "InterviewQuestion",
    "InterviewAnswer",
    "MutantQuestion",
    "ToolRemediation",
]
