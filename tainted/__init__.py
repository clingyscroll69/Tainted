"""Tainted — a security scanner for AI-written apps.

The engine reasons in three registers — Structure (static), Meaning (LLM), Proof (live) —
and exposes three operations: analyze, prove, fix.
"""

from tainted.models import (
    AnalysisResult,
    Candidate,
    Check,
    Confidence,
    Exploit,
    Finding,
    FindingStatus,
    FixResult,
    MutationSummary,
    Plane,
    ProbeResult,
    Provenance,
    Severity,
)

from tainted.orchestrator import OwnershipError, analyze, fix, prove
from tainted.budget import Budget, BudgetOutcome, parse_budget
from tainted.operations import (
    completion_gate,
    pairing_diff,
    preflight,
    regression_check,
    reprove,
    second_opinion,
)
from tainted.priority import priority_of, by_priority
from tainted.standards import ids_for

__version__ = "0.2.0"

__all__ = [
    "analyze",
    "prove",
    "fix",
    "OwnershipError",
    "Budget",
    "BudgetOutcome",
    "parse_budget",
    "preflight",
    "reprove",
    "second_opinion",
    "regression_check",
    "pairing_diff",
    "completion_gate",
    "priority_of",
    "by_priority",
    "ids_for",
    "AnalysisResult",
    "Candidate",
    "Check",
    "Confidence",
    "Exploit",
    "Finding",
    "FindingStatus",
    "FixResult",
    "MutationSummary",
    "Plane",
    "ProbeResult",
    "Provenance",
    "Severity",
    "__version__",
]
