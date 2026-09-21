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

__version__ = "0.1.3"

__all__ = [
    "analyze",
    "prove",
    "fix",
    "OwnershipError",
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
