"""Third-party benchmarks — validating one component, and saying which one.

The only benchmark here is AgentDojo, and it validates the injection *generator*, not the
detector. Keeping that distinction attached to the number is the whole reason this lives in its
own package rather than being folded into the tool plane's results.
"""

from tainted.bench.agentdojo import (
    BenchmarkCase,
    BenchmarkResult,
    CaseOutcome,
    agentdojo_available,
    run_benchmark,
)

__all__ = [
    "BenchmarkCase",
    "BenchmarkResult",
    "CaseOutcome",
    "agentdojo_available",
    "run_benchmark",
]
