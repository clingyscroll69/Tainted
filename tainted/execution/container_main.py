"""What runs inside the sandbox container. One run, then the process ends.

Reads a `RunRequest` from stdin, runs it, writes NDJSON events to stdout as they happen, and
emits exactly one terminal event: `report`, `refused` or `error`.

Nothing here writes to stdout except `_emit`. A stray `print` would land in the middle of the
event stream and the host would refuse the whole run — which is the correct failure, but an
annoying one to debug. Diagnostics go to stderr, which the host forwards untouched.
"""

from __future__ import annotations

import json
import os
import sys
from typing import Any, Optional, TextIO

from tainted.dynamic.target import ProveSetup
from tainted.execution.base import ProveOutcome
from tainted.execution.wire import RunRequest, encode_event
from tainted.selfdefense import AllowedCall, PlanViolation, ProbePlan

# The run key arrives as an env var rather than in the request body, so it stays out of any
# log the caller kept of what it asked for. See `tainted.execution.guard.new_run_key`.
RUN_KEY_ENV = "TAINTED_RUN_KEY"


def _emit(out: TextIO, kind: str, **payload: Any) -> None:
    out.write(encode_event(kind, **payload) + "\n")
    out.flush()  # the host is reading this live; buffering defeats the point


def _plan_from(raw: Optional[dict[str, Any]]) -> Optional[ProbePlan]:
    if raw is None:
        return None
    return ProbePlan(
        target_url=raw["target_url"],
        allowed=[
            AllowedCall(tool=c["tool"], arg_constraints=c.get("arg_constraints", {}))
            for c in raw.get("allowed", [])
        ],
    )


class LLMExpectedButMissing(RuntimeError):
    """The host had a usable LLM and the container does not. See `_run`."""


def _run(req: RunRequest, key: Optional[bytes], out: TextIO) -> ProveOutcome:
    from tainted.execution.base import LocalExecutor, _llm_or_none

    if req.llm_expected and _llm_or_none() is None:
        # The host ranked candidates with the meaning register — that is what `analyze`
        # already showed the user — and resolved no LLM here means the key did not cross the
        # container boundary (blocked env var, missing image build arg, whatever). Running
        # anyway would silently re-rank everything on Structure alone and hand back a report
        # that looks complete but is missing the register the user was already shown. That is
        # exactly the false-negative shape this tool exists to not produce, so this refuses
        # instead of degrading.
        raise LLMExpectedButMissing(
            "The host has a configured LLM but GEMINI_API_KEY did not reach this container. "
            "Running would silently rank findings without the meaning register the host "
            "already showed you, which is a different (and weaker) result than the one you "
            "were shown, not the same one running more safely."
        )

    setup = ProveSetup.model_validate(req.setup)
    budget = None
    if req.max_seconds is not None or req.max_candidates is not None:
        from tainted.budget import Budget

        budget = Budget(max_seconds=req.max_seconds, max_candidates=req.max_candidates)
    # Inside the container, in-process IS the containment. LocalExecutor is the right executor
    # here and only here.
    return LocalExecutor().prove(
        req.repo_path,
        setup,
        ownership_verified=req.ownership_verified,
        autodiscover=req.autodiscover,
        plan=_plan_from(req.plan),
        plan_signature=req.plan_signature,
        run_key=key,
        budget=budget,
        on_candidates=lambda cs: _emit(
            out, "candidates", candidates=[c.model_dump(mode="json") for c in cs]
        ),
        on_finding=lambda f: _emit(out, "finding", finding=f.model_dump(mode="json")),
    )


def main(stdin: TextIO, stdout: TextIO, env: dict[str, str]) -> int:
    try:
        raw_key = env.get(RUN_KEY_ENV, "")
        key = bytes.fromhex(raw_key) if raw_key else None
        req = RunRequest.model_validate(json.loads(stdin.read()))
        outcome = _run(req, key, stdout)
    except PlanViolation as exc:
        # Terminal, but not an error: the guard did its job. The host raises PlanViolation on
        # seeing this, preserving the distinction the MCP surface is careful about.
        _emit(stdout, "refused", message=str(exc), blocked_calls=[{"refused": str(exc)}])
        return 0
    except Exception as exc:  # noqa: BLE001 - reported to the host, which re-raises
        _emit(stdout, "error", message=f"{type(exc).__name__}: {exc}")
        return 1
    _emit(
        stdout,
        "report",
        report=outcome.report.model_dump(mode="json"),
        blocked_calls=outcome.blocked_calls,
        budget=outcome.budget,
    )
    return 0


if __name__ == "__main__":  # pragma: no cover - the container's own entrypoint
    sys.exit(main(sys.stdin, sys.stdout, dict(os.environ)))
