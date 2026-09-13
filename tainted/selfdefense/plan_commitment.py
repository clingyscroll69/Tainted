"""Plan-commitment — the self-defense on the `prove` MCP tool.

The `prove` tool is an exploit-executing capability handed to an agent that reads untrusted
content — which *is* the confused-deputy co-location the product exists to find. So before
`prove` touches the target, it commits to its probe plan: an explicit, signed set of tool calls
with argument constraints. Every subsequent call is checked against the commitment; anything the
tool "decides" to do after reading target content, that wasn't in the plan, is refused.

Plan-commitment is contested *in general* — most agents can't pre-commit because what they do
next legitimately depends on what they read. It is airtight for `prove` specifically, because
`prove`'s legitimate behavior is fully known in advance: a bounded, enumerable set of probes at
a human-named target that should never do something new because of what it read.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from dataclasses import dataclass, field
from typing import Any, Optional


class PlanViolation(RuntimeError):
    """Raised when a tool call is not permitted by the committed plan."""


@dataclass
class AllowedCall:
    """One permitted call: a tool name and per-argument constraints.

    A constraint is one of: an exact value, a set/list of allowed values, or a `re:`-prefixed
    regex string. An argument with no constraint is unconstrained; a required-but-absent
    argument is a violation.
    """

    tool: str
    arg_constraints: dict[str, Any] = field(default_factory=dict)

    def permits(self, tool: str, args: dict[str, Any]) -> bool:
        if tool != self.tool:
            return False
        for key, constraint in self.arg_constraints.items():
            if key not in args:
                return False
            if not _matches(args[key], constraint):
                return False
        return True


def _matches(value: Any, constraint: Any) -> bool:
    if isinstance(constraint, (list, set, tuple)):
        return value in constraint
    if isinstance(constraint, str) and constraint.startswith("re:"):
        return re.fullmatch(constraint[3:], str(value)) is not None
    return value == constraint


@dataclass
class ProbePlan:
    """The bounded set of calls `prove` commits to before touching the target."""

    target_url: str
    allowed: list[AllowedCall] = field(default_factory=list)

    def canonical(self) -> str:
        """A stable serialization for signing (order-independent, whitespace-normalized)."""
        payload = {
            "target_url": self.target_url,
            "allowed": sorted(
                (
                    {"tool": c.tool, "args": _stable(c.arg_constraints)}
                    for c in self.allowed
                ),
                key=lambda d: (d["tool"], json.dumps(d["args"], sort_keys=True)),
            ),
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":"))

    def permits(self, tool: str, args: dict[str, Any]) -> bool:
        return any(c.permits(tool, args) for c in self.allowed)


def _stable(d: dict[str, Any]) -> dict[str, Any]:
    out = {}
    for k, v in d.items():
        out[k] = sorted(v) if isinstance(v, (set, tuple)) else v
    return out


def commit(plan: ProbePlan, secret: bytes) -> str:
    """Sign a plan with an HMAC over its canonical form. Returns a hex signature."""
    return hmac.new(secret, plan.canonical().encode("utf-8"), hashlib.sha256).hexdigest()


class PlanGuard:
    """Enforces a signed plan. Every `prove`-issued call passes through `check` first."""

    def __init__(self, plan: ProbePlan, signature: str, secret: bytes):
        expected = commit(plan, secret)
        if not hmac.compare_digest(expected, signature):
            raise PlanViolation("Probe plan signature does not verify — plan was tampered with.")
        self.plan = plan
        self._blocked: list[dict[str, Any]] = []

    @property
    def blocked_calls(self) -> list[dict[str, Any]]:
        return list(self._blocked)

    def check(self, tool: str, args: dict[str, Any]) -> None:
        """Raise PlanViolation unless the committed plan permits this exact call."""
        if not self.plan.permits(tool, args):
            self._blocked.append({"tool": tool, "args": args})
            raise PlanViolation(
                f"Call `{tool}` with {args} was not in the committed probe plan — refused. "
                f"`prove` may only do what it committed to before reading target content."
            )

    def guarded(self, tool: str):
        """Wrap a callable so it is checked before every invocation."""

        def wrapper(fn):
            def inner(**args):
                self.check(tool, args)
                return fn(**args)

            return inner

        return wrapper
