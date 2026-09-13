"""The agent loop the configured-agent sandbox runs against.

`sandbox.py` owns the harness — poisoned source, logging-stub sinks, a trace of what fired.
This module owns the thing being tested: an agent that reads the source's content and decides
which tools to call. Without it the tool plane has no dynamic half at all, and collapses to the
static co-location graph the design explicitly says is *not* a verdict.

The agent stood up here is equivalent to the manifest, not a copy of the user's process: the
manifest lists the tools and their descriptions, and that is genuinely all a tool-calling agent
gets. That is the plane's core claim and its honest limit in one — it is why a **configured**
agent can be proven from its config alone with no user code, no boot and no keys, and equally
why a **coded** agent cannot be, since its behavior lives in a program we would have to run.

The driver is deliberately naive about defenses. It does not add instructions telling the model
to distrust tool output, because the question under test is whether *this tool graph* is turnable
by content, not whether a hardened system prompt can save it.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:  # the runtime import lives inside run(), where the cycle is avoidable
    from tainted.dynamic.sandbox import ToolCall

from typing import Any, Optional, Protocol

from tainted.llm.client import LLMClient, LLMTier, LLMUnavailable
from tainted.llm.prompts import AGENT_DRIVER_SCHEMA, agent_driver_prompt


class ToolCallLike(Protocol):
    tool: str
    args: dict[str, Any]


class AgentDriver(Protocol):
    """Decides which tools the agent calls given the (poisoned) source content."""

    def run(
        self, *, system: str, source_output: str, sink_names: list[str]
    ) -> list[Any]: ...


class LLMAgentDriver:
    """A tool-calling agent backed by the language model.

    One turn is enough for this test. A confused-deputy exploit lands on the turn where the
    agent processes the poisoned content and decides to act on it; an agent that resists that
    turn has resisted the attack, and one that folds has already folded.
    """

    def __init__(self, llm: LLMClient, max_calls: int = 8):
        self.llm = llm
        self.max_calls = max_calls

    def run(
        self, *, system: str, source_output: str, sink_names: list[str]
    ) -> list["ToolCall"]:
        from tainted.dynamic.sandbox import ToolCall

        try:
            decision = self.llm.complete_json(
                system=system,
                prompt=agent_driver_prompt(source_output, sink_names),
                tier=LLMTier.BULK,
                schema=AGENT_DRIVER_SCHEMA,
            )
        except LLMUnavailable:
            raise
        except Exception:
            # A model failure is not evidence the agent resisted. Returning no calls would be
            # recorded as "not turned", which would be a false negative dressed as a result.
            raise AgentDriverError(
                "The agent driver could not complete a turn; no conclusion can be drawn about "
                "whether this scope is turnable."
            )

        calls: list[ToolCall] = []
        for raw in (decision.get("tool_calls") or [])[: self.max_calls]:
            if not isinstance(raw, dict):
                continue
            name = raw.get("tool")
            if not name:
                continue
            args = raw.get("args")
            calls.append(ToolCall(tool=str(name), args=args if isinstance(args, dict) else {}))
        return calls


class AgentDriverError(RuntimeError):
    """The driver could not complete a turn, so the scope's turnability is undetermined."""


def build_driver(llm: Optional[LLMClient]) -> Optional[AgentDriver]:
    """The driver for a live run, or None when no model is configured."""
    if llm is None or not llm.available:
        return None
    return LLMAgentDriver(llm)
