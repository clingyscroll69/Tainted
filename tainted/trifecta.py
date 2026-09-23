"""The lethal trifecta's third leg, computed over a tool-plane scope.

Tainted already finds the dangerous pair: a scope holding both a data **source** (it reads
untrusted content) and a **sink** (it takes a consequential action). The widely understood
framing — Simon Willison's "lethal trifecta", Meta's "Agents Rule of Two" — adds one more
question that Tainted does not currently answer: *can data also leave?* A scope that reads
untrusted content, acts on it, **and** can send data outward is strictly more dangerous than one
whose sinks all stay inside the system, because the injected instruction can exfiltrate rather
than merely misfire.

This module answers that third question deterministically from the sink tools a scope already
holds — no model call — and exposes it two ways: a boolean the standards mapping reads to add the
exfiltration technique id, and a severity nudge so a scope that closes the full trifecta ranks
above one that does not. It is a *nudge*, never a new membership decision: it cannot add or drop a
candidate, only reorder, in keeping with the rule that only proof decides membership.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from tainted.static.tools import AgentScope, ToolSpec

# Names and description fragments that mark a sink as one that sends data *out of the system*, as
# opposed to one that acts locally. Deliberately broad on the recognisable verbs and backed by a
# description scan, because a tool named `run` with the description "post the result to a webhook"
# is an egress sink whatever it is called.
_EGRESS_NAME = re.compile(
    r"(send|email|mail|post|http|fetch|request|webhook|upload|publish|notify|slack|"
    r"tweet|message|export|share|forward|relay|sms|dispatch|emit|sync)",
    re.I,
)
_EGRESS_DESC = re.compile(
    r"(send|e-?mail|post to|http|external|outbound|webhook|upload|publish|to a url|"
    r"third[- ]party|notify|forward|exfiltrat|out of|remote server|another (system|service))",
    re.I,
)


def _is_egress(tool: ToolSpec) -> bool:
    return bool(_EGRESS_NAME.search(tool.name or "") or _EGRESS_DESC.search(tool.description or ""))


@dataclass(frozen=True)
class TrifectaVerdict:
    """Whether a co-located scope also closes the third leg, and which tools do it."""

    reads_untrusted: bool  # has a source
    can_act: bool  # has a sink
    can_exfiltrate: bool  # has an egress sink specifically
    egress_tools: tuple[str, ...] = ()

    @property
    def complete(self) -> bool:
        """All three legs present — the fully lethal case."""
        return self.reads_untrusted and self.can_act and self.can_exfiltrate

    def note(self) -> str:
        if self.complete:
            leaving = ", ".join(f"`{t}`" for t in self.egress_tools)
            return (
                f"Full lethal trifecta: this agent reads untrusted content, acts on it, and can "
                f"send data outward ({leaving}). An injection here can exfiltrate, not just "
                f"misfire."
            )
        if self.reads_untrusted and self.can_act:
            return (
                "Reads untrusted content and can act on it, but none of its sinks send data "
                "outward — the injected instruction can misuse a tool, but cannot obviously "
                "carry data off the system. One leg short of the lethal trifecta."
            )
        return "Not a co-located source-and-sink scope."

    def as_dict(self) -> dict:
        return {
            "reads_untrusted": self.reads_untrusted,
            "can_act": self.can_act,
            "can_exfiltrate": self.can_exfiltrate,
            "egress_tools": list(self.egress_tools),
            "complete": self.complete,
            "note": self.note(),
        }


def assess(scope: AgentScope) -> TrifectaVerdict:
    """Compute the trifecta verdict for one scope from the tools it already holds."""
    egress = [t for t in scope.sinks if _is_egress(t)]
    return TrifectaVerdict(
        reads_untrusted=bool(scope.sources),
        can_act=bool(scope.sinks),
        can_exfiltrate=bool(egress),
        egress_tools=tuple(t.name for t in egress),
    )
