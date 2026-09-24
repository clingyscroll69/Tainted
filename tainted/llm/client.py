"""The LLMClient interface.

Provider-agnostic. Concrete providers implement one primitive — `complete_json` — and the
base class builds the engine's task methods (label / rank / filter / judge / generate) on top,
so swapping providers touches one file.

Two tiers: JUDGE (hard reasoning — ownership, applicability, fix interviews) and BULK
(labeling, ranking, injection generation). Which model backs each tier is the provider's call.
"""

from __future__ import annotations

import abc
from enum import Enum
from typing import Any

from tainted.llm import prompts


class LLMTier(str, Enum):
    JUDGE = "judge"
    BULK = "bulk"


class LLMUnavailable(RuntimeError):
    """Raised when an LLM call is attempted with no key configured.

    Callers on the request plane treat this as "cannot rank" and fall back to a
    deterministic order — the model only decides ordering there, never membership,
    so its absence degrades gracefully.
    """


class LLMClient(abc.ABC):
    """Base class. Providers implement `complete_json`; task methods are shared."""

    @abc.abstractmethod
    def complete_json(
        self,
        *,
        system: str,
        prompt: str,
        tier: LLMTier,
        schema: dict[str, Any],
    ) -> Any:
        """Return parsed JSON matching `schema`. The one primitive a provider must supply."""

    @property
    @abc.abstractmethod
    def available(self) -> bool:
        """False when no key is configured; task methods raise LLMUnavailable if called."""

    # ------------------------------------------------------------------ #
    # Task methods — the engine's meaning-register vocabulary
    # ------------------------------------------------------------------ #
    def rank(self, items: list[dict[str, Any]]) -> list[float]:
        """Request plane: score candidates by likelihood of being a real object reference.

        Returns one score in [0, 1] per input item, order preserved. The scores decide trial
        *order*, never trial *membership* — the whole set is fired regardless.
        """
        self._require()
        result = self.complete_json(
            system=prompts.RANK_SYSTEM,
            prompt=prompts.rank_prompt(items),
            tier=LLMTier.BULK,
            schema=prompts.RANK_SCHEMA,
        )
        scores = [float(s) for s in result.get("scores", [])]
        # Never let a short/garbled response drop candidates: pad with a neutral score.
        if len(scores) < len(items):
            scores += [0.5] * (len(items) - len(scores))
        return scores[: len(items)]

    def label_tool(self, tool: dict[str, Any]) -> dict[str, Any]:
        """Tool plane: label a tool as source / sink / neither, with a severity for sinks."""
        self._require()
        return self.complete_json(
            system=prompts.TOOL_LABEL_SYSTEM,
            prompt=prompts.tool_label_prompt(tool),
            tier=LLMTier.BULK,
            schema=prompts.TOOL_LABEL_SCHEMA,
        )

    def filter_scopes(self, scopes: list[dict[str, Any]]) -> list[bool]:
        """Tool plane: keep/drop co-located scopes before expensive dynamic proof.

        Unlike `rank`, a False here removes a candidate from the dynamic queue. Prefer
        `filter_scopes_explained`, which returns the reasons alongside the decisions so a drop
        can be recorded in the report rather than vanishing.
        """
        return [kept for kept, _ in self.filter_scopes_explained(scopes)]

    def filter_scopes_explained(
        self, scopes: list[dict[str, Any]]
    ) -> list[tuple[bool, str]]:
        """`filter_scopes`, with the model's stated reason for each decision.

        The reason matters because this is the engine's only place where the model decides
        *membership* rather than order. A dropped scope used to leave no trace, so a report
        listing three scopes looked identical whether the repository had three or the filter
        had quietly removed a fourth. Tainted's rule is to say how far it reached; that has to
        apply to its own filter too.
        """
        self._require()
        result = self.complete_json(
            system=prompts.SCOPE_FILTER_SYSTEM,
            prompt=prompts.scope_filter_prompt(scopes),
            tier=LLMTier.JUDGE,
            schema=prompts.SCOPE_FILTER_SCHEMA,
        )
        keep = [bool(k) for k in result.get("keep", [])]
        reasons = [str(r) for r in (result.get("rationales") or [])]
        if len(keep) < len(scopes):
            keep += [True] * (len(scopes) - len(keep))  # doubt keeps a scope in
        reasons += [""] * (len(scopes) - len(reasons))
        return list(zip(keep[: len(scopes)], reasons[: len(scopes)]))

    def judge_applicability(self, question: str, evidence: str) -> dict[str, Any]:
        """Applicability rung 2: read code and answer plainly whether a plane exists."""
        self._require()
        return self.complete_json(
            system=prompts.APPLICABILITY_SYSTEM,
            prompt=prompts.applicability_prompt(question, evidence),
            tier=LLMTier.JUDGE,
            schema=prompts.APPLICABILITY_SCHEMA,
        )

    def judge_ownership(self, candidate: dict[str, Any]) -> dict[str, Any]:
        """Decide whether an id is an object reference lacking an ownership check."""
        self._require()
        return self.complete_json(
            system=prompts.OWNERSHIP_SYSTEM,
            prompt=prompts.ownership_prompt(candidate),
            tier=LLMTier.JUDGE,
            schema=prompts.OWNERSHIP_SCHEMA,
        )

    def generate_injection(self, scope: dict[str, Any]) -> dict[str, Any]:
        """Tool plane: craft an injection aimed at a specific co-located scope."""
        self._require()
        return self.complete_json(
            system=prompts.INJECTION_SYSTEM,
            prompt=prompts.injection_prompt(scope),
            tier=LLMTier.BULK,
            schema=prompts.INJECTION_SCHEMA,
        )

    def compile_invariant(
        self, rule: str, routes: list[dict[str, Any]]
    ) -> dict[str, Any]:
        """Turn a plain-English rule into one concrete request that would violate it.

        Translation only. The model proposes the attack; whether the rule actually holds is
        decided by firing it, never by asking the model what it thinks.
        """
        self._require()
        return self.complete_json(
            system=prompts.INVARIANT_SYSTEM,
            prompt=prompts.invariant_prompt(rule, routes),
            tier=LLMTier.JUDGE,
            schema=prompts.INVARIANT_SCHEMA,
        )

    def _require(self) -> None:
        if not self.available:
            raise LLMUnavailable(
                "No LLM key configured. Static analysis runs; the meaning register does not. "
                "Set GEMINI_API_KEY to enable ranking, labeling, and applicability judgment."
            )
