"""Gemini implementation of the LLMClient interface (google-genai SDK).

Judge tier -> gemini-2.5-pro; bulk tier -> gemini-2.5-flash. Both overridable via settings.
Responses are constrained to JSON with a schema so the engine gets parseable output.
"""

from __future__ import annotations

import json
from typing import Any, Optional

from tainted.config import Settings, get_settings
from tainted.llm.client import LLMClient, LLMTier


class GeminiClient(LLMClient):
    def __init__(self, settings: Optional[Settings] = None):
        self._settings = settings or get_settings()
        self._client = None  # lazily constructed so importing the engine needs no key

    @property
    def available(self) -> bool:
        return self._settings.has_llm

    def _model_for(self, tier: LLMTier) -> str:
        if tier is LLMTier.JUDGE:
            return self._settings.tainted_llm_model_judge
        return self._settings.tainted_llm_model_bulk

    def _get_client(self):
        if self._client is None:
            from google import genai  # imported lazily; heavy and key-gated
            from google.genai import types

            # attempts=1 disables the SDK's own exponential backoff so OUR fallback logic is
            # authoritative and fast: a pro-tier 429 returns immediately to be retried on the
            # bulk model, instead of the SDK backing off for a minute first.
            self._client = genai.Client(
                api_key=self._settings.gemini_api_key,
                http_options=types.HttpOptions(
                    timeout=self._settings.llm_timeout_ms,
                    retry_options=types.HttpRetryOptions(attempts=1),
                ),
            )
        return self._client

    def complete_json(
        self,
        *,
        system: str,
        prompt: str,
        tier: LLMTier,
        schema: dict[str, Any],
    ) -> Any:
        model = self._model_for(tier)
        try:
            return self._call(model=model, system=system, prompt=prompt, schema=schema)
        except Exception:
            # Judge model unavailable (quota / sunset id) -> degrade to bulk rather than fail.
            fallback = self._settings.tainted_llm_model_bulk
            if (
                tier is LLMTier.JUDGE
                and self._settings.llm_judge_falls_back_to_bulk
                and fallback != model
            ):
                return self._call(
                    model=fallback, system=system, prompt=prompt, schema=schema
                )
            raise

    # Transient server errors (503 high-demand, 500) recover in seconds; quota (429) and
    # sunset ids (404) do not, and are left to the judge->bulk fallback / caller.
    _TRANSIENT_BACKOFF_S = (2.0, 5.0)

    def _call(self, *, model: str, system: str, prompt: str, schema: dict[str, Any]) -> Any:
        import time

        from google.genai import errors, types

        client = self._get_client()
        config = types.GenerateContentConfig(
            system_instruction=system,
            response_mime_type="application/json",
            response_json_schema=schema,
            temperature=0.0,  # deterministic judgment
        )
        attempts = len(self._TRANSIENT_BACKOFF_S) + 1
        for i in range(attempts):
            try:
                response = client.models.generate_content(
                    model=model, contents=prompt, config=config
                )
                break
            except errors.ServerError:  # 5xx — transient, retry with backoff
                if i == attempts - 1:
                    raise
                time.sleep(self._TRANSIENT_BACKOFF_S[i])
        text = (response.text or "").strip()
        if not text:
            raise ValueError("Gemini returned an empty response")
        try:
            return json.loads(text)
        except json.JSONDecodeError as exc:  # pragma: no cover - defensive
            raise ValueError(f"Gemini returned non-JSON: {text[:500]}") from exc


_default: Optional[GeminiClient] = None


def get_default_client(reload: bool = False) -> GeminiClient:
    """Process-wide default client. Safe to call with no key — `.available` reports it."""
    global _default
    if _default is None or reload:
        _default = GeminiClient(get_settings(reload=reload))
    return _default
