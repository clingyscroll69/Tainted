"""Settings and secret loading.

The Gemini API key is read from the environment (or a gitignored `.env`). It is never
hardcoded and never written to disk by the engine.
"""

from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_prefix="",
        extra="ignore",
    )

    # The one secret. Empty string means "no key configured" — the engine's static
    # analysis still runs; only the meaning register (LLM) is unavailable.
    gemini_api_key: str = ""

    # Model routing. Pro for judgment (ownership reasoning, applicability, fix interviews),
    # Flash for bulk labeling/ranking. The `-latest` aliases track the current model so a
    # pinned id can't silently sunset (as `gemini-2.5-flash` did). Overridable via env.
    tainted_llm_model_judge: str = "gemini-pro-latest"
    tainted_llm_model_bulk: str = "gemini-flash-latest"

    # If the judge model errors (e.g. quota/429 or a sunset id), fall back to the bulk model
    # rather than fail the whole run. The distinction is quality, not correctness.
    llm_judge_falls_back_to_bulk: bool = True

    # Hard per-request HTTP timeout (ms). The SDK's retry/backoff on 429s can otherwise hang.
    llm_timeout_ms: int = 90_000

    # Safety cap for the unfiltered-RLS probe: pull a handful of rows, never a table.
    unfiltered_row_cap: int = 5

    @property
    def has_llm(self) -> bool:
        return bool(self.gemini_api_key.strip())


_settings: Settings | None = None


def get_settings(reload: bool = False) -> Settings:
    """Process-wide settings singleton."""
    global _settings
    if _settings is None or reload:
        _settings = Settings()
    return _settings
