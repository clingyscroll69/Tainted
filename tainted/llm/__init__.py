"""The meaning register — a language model behind a thin, swappable interface."""

from tainted.llm.client import LLMCallFailed, LLMClient, LLMTier, LLMUnavailable
from tainted.llm.gemini import GeminiClient, get_default_client

__all__ = [
    "LLMCallFailed",
    "LLMClient",
    "LLMTier",
    "LLMUnavailable",
    "GeminiClient",
    "get_default_client",
]
