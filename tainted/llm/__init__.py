"""The meaning register — a language model behind a thin, swappable interface."""

from tainted.llm.client import LLMClient, LLMTier, LLMUnavailable
from tainted.llm.gemini import GeminiClient, get_default_client

__all__ = [
    "LLMClient",
    "LLMTier",
    "LLMUnavailable",
    "GeminiClient",
    "get_default_client",
]
