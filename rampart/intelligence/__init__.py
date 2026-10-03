"""The reasoning ("LLM proposes") layer — strictly advisory.

Nothing here touches the network or the filesystem of the target; every suggestion is
re-checked by the deterministic policy pipeline and, for findings, by the independent
validator. Providers implement one interface:

* :class:`DeterministicProvider` - rule-based, zero-cost, reproducible (the default, so
  CI and offline demos are free and deterministic);
* :class:`ClaudeCodeProvider`   - shells out to the ``claude`` CLI (no API key needed);
* :class:`OpenAICompatProvider` - bring-your-own-key path for any OpenAI-compatible endpoint
  (OpenAI, OpenRouter, Groq, Together, LiteLLM gateway, or fully-local Ollama).
"""
from .base import IntelligenceProvider
from .deterministic import DeterministicProvider
from .claude_code import ClaudeCodeProvider
from .openai_compat import OpenAICompatProvider


def get_provider(name: str, budget=None) -> IntelligenceProvider:
    name = (name or "deterministic").lower()
    if name in ("claude", "claude-code", "claudecode"):
        return ClaudeCodeProvider(budget=budget)
    if name in ("openai", "openai-compat", "llm", "api", "openrouter", "groq", "ollama", "litellm", "together"):
        return OpenAICompatProvider(budget=budget)
    if name == "deterministic":
        return DeterministicProvider()
    raise ValueError(f"unknown intelligence provider {name!r} "
                     "(use 'deterministic', 'claude-code', or 'openai-compat')")


__all__ = ["IntelligenceProvider", "DeterministicProvider", "ClaudeCodeProvider",
           "OpenAICompatProvider", "get_provider"]
