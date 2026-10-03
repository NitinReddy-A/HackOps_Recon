"""OpenAI-compatible LLM provider — the "connect your own API key" path.

One provider covers every OpenAI-compatible endpoint, so users can bring their own key:

    OpenAI       base_url=https://api.openai.com/v1        model=gpt-4o-mini
    OpenRouter   base_url=https://openrouter.ai/api/v1     model=... (many free tiers)
    Groq         base_url=https://api.groq.com/openai/v1   model=llama-3.3-70b-versatile
    Together     base_url=https://api.together.xyz/v1      model=...
    LiteLLM      base_url=http://localhost:4000/v1         model=... (self-hosted gateway)
    Ollama       base_url=http://localhost:11434/v1        model=qwen2.5  (fully local, free)

Configuration is via environment variables (never on the command line):

    RAMPART_LLM_BASE_URL   default https://api.openai.com/v1
    RAMPART_LLM_MODEL      default gpt-4o-mini
    RAMPART_LLM_API_KEY    the key itself, OR
    RAMPART_LLM_API_KEY_ENV  the NAME of the env var holding the key (default OPENAI_API_KEY)

Dependency-free (stdlib ``urllib``). Falls back to the deterministic provider on any error.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

from .llm_base import LLMProvider

_SYSTEM = ("You are a careful application-security analyst assisting an AUTHORIZED, "
           "non-destructive assessment. Reply with exactly one JSON object and nothing else.")


class OpenAICompatProvider(LLMProvider):
    name = "openai-compat"

    def __init__(self, budget=None, base_url=None, model=None, api_key=None, timeout: float = 60.0):
        super().__init__(budget=budget)
        self.base_url = (base_url or os.environ.get("RAMPART_LLM_BASE_URL")
                         or "https://api.openai.com/v1").rstrip("/")
        self.model = model or os.environ.get("RAMPART_LLM_MODEL") or "gpt-4o-mini"
        if api_key is None:
            api_key = os.environ.get("RAMPART_LLM_API_KEY")
            if not api_key:
                key_env = os.environ.get("RAMPART_LLM_API_KEY_ENV", "OPENAI_API_KEY")
                api_key = os.environ.get(key_env, "")
        self.api_key = api_key or ""
        self.timeout = timeout

    def _complete(self, prompt: str) -> str | None:
        payload = json.dumps({
            "model": self.model,
            "temperature": 0,
            "messages": [{"role": "system", "content": _SYSTEM},
                         {"role": "user", "content": prompt}],
        }).encode()
        req = urllib.request.Request(
            f"{self.base_url}/chat/completions", data=payload, method="POST",
            headers={"Content-Type": "application/json",
                     "Authorization": f"Bearer {self.api_key}"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read().decode("utf-8", errors="replace"))
        except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError, OSError):
            return None
        if self.budget is not None:
            usage = data.get("usage") or {}
            self.budget.record_tokens(int(usage.get("total_tokens", 0)))
        try:
            return data["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError):
            return None
