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
import re
import urllib.error
import urllib.request

from .llm_base import LLMProvider, content_text

_SYSTEM = (
    "You are a careful application-security analyst assisting an AUTHORIZED, "
    "non-destructive assessment. Reply with exactly one JSON object and nothing else."
)

MAX_RESPONSE_BYTES = 4 * 1024 * 1024  # never buffer an unbounded provider response
_VERSION_SEGMENT = re.compile(r"/v\d+[a-z0-9]*(/|$)", re.IGNORECASE)


def _as_int(v) -> int:
    if isinstance(v, bool):
        return 0
    if isinstance(v, (int, float)):
        return max(0, int(v))
    if isinstance(v, str):
        try:
            return max(0, int(float(v)))
        except ValueError:
            return 0
    return 0


class OpenAICompatProvider(LLMProvider):
    name = "openai-compat"

    def __init__(self, budget=None, base_url=None, model=None, api_key=None, timeout: float = 60.0):
        super().__init__(budget=budget)
        self.base_url = (
            base_url or os.environ.get("RAMPART_LLM_BASE_URL") or "https://api.openai.com/v1"
        ).rstrip("/")
        self.model = model or os.environ.get("RAMPART_LLM_MODEL") or "gpt-4o-mini"
        if api_key is None:
            api_key = os.environ.get("RAMPART_LLM_API_KEY")
            if not api_key:
                key_env = os.environ.get("RAMPART_LLM_API_KEY_ENV", "OPENAI_API_KEY")
                api_key = os.environ.get(key_env, "")
        self.api_key = (api_key or "").strip()
        self.timeout = timeout
        if not self.api_key:
            # Local gateways (Ollama, LiteLLM) often need no key; never send an empty "Bearer ".
            self.note("no API key configured — sending requests without an Authorization header")

    def _complete(self, prompt: str) -> str | None:
        try:
            payload = json.dumps(
                {
                    "model": self.model,
                    "temperature": 0,
                    "messages": [
                        {"role": "system", "content": _SYSTEM},
                        {"role": "user", "content": prompt},
                    ],
                }
            ).encode("utf-8")
        except (TypeError, ValueError) as exc:
            self.degrade(f"could not encode request: {exc}")
            return None
        url = f"{self.base_url}/chat/completions"
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        req = urllib.request.Request(url, data=payload, method="POST", headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read(MAX_RESPONSE_BYTES + 1)
        except urllib.error.HTTPError as exc:
            hint = ""
            if exc.code == 404 and not _VERSION_SEGMENT.search(self.base_url.split("://", 1)[-1]):
                hint = " — does the base URL need /v1?"
            elif exc.code in (401, 403):
                hint = " — check the API key" + ("" if self.api_key else " (none configured)")
            self.degrade(f"HTTP {exc.code} from {url}{hint}")
            return None
        except (urllib.error.URLError, OSError, ValueError) as exc:
            self.degrade(f"request to {url} failed: {exc}")
            return None
        if len(raw) > MAX_RESPONSE_BYTES:
            self.degrade(f"response from {url} exceeded {MAX_RESPONSE_BYTES} bytes — ignored")
            return None
        try:
            data = json.loads(raw.decode("utf-8", errors="replace"))
        except (json.JSONDecodeError, ValueError):
            self.degrade(f"non-JSON response from {url}")
            return None
        if not isinstance(data, dict):
            self.degrade(f"unexpected response shape from {url} (not a JSON object)")
            return None
        if self.budget is not None:
            usage = data.get("usage")
            tokens = _as_int(usage.get("total_tokens")) if isinstance(usage, dict) else 0
            try:
                self._charge(tokens=tokens)
            except Exception:  # noqa: BLE001 - accounting must never crash the provider
                pass
        try:
            message = data["choices"][0]["message"]
            content = message.get("content") if isinstance(message, dict) else None
        except (KeyError, IndexError, TypeError):
            content = None
        text = content_text(content)
        if text is None:
            self.degrade(f"no message content in response from {url}")
        return text
