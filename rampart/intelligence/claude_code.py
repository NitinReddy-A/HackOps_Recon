"""Claude Code as the intelligence backend (instead of an LLM API).

Shells out to the ``claude`` CLI in headless mode (``claude -p --output-format json``),
reads the prompt from stdin, parses the JSON envelope, and returns the assistant text.
Cost/token usage is pulled from the envelope into the engagement budget. All shared logic
(JSON extraction, grounding, fallback) lives in :mod:`rampart.intelligence.llm_base`.

The pipe is always UTF-8 in both directions (never the platform code page), so non-ASCII
target data cannot raise on the way in or turn into mojibake on the way out. Any failure
degrades to the deterministic fallback with a recorded reason — it never raises.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys

from .llm_base import LLMProvider, extract_json


def _num(v, cast):
    if isinstance(v, bool):
        return cast(0)
    if isinstance(v, (int, float)):
        return cast(v) if v > 0 else cast(0)
    if isinstance(v, str):
        try:
            f = float(v)
        except ValueError:
            return cast(0)
        return cast(f) if f > 0 else cast(0)
    return cast(0)


class ClaudeCodeProvider(LLMProvider):
    name = "claude-code"

    def __init__(self, cli: str | None = None, timeout: float = 120.0, budget=None, model: str | None = None):
        super().__init__(budget=budget)
        found = shutil.which("claude")
        self.cli = cli or found or "claude"
        self.timeout = timeout
        self.model = model
        self._warned_missing = False
        if not cli and not found:
            self._missing_cli()

    def _missing_cli(self):
        reason = (
            "`claude` CLI not found on PATH — the claude-code provider will fall back to the "
            "deterministic provider (no LLM reasoning)"
        )
        self.degrade(reason)
        if not self._warned_missing:
            self._warned_missing = True
            print(f"rampart: warning: {reason}", file=sys.stderr)

    def _complete(self, prompt: str) -> str | None:
        cmd = [self.cli, "-p", "--output-format", "json"]
        if self.model:
            cmd += ["--model", self.model]
        try:
            proc = subprocess.run(
                cmd,
                input=prompt,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=self.timeout,
            )
        except FileNotFoundError:
            self._missing_cli()
            return None
        except subprocess.TimeoutExpired:
            self.degrade(f"`claude` timed out after {self.timeout:g}s")
            return None
        except (OSError, ValueError, UnicodeError) as exc:
            self.degrade(f"`claude` could not be run: {type(exc).__name__}: {exc}")
            return None
        if proc.returncode != 0:
            self.degrade(f"`claude` exited with status {proc.returncode}")
            return None
        stdout = proc.stdout or ""
        try:
            envelope = json.loads(stdout)
        except (json.JSONDecodeError, ValueError):
            envelope = None
            for line in reversed(stdout.strip().splitlines()):
                envelope = extract_json(line)
                if isinstance(envelope, dict):
                    break
        if not isinstance(envelope, dict):
            self.degrade("`claude` returned no JSON envelope")
            return None
        if self.budget is not None:
            try:
                usage = envelope.get("usage")
                tokens = (
                    _num(usage.get("input_tokens"), int) + _num(usage.get("output_tokens"), int)
                    if isinstance(usage, dict)
                    else 0
                )
                self._charge(tokens=tokens, usd=_num(envelope.get("total_cost_usd"), float))
            except Exception:  # noqa: BLE001 - accounting must never crash the provider
                pass
        if envelope.get("is_error"):
            self.degrade("`claude` reported an error result")
            return None
        result = envelope.get("result", "")
        return result if isinstance(result, str) else None
