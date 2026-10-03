"""Claude Code as the intelligence backend (instead of an LLM API).

Shells out to the ``claude`` CLI in headless mode (``claude -p --output-format json``),
reads the prompt from stdin, parses the JSON envelope, and returns the assistant text.
Cost/token usage is pulled from the envelope into the engagement budget. All shared logic
(JSON extraction, grounding, fallback) lives in :mod:`rampart.intelligence.llm_base`.
"""
from __future__ import annotations

import json
import shutil
import subprocess

from .llm_base import LLMProvider, extract_json


class ClaudeCodeProvider(LLMProvider):
    name = "claude-code"

    def __init__(self, cli: str | None = None, timeout: float = 120.0, budget=None, model: str | None = None):
        super().__init__(budget=budget)
        self.cli = cli or shutil.which("claude") or "claude"
        self.timeout = timeout
        self.model = model

    def _complete(self, prompt: str) -> str | None:
        cmd = [self.cli, "-p", "--output-format", "json"]
        if self.model:
            cmd += ["--model", self.model]
        try:
            proc = subprocess.run(cmd, input=prompt, capture_output=True, text=True, timeout=self.timeout)
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            return None
        if proc.returncode != 0:
            return None
        try:
            envelope = json.loads(proc.stdout)
        except json.JSONDecodeError:
            envelope = None
            for line in reversed(proc.stdout.strip().splitlines()):
                envelope = extract_json(line)
                if isinstance(envelope, dict):
                    break
        if not isinstance(envelope, dict):
            return None
        if self.budget is not None:
            self.budget.record_cost(float(envelope.get("total_cost_usd", 0.0) or 0.0))
            usage = envelope.get("usage") or {}
            self.budget.record_tokens(int(usage.get("input_tokens", 0)) + int(usage.get("output_tokens", 0)))
        if envelope.get("is_error"):
            return None
        return envelope.get("result", "")
