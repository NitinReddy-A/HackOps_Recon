"""Client for an authorized LLM endpoint — every prompt goes through the policy pipeline.

The chat request is a gated POST (Tier 2), so an authorized LLM assessment runs under the
same allowlist -> scope -> risk -> policy -> approval -> budget -> audit choke-point as every
other action. The model's reply is DATA — it is inspected by a deterministic oracle and never
executed or turned into a tool call.
"""
from __future__ import annotations

import json


def _dig(obj, dotted: str):
    cur = obj
    for part in (dotted or "").split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


class LLMClient:
    def __init__(self, runner, chat_path="/chat", input_field="message", output_field="reply"):
        self.runner = runner
        self.chat_path = chat_path
        self.input_field = input_field
        self.output_field = output_field

    def ask(self, prompt: str, summary: str = "llm probe"):
        """Returns (reply_text|None, outcome). reply is None if the request was blocked."""
        outcome = self.runner.post(self.chat_path, {self.input_field: prompt},
                                   payload_class="canary", rationale="LLM security probe (authorized)",
                                   summary=summary)
        if not outcome.executed:
            return None, outcome
        body = outcome.body
        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            return body, outcome                 # non-JSON endpoint: whole body is the reply
        reply = _dig(data, self.output_field)
        if reply is None:
            reply = body                          # fall back to raw body if the field is absent
        return (reply if isinstance(reply, str) else json.dumps(reply)), outcome
