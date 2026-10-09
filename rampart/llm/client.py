"""Client for an authorized LLM endpoint — every prompt goes through the policy pipeline.

The chat request is a gated POST (Tier 2), so an authorized LLM assessment runs under the
same allowlist -> scope -> risk -> policy -> approval -> budget -> audit choke-point as every
other action. The model's reply is DATA — it is inspected by a deterministic oracle and never
executed or turned into a tool call.

A reply is only handed to the oracle when it is trustworthy as "what the model said": the
request was executed, the HTTP status was 2xx, and (for a JSON body) the configured output
field resolved. Anything else is reported as ``blocked`` (policy refused it), ``error``
(transport failure / timeout / non-2xx) or ``inconclusive`` (the reply could not be located),
so an error page that quotes the prompt can never be mistaken for a model reply, and a broken
endpoint can never be mistaken for a model whose guardrails "held".
"""

from __future__ import annotations

import json
from dataclasses import dataclass

# Reply statuses (distinct on purpose — see module docstring).
OK = "ok"
BLOCKED = "blocked"
ERROR = "error"
INCONCLUSIVE = "inconclusive"

_MISSING = object()


def _dig(obj, dotted: str):
    """Resolve a dotted path; numeric segments index lists (``choices.0.message.content``).

    Returns ``_MISSING`` when any segment does not resolve."""
    cur = obj
    for part in (dotted or "").split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        elif isinstance(cur, list) and part.lstrip("-").isdigit():
            idx = int(part)
            if -len(cur) <= idx < len(cur):
                cur = cur[idx]
            else:
                return _MISSING
        else:
            return _MISSING
    return cur


@dataclass
class LLMReply:
    status: str  # ok | blocked | error | inconclusive
    text: str | None = None  # the model reply (only when status == ok)
    outcome: object = None
    note: str = ""
    http_status: int | None = None

    @property
    def ok(self) -> bool:
        return self.status == OK and self.text is not None


class LLMClient:
    def __init__(self, runner, chat_path="/chat", input_field="message", output_field="reply"):
        self.runner = runner
        self.chat_path = chat_path
        self.input_field = input_field
        self.output_field = output_field

    def query(self, prompt: str, summary: str = "llm probe") -> LLMReply:
        """Send one prompt through the gated pipeline and classify the result."""
        outcome = self.runner.post(
            self.chat_path,
            {self.input_field: prompt},
            payload_class="canary",
            rationale="LLM security probe (authorized)",
            summary=summary,
        )
        if not outcome.executed:
            decision = getattr(outcome, "decision", None)
            allowed = getattr(decision, "allowed", False)
            if allowed:
                # policy allowed it, but the executor failed (connection refused, timeout, ...)
                return LLMReply(ERROR, outcome=outcome, note="request failed (connection error or timeout)")
            reason = getattr(decision, "reason", "") or "denied by policy"
            return LLMReply(BLOCKED, outcome=outcome, note=f"blocked: {reason}")

        status = outcome.status
        if not isinstance(status, int) or not (200 <= status < 300):
            return LLMReply(
                ERROR,
                outcome=outcome,
                http_status=status if isinstance(status, int) else None,
                note=f"HTTP {status} from {self.chat_path} — not a model reply (probe not evaluated)",
            )

        body = outcome.body
        try:
            data = json.loads(body)
        except (json.JSONDecodeError, ValueError):
            # non-JSON endpoint: the whole (2xx) body is the reply
            return LLMReply(OK, text=body, outcome=outcome, http_status=status)
        if not self.output_field:
            return LLMReply(OK, text=body, outcome=outcome, http_status=status)
        reply = _dig(data, self.output_field)
        if reply is _MISSING or reply is None:
            return LLMReply(
                INCONCLUSIVE,
                outcome=outcome,
                http_status=status,
                note=(
                    f"output field {self.output_field!r} not found in the JSON response — "
                    "set --output-field to the reply's dotted path (e.g. choices.0.message.content)"
                ),
            )
        text = reply if isinstance(reply, str) else json.dumps(reply)
        return LLMReply(OK, text=text, outcome=outcome, http_status=status)

    def ask(self, prompt: str, summary: str = "llm probe"):
        """Back-compat: returns (reply_text|None, outcome); reply is None unless status == ok."""
        r = self.query(prompt, summary=summary)
        return (r.text if r.ok else None), r.outcome
