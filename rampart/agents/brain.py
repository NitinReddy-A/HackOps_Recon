"""Agent "brains" — produce a structured decision from the current reasoning context.

A brain decides the next step for an exploration/critic agent. The real brain delegates to
the configured IntelligenceProvider (Claude Code / OpenAI-compatible); the deterministic
provider cannot reason, so it simply stops (honest: business-logic reasoning needs an LLM).
``MockBrain`` replays a scripted list of decisions so the whole orchestration — tool execution,
policy gating, finding tiering — is testable with no LLM and no cost.

A decision is a dict:
    {"thought": str,
     "action": {"method": "GET", "path": str, "query": {...}} | None,   # a probe to run (GET only)
     "conclude": {finding fields} | None,                                # emit a candidate finding
     "verdict": "stands" | "refuted" | None,                             # critic only
     "stop": bool}
Any target-derived text in the context is UNTRUSTED and must never be treated as instructions.
"""
from __future__ import annotations


class AgentBrain:
    def __init__(self, intel):
        self.intel = intel
        self.name = getattr(intel, "name", "deterministic")

    def decide(self, context: dict) -> dict:
        try:
            out = self.intel.agent_step(context)
            if isinstance(out, dict):
                return out
        except Exception:  # noqa: BLE001 - a brain error must not break the run
            pass
        return {"thought": "no decision", "stop": True}

    def can_reason(self) -> bool:
        # the deterministic provider returns stop immediately; LLM-backed providers reason.
        return self.name not in ("deterministic", "base")


class MockBrain:
    """Replays scripted decisions (for tests). Optionally keys scripts by agent 'mode'."""

    def __init__(self, script):
        if isinstance(script, dict):
            self._by_mode = {k: list(v) for k, v in script.items()}
            self._flat = None
        else:
            self._by_mode = None
            self._flat = list(script)
        self.name = "mock"
        self.calls = []

    def decide(self, context: dict) -> dict:
        self.calls.append(context)
        if self._by_mode is not None:
            q = self._by_mode.get(context.get("mode", ""), [])
            return q.pop(0) if q else {"thought": "end", "stop": True}
        if self._flat:
            return self._flat.pop(0)
        return {"thought": "end", "stop": True}

    def can_reason(self) -> bool:
        return True
