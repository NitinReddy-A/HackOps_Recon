"""Shared logic for LLM-backed intelligence providers.

A concrete provider only implements :meth:`_complete` (prompt -> raw text). Everything
else — JSON extraction, the four intelligence methods, and the anti-hallucination grounding
that keeps only hypotheses referencing endpoints/principals/objects we actually discovered —
lives here and is identical across the Claude Code and OpenAI-compatible backends. Any
failure falls back to the deterministic provider so a run never breaks.
"""
from __future__ import annotations

import json
import re

from .base import IntelligenceProvider
from .deterministic import DeterministicProvider
from . import prompts

_FENCE = re.compile(r"```(?:json)?\s*(.*?)```", re.DOTALL)


def extract_json(text: str):
    text = (text or "").strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    m = _FENCE.search(text)
    if m:
        try:
            return json.loads(m.group(1).strip())
        except json.JSONDecodeError:
            pass
    for opener, closer in (("{", "}"), ("[", "]")):
        start = text.find(opener)
        if start == -1:
            continue
        depth = 0
        for i in range(start, len(text)):
            if text[i] == opener:
                depth += 1
            elif text[i] == closer:
                depth -= 1
                if depth == 0:
                    try:
                        return json.loads(text[start:i + 1])
                    except json.JSONDecodeError:
                        break
    return None


class LLMProvider(IntelligenceProvider):
    name = "llm"

    def __init__(self, budget=None):
        self.budget = budget
        self._fallback = DeterministicProvider()
        self.degraded = False
        self.calls = 0

    # subclasses implement this
    def _complete(self, prompt: str) -> str | None:
        raise NotImplementedError

    def _json(self, prompt: str):
        out = self._complete(prompt)
        if out is None:
            self.degraded = True
            return None
        self.calls += 1
        return extract_json(out)

    # ---------------------------------------------------------------- methods
    def label_endpoint(self, ctx: dict) -> dict:
        out = self._json(prompts.label_endpoint_prompt(ctx))
        if isinstance(out, dict) and "is_ownable" in out:
            return out
        return self._fallback.label_endpoint(ctx)

    def propose_hypotheses(self, appmodel: dict) -> list[dict]:
        out = self._json(prompts.hypotheses_prompt(appmodel))
        raw = out.get("hypotheses") if isinstance(out, dict) else None
        if not isinstance(raw, list):
            return self._fallback.propose_hypotheses(appmodel)
        return self._ground(raw, appmodel) or self._fallback.propose_hypotheses(appmodel)

    def propose_web_hypotheses(self, appmodel: dict) -> list[dict]:
        # Input-fuzzing classes are enumerated deterministically (reliable, no hallucination);
        # the independent oracle remains the sole confirmation gate.
        return self._fallback.propose_web_hypotheses(appmodel)

    def plan_assessment(self, ctx: dict) -> dict:
        # Planner agent (its own reasoning call); falls back to deterministic prioritisation.
        candidates = set(ctx.get("candidate_classes") or [])
        out = self._json(prompts.plan_prompt(ctx))
        if isinstance(out, dict) and isinstance(out.get("order"), list):
            order = [c for c in out["order"] if c in candidates]
            if order:
                out["order"] = order
                return out
        return IntelligenceProvider.plan_assessment(self, ctx)

    def draft_finding_narrative(self, ctx: dict) -> dict:
        out = self._json(prompts.narrative_prompt(ctx))
        if isinstance(out, dict) and "description" in out:
            return out
        return self._fallback.draft_finding_narrative(ctx)

    def propose_patch(self, ctx: dict) -> dict:
        out = self._json(prompts.patch_prompt(ctx))
        if isinstance(out, dict) and "diff" in out:
            return out
        return self._fallback.propose_patch(ctx)

    # ------------------------------------------------------------- grounding
    @staticmethod
    def _ground(raw: list, appmodel: dict) -> list[dict]:
        ep_by_id = {e["id"]: e for e in appmodel.get("endpoints", [])}
        principals = {p["id"] for p in appmodel.get("principals", [])}
        objects = appmodel.get("objects", [])
        grounded = []
        for h in raw:
            if not isinstance(h, dict):
                continue
            ep = ep_by_id.get(h.get("endpoint_id"))
            atk, vic = h.get("attacker_principal"), h.get("victim_principal")
            if not ep or atk not in principals or vic not in principals or atk == vic:
                continue
            otype = ep.get("returns_object_type")
            atk_obj = next((o for o in objects if o.get("owner_principal") == atk and o.get("type") == otype), None)
            vic_obj = next((o for o in objects if o.get("owner_principal") == vic and o.get("type") == otype), None)
            if not atk_obj or not vic_obj:
                continue
            grounded.append({
                "vuln_class": h.get("vuln_class", "IDOR/BOLA"),
                "cwe": h.get("cwe") or ["CWE-639"],
                "endpoint_id": ep["id"], "endpoint_method": ep["method"], "endpoint_path": ep["path"],
                "object_type": otype, "selector_param": (ep.get("object_selector") or {}).get("param"),
                "attacker_principal": atk, "victim_principal": vic,
                "attacker_object": atk_obj, "victim_object": vic_obj,
                "rationale": h.get("rationale", "") + " [LLM-proposed; grounded against the app model]",
            })
        return grounded
