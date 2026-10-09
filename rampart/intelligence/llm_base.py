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

from . import prompts
from .base import IntelligenceProvider
from .deterministic import DeterministicProvider

_FENCE = re.compile(r"```(?:json)?\s*(.*?)```", re.DOTALL)


# Hypothesis classes an access-control (grounded) hypothesis may carry. These are the only
# classes the BOLA/IDOR worker executes; anything else an LLM returns is dropped.
_ACCESS_CONTROL_CLASSES = {"IDOR/BOLA"}
_CLASS_ALIASES = {
    "idor/bola": "IDOR/BOLA",
    "bola/idor": "IDOR/BOLA",
    "idor": "IDOR/BOLA",
    "bola": "IDOR/BOLA",
}
_CWE = re.compile(r"^CWE-\d{1,5}$")


def content_text(content):
    """Normalise a chat message ``content`` to text.

    Accepts a plain string or a list of content parts (``[{"type":"text","text":...}, ...]``,
    as some OpenAI-compatible gateways return). Returns None if no text can be found."""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for part in content:
            if isinstance(part, str):
                parts.append(part)
            elif isinstance(part, dict) and isinstance(part.get("text"), str):
                parts.append(part["text"])
        return "".join(parts) if parts else None
    return None


def normalize_vuln_class(value, default="IDOR/BOLA"):
    """Map an LLM-supplied vuln_class onto a supported access-control class, else None."""
    if value is None:
        return default
    if not isinstance(value, str):
        return None
    v = value.strip()
    if v in _ACCESS_CONTROL_CLASSES:
        return v
    return _CLASS_ALIASES.get(v.lower())


def _clean_cwes(value, default):
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, list):
        return list(default)
    out = [c.strip().upper() for c in value if isinstance(c, str) and _CWE.match(c.strip().upper())]
    return out or list(default)


def extract_json(text):
    if not isinstance(text, str):
        text = content_text(text)
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
                        return json.loads(text[start : i + 1])
                    except json.JSONDecodeError:
                        break
    return None


class LLMProvider(IntelligenceProvider):
    name = "llm"

    def __init__(self, budget=None):
        self.budget = budget
        self._fallback = DeterministicProvider()
        self.degraded = False
        self.degraded_reasons: list[str] = []  # why calls fell back (for the caller to surface)
        self.notes: list[str] = []  # non-fatal configuration notes
        self.calls = 0

    def note(self, msg: str) -> None:
        if msg and msg not in self.notes:
            self.notes.append(msg)

    def degrade(self, reason: str) -> None:
        self.degraded = True
        if reason and reason not in self.degraded_reasons:
            self.degraded_reasons.append(reason)

    # subclasses implement this
    def _complete(self, prompt: str) -> str | None:
        raise NotImplementedError

    def _json(self, prompt: str):
        try:
            out = self._complete(prompt)
        except Exception as exc:  # noqa: BLE001 - a provider must never crash the scan
            self.degrade(f"{type(exc).__name__}: {exc}")
            out = None
        if out is None:
            self.degraded = True
            return None
        self.calls += 1
        try:
            return extract_json(out)
        except Exception:  # noqa: BLE001
            return None

    # ---------------------------------------------------------------- methods
    def label_endpoint(self, ctx: dict) -> dict:
        clean = self._valid_label(self._json(prompts.label_endpoint_prompt(ctx)))
        if clean is not None:
            return clean
        return self._fallback.label_endpoint(ctx)

    @staticmethod
    def _valid_label(out):
        """Return a shape-checked copy of a label_endpoint reply, or None if it is malformed."""
        if not isinstance(out, dict) or not isinstance(out.get("is_ownable"), bool):
            return None
        otype = out.get("returns_object_type")
        if otype is not None and not isinstance(otype, str):
            return None
        sel = out.get("object_selector")
        if sel is not None and not isinstance(sel, dict):
            return None
        if sel:
            param, where = sel.get("param"), sel.get("in", "path")
            if not isinstance(param, str) or not param or where not in ("path", "query"):
                return None
            sel = {"param": param, "in": where}
        rationale = out.get("rationale")
        return {
            "returns_object_type": otype or None,
            "object_selector": sel or {},
            "is_ownable": out["is_ownable"],
            "rationale": rationale if isinstance(rationale, str) else "",
        }

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
        candidates = {c for c in (ctx.get("candidate_classes") or []) if isinstance(c, str)}
        out = self._json(prompts.plan_prompt(ctx))
        if isinstance(out, dict) and isinstance(out.get("order"), list):
            order = [c for c in out["order"] if isinstance(c, str) and c in candidates]
            if order:
                out["order"] = order
                return out
        return IntelligenceProvider.plan_assessment(self, ctx)

    def agent_step(self, ctx: dict) -> dict:
        # A reasoning step for the business-logic / access-logic / critic agents.
        out = self._json(prompts.agent_step_prompt(ctx))
        return out if isinstance(out, dict) else {"thought": "no decision", "stop": True}

    def draft_finding_narrative(self, ctx: dict) -> dict:
        out = self._json(prompts.narrative_prompt(ctx))
        if isinstance(out, dict) and isinstance(out.get("description"), str):
            return {k: v for k, v in out.items() if isinstance(v, str)}
        return self._fallback.draft_finding_narrative(ctx)

    def propose_patch(self, ctx: dict) -> dict:
        out = self._json(prompts.patch_prompt(ctx))
        if isinstance(out, dict) and isinstance(out.get("diff"), str):
            return {"diff": out["diff"], "explanation": str(out.get("explanation") or "")}
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
            vclass = normalize_vuln_class(h.get("vuln_class"))
            if vclass is None:
                continue  # non-string / unsupported class from the model: drop, never crash
            eid = h.get("endpoint_id")
            ep = ep_by_id.get(eid) if isinstance(eid, str) else None
            atk, vic = h.get("attacker_principal"), h.get("victim_principal")
            if not isinstance(atk, str) or not isinstance(vic, str):
                continue
            if not ep or atk not in principals or vic not in principals or atk == vic:
                continue
            otype = ep.get("returns_object_type")
            atk_obj = next(
                (o for o in objects if o.get("owner_principal") == atk and o.get("type") == otype), None
            )
            vic_obj = next(
                (o for o in objects if o.get("owner_principal") == vic and o.get("type") == otype), None
            )
            if not atk_obj or not vic_obj:
                continue
            grounded.append(
                {
                    "vuln_class": vclass,
                    "cwe": _clean_cwes(h.get("cwe"), ["CWE-639"]),
                    "endpoint_id": ep["id"],
                    "endpoint_method": ep["method"],
                    "endpoint_path": ep["path"],
                    "object_type": otype,
                    "selector_param": (ep.get("object_selector") or {}).get("param"),
                    "attacker_principal": atk,
                    "victim_principal": vic,
                    "attacker_object": atk_obj,
                    "victim_object": vic_obj,
                    "rationale": (h.get("rationale") if isinstance(h.get("rationale"), str) else "")[:2000]
                    + " [LLM-proposed; grounded against the app model]",
                }
            )
        return grounded
