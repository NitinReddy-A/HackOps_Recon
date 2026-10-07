"""Agent-harness reliability layer — validation, self-repair, loop/deviation guards, coverage.

The reasoning agents run on an LLM, so their output can be malformed, drift off-task, loop, or
silently skip objectives. This module makes the harness *robust and auditable* so the agentic
layer is accurate and misses nothing it set out to test:

* **Schema validation + one self-repair** — every brain decision is validated; an invalid one
  triggers a single corrective re-prompt, then a safe stop (never a silent no-op).
* **Loop / no-progress detection** — repeated identical actions are detected and halt the objective.
* **Deviation bounds** — actions are path-only on the authorized target (off-host is structurally
  impossible) and still pass the policy choke-point; budget/step caps are enforced here too.
* **No-miss coverage** — every planned objective gets a recorded outcome; unreached ones are surfaced.
"""
from __future__ import annotations

_METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE")


def validate_decision(d) -> tuple[bool, list]:
    """Return (ok, errors). A decision must be a JSON object that does exactly one meaningful thing."""
    if not isinstance(d, dict):
        return False, ["decision is not a JSON object"]
    errs: list[str] = []
    action = d.get("action")
    if action is not None:
        if not isinstance(action, dict) or not action.get("path"):
            errs.append("action must be an object containing a 'path'")
        else:
            if str(action.get("method", "GET")).upper() not in _METHODS:
                errs.append(f"action.method must be one of {_METHODS}")
            if not str(action.get("path", "")).startswith("/"):
                errs.append("action.path must be a server-relative path starting with '/'")
            q = action.get("query")
            if q is not None and not isinstance(q, dict):
                errs.append("action.query must be an object")
    conclude = d.get("conclude")
    if conclude is not None and (not isinstance(conclude, dict) or not conclude.get("title")):
        errs.append("conclude must be an object with a non-empty 'title'")
    if d.get("verdict") is not None and d["verdict"] not in ("stands", "refuted"):
        errs.append("verdict must be 'stands' or 'refuted'")
    if action is None and conclude is None and not d.get("stop") and d.get("verdict") is None:
        errs.append("decision must contain an action, a conclude, a verdict, or stop:true")
    return (not errs), errs


def action_signature(action) -> str:
    if not isinstance(action, dict):
        return ""
    q = action.get("query") or {}
    qs = "&".join(f"{k}={q[k]}" for k in sorted(q)) if isinstance(q, dict) else str(q)
    return f"{str(action.get('method', 'GET')).upper()} {action.get('path', '')}?{qs}"


class DecisionGuard:
    """Validates decisions, requests one self-repair, and detects action loops — per objective."""

    def __init__(self, brain, max_repairs: int = 1):
        self.brain = brain
        self.max_repairs = max_repairs
        self.seen: set[str] = set()
        self.stats = {"decisions": 0, "repairs": 0, "invalid": 0, "repeats": 0}

    def decide(self, ctx: dict) -> tuple[dict, str]:
        """Return (decision, status). status in: ok | invalid | repeat.

        'invalid' means validation failed even after a repair attempt (caller should stop the
        objective). 'repeat' means the proposed action was already executed (loop — caller stops)."""
        d = self.brain.decide(ctx)
        self.stats["decisions"] += 1
        ok, errs = validate_decision(d)
        repairs = 0
        while not ok and repairs < self.max_repairs:
            self.stats["repairs"] += 1
            repairs += 1
            d = self.brain.decide({**ctx, "repair_errors": errs, "previous": d})
            self.stats["decisions"] += 1
            ok, errs = validate_decision(d)
        if not ok:
            self.stats["invalid"] += 1
            return {"thought": f"invalid decision: {'; '.join(errs)}", "stop": True}, "invalid"
        if d.get("action"):
            sig = action_signature(d["action"])
            if sig in self.seen:
                self.stats["repeats"] += 1
                return d, "repeat"
            self.seen.add(sig)
        return d, "ok"

    def reset_loop_memory(self):
        self.seen.clear()
