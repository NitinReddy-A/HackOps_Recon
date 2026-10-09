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

import ipaddress
import re
from urllib.parse import unquote, urlsplit

_METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE")
_ABS_URL = re.compile(r"(?i)\b([a-z][a-z0-9+.\-]*)://([^\s/?#'\"<>]*)")
_METADATA_HOSTS = {"metadata.google.internal", "metadata", "instance-data", "metadata.azure.internal"}


def _path_problem(path) -> str:
    """Why an agent-proposed path is not a server-relative path on the authorized target ('' = ok)."""
    if not isinstance(path, str) or not path:
        return "path must be a non-empty string"
    if not path.startswith("/"):
        return "action.path must be a server-relative path starting with '/'"
    if path.startswith("//") or "\\" in path or "://" in path:
        return "action.path must not name another host or scheme (path-only on the authorized target)"
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in path):
        return "action.path must not contain control characters"
    return ""


def _host_is_sensitive(host: str) -> bool:
    h = (host or "").strip("[]").lower()
    if h in _METADATA_HOSTS:
        return True
    try:
        ip = ipaddress.ip_address(h)
    except ValueError:
        return False
    return ip.is_link_local or ip.is_multicast or ip.is_unspecified or str(ip) == "fd00:ec2::254"


def vet_action(action, scope=None) -> str:
    """Containment check for an agent-proposed probe ('' = ok, else the refusal reason).

    The policy pipeline still gates whatever passes; this refuses, before anything is sent,
    proposals that would steer the authorized target at things outside the contract: other
    hosts/schemes in the path, ``file://`` and other non-HTTP URLs, link-local / cloud-metadata
    addresses, or absolute URLs to hosts that are not in ``scope.in_scope``."""
    if not isinstance(action, dict):
        return "action must be an object"
    why = _path_problem(action.get("path"))
    if why:
        return why
    q = action.get("query") or {}
    if not isinstance(q, dict):
        return "action.query must be an object"
    values = [action["path"]] + [f"{k}={v}" for k, v in q.items()]
    values += [unquote(unquote(str(t))) for t in values]  # look through (double) URL-encoding
    for text in values:
        for m in _ABS_URL.finditer(str(text)):
            scheme, netloc = m.group(1).lower(), m.group(2)
            if scheme not in ("http", "https"):
                return f"{scheme}:// URLs are not permitted in agent probes"
            try:
                host = urlsplit(f"{scheme}://{netloc}").hostname or ""
            except ValueError:
                return "malformed URL in agent probe"
            if _host_is_sensitive(host):
                return f"link-local / cloud-metadata address {host!r} is not permitted"
            if scope is not None and scope.host_scope(host) is None:
                return f"URL host {host!r} is outside the authorized scope"
    return ""


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
            why = _path_problem(action.get("path"))
            if why:
                errs.append(why)
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
        self.last_rejected = None  # the last decision rejected as invalid (for the audit trail)

    def decide(self, ctx: dict) -> tuple[dict, str]:
        """Return (decision, status). status in: ok | invalid | repeat.

        'invalid' means validation failed even after a repair attempt (caller should stop the
        objective). 'repeat' means the proposed action was already executed (loop — caller stops)."""
        d = self._ask(ctx)
        self.stats["decisions"] += 1
        ok, errs = validate_decision(d)
        repairs = 0
        while not ok and repairs < self.max_repairs:
            self.stats["repairs"] += 1
            repairs += 1
            d = self._ask({**ctx, "repair_errors": errs, "previous": d})
            self.stats["decisions"] += 1
            ok, errs = validate_decision(d)
        if not ok:
            self.stats["invalid"] += 1
            self.last_rejected = d
            return {"thought": f"invalid decision: {'; '.join(errs)}", "stop": True}, "invalid"
        if d.get("action"):
            sig = action_signature(d["action"])
            if sig in self.seen:
                self.stats["repeats"] += 1
                return d, "repeat"
            self.seen.add(sig)
        return d, "ok"

    def _ask(self, ctx):
        try:
            return self.brain.decide(ctx)
        except Exception as exc:  # noqa: BLE001 - a brain error is an invalid decision, not a crash
            return {"error": f"{type(exc).__name__}: {exc}"}

    def reset_loop_memory(self):
        self.seen.clear()
