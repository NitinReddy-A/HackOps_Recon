"""Shared accounting for engines that open their OWN connections outside the HTTP pipeline.

The live-infra scanner (raw TCP/TLS sockets), the gRPC engine (its own HTTP/2 channel) and the
headless browser (Chromium's own network stack) all bypass Rampart's ``PolicyPipeline``. This
module gives them the two pipeline guarantees they can still honour themselves:

* **Audit** — one hash-chained :class:`~rampart.schemas.audit.AuditEvent` per connection / RPC /
  browser request, allowed *or* blocked, so a reviewer can reconstruct every side-channel action.
* **Budget** — each admitted action consumes one request from the engagement's
  :class:`~rampart.policy.budget.BudgetTracker` (rate limit + total cap), and a killed budget
  (the kill-switch) stops the engine.

Both are optional: with ``audit=None`` / ``budget=None`` the guard is a no-op that admits every
action (the historical behaviour, kept for unit tests and library callers). An audit sink that
FAILS to record is fail-closed — the action is denied, exactly as the pipeline does.

:class:`ScanOutcome` is a ``list`` of findings that can also carry a structured ``skip_reason``
(e.g. ``"grpc: skipped — pip install rampart-appsec[grpc]"``) so a caller can tell "ran and found
nothing" from "did not run", without breaking callers that treat the result as a plain list.
"""

from __future__ import annotations

from ..schemas.audit import AuditEvent


class ScanOutcome(list):
    """A list of findings plus an optional machine-readable reason the engine did not (fully) run.

    ``skip_reason`` is "" when the engine ran. ``notes`` collects non-fatal remarks (e.g. a
    blocked out-of-scope request) for the caller's phase log.
    """

    def __init__(self, items=(), skip_reason: str = "", notes=None):
        super().__init__(items)
        self.skip_reason = skip_reason
        self.notes = list(notes or [])

    @property
    def skipped(self) -> bool:
        return bool(self.skip_reason)


def skip_reason_of(result) -> str:
    """The ``skip_reason`` of an engine result ("" for a plain list / an engine that ran)."""
    return str(getattr(result, "skip_reason", "") or "")


class SideChannelGuard:
    """Audit + budget gate for one out-of-pipeline engine.

    Parameters
    ----------
    audit:
        An :class:`~rampart.audit.AuditLog` (anything with ``append(AuditEvent)``), an object with
        ``record(AuditEvent)``, or a plain callable taking the event. ``None`` = no auditing.
    budget:
        A :class:`~rampart.policy.budget.BudgetTracker` (``try_consume_request(host)`` and
        ``killed``). ``None`` = unlimited.
    engagement_id, tool, actor_role, phase:
        Stamped on every audit event.
    """

    def __init__(
        self,
        audit=None,
        budget=None,
        engagement_id: str = "",
        tool: str = "side-channel",
        actor_role: str = "side-channel",
        phase: str = "test",
    ):
        self.audit = audit
        self.budget = budget
        self.engagement_id = engagement_id or ""
        self.tool = tool
        self.actor_role = actor_role
        self.phase = phase
        self.admitted = 0
        self.blocked = 0
        self.events: list = []  # lightweight local record (also useful when audit is None)

    # ------------------------------------------------------------------ state
    @property
    def killed(self) -> bool:
        """True once the engagement kill-switch is engaged — the engine must stop."""
        return bool(getattr(self.budget, "killed", False)) if self.budget is not None else False

    def _budget_snapshot(self) -> dict:
        snap = getattr(self.budget, "snapshot", None)
        if callable(snap):
            try:
                return dict(snap())
            except Exception:  # noqa: BLE001
                return {}
        return {}

    # ------------------------------------------------------------------ audit
    def _emit(self, action: dict, decision: str, reason: str, status: str) -> bool:
        """Record one event. Returns False if a configured audit sink failed (fail-closed)."""
        rec = {"action": dict(action), "decision": decision, "reason": reason, "status": status}
        self.events.append(rec)
        if self.audit is None:
            return True
        ev = AuditEvent(
            engagement_id=self.engagement_id,
            phase=self.phase,
            actor={"type": "engine", "agent_role": self.actor_role, "profile": self.tool},
            action=dict(action, tool=self.tool),
            policy_decision={"decision": decision, "reason": reason, "enforced_by": "side-channel-guard"},
            execution={"status": status},
            budget=self._budget_snapshot(),
        )
        try:
            if hasattr(self.audit, "append"):
                self.audit.append(ev)
            elif hasattr(self.audit, "record"):
                self.audit.record(ev)
            elif callable(self.audit):
                self.audit(ev)
            return True
        except Exception:  # noqa: BLE001 - audit write failure => deny (fail-closed)
            return False

    # ------------------------------------------------------------------ gate
    def admit(self, host: str, action: dict, allowed: bool = True, reason: str = "") -> tuple[bool, str]:
        """Decide + audit ONE side-channel action (a connect, an RPC, a browser request).

        ``allowed``/``reason`` carry the caller's own scope decision; a scope denial is recorded
        and returned as-is. An allowed action then has to pass the kill-switch and the budget
        (one request is consumed). Exactly one audit event is written either way.
        """
        host = str(host or "").lower()
        action = dict(action or {})
        action.setdefault("target_host", host)
        if not allowed:
            self.blocked += 1
            self._emit(action, "deny", reason or "out of scope", "blocked")
            return False, reason or "out of scope"
        if self.killed:
            why = f"kill-switch engaged: {getattr(self.budget, 'kill_reason', '')}".rstrip(": ")
            self.blocked += 1
            self._emit(action, "deny", why, "blocked")
            return False, why
        if self.budget is not None and hasattr(self.budget, "try_consume_request"):
            try:
                ok, why = self.budget.try_consume_request(host)
            except Exception as exc:  # noqa: BLE001 - a broken budget is fail-closed
                ok, why = False, f"budget error: {exc}"
            if not ok:
                self.blocked += 1
                self._emit(action, "deny", f"budget/circuit-breaker: {why}", "blocked")
                return False, f"budget/circuit-breaker: {why}"
        if not self._emit(action, "allow", reason or "in scope", "allowed"):
            self.blocked += 1
            return False, "audit log write failed (fail-closed)"
        self.admitted += 1
        return True, reason or "in scope"


def guard_from(guard=None, audit=None, budget=None, engagement_id: str = "", **kw) -> SideChannelGuard:
    """Return ``guard`` if given, else build one from ``audit``/``budget`` (no-op when both None)."""
    if isinstance(guard, SideChannelGuard):
        return guard
    return SideChannelGuard(audit=audit, budget=budget, engagement_id=engagement_id, **kw)
