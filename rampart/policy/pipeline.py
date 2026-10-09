"""The single safety choke-point (blueprint section 12).

No agent code executes a tool call directly. Everything goes through
:meth:`PolicyPipeline.execute`, which runs, in order and fail-closed:

    0. scope expiry (checked on EVERY request, not only at start)
    1. target allowlist (host + port + resolved IP)
    2. scope validator (scheme/path/method/Host-header/exclusions, on the canonical path)
    3. action-risk classifier (deterministic tiers)
    4. policy engine (ALLOW / ALLOW_WITH_INTERRUPT / DENY)
    5. human approval interrupt for Tier 2 (HITL)
    6. budget / rate-limit (throttle) / kill-switch
    7. execution via the deterministic executor (narrow tools only)
    8. append-only audit BEFORE (intent+decision) and AFTER (result)

If any stage errors or is unreachable, the request is denied (and the denial is audited).

Seeded-account logins (a setup step, not an attack action) use :meth:`execute_setup`: the same
expiry/allowlist/scope/budget/audit stages, minus the risk tier + approval (a login POST is not a
Tier-2 attack on the target — but it must still stay on in-scope hosts/ports/paths/methods).
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from ..schemas.audit import AuditEvent
from ..schemas.scope import EngagementScope
from ..schemas.toolcall import Decision, PolicyDecision, ToolCallRequest
from ..util import redact_headers, redact_params, sha256_hex
from . import allowlist, engine, risk, scope_validator
from .budget import BudgetTracker

# approver(request, decision) -> {"granted": bool, "approver_user_id": str, "scope_bound": {...}}
Approver = Callable[[ToolCallRequest, PolicyDecision], dict]


@dataclass
class PipelineResult:
    decision: PolicyDecision
    executed: bool = False
    response: object = None  # executor's HttpResponse, or None if blocked
    blocked_reason: str = ""
    resolved_ip: str = ""
    audit_event_ids: list = field(default_factory=list)


class PolicyPipeline:
    def __init__(
        self,
        scope: EngagementScope,
        audit_log,
        budget: BudgetTracker,
        executor,
        resolver=allowlist.default_resolver,
        approver: Approver | None = None,
    ):
        self.scope = scope
        self.audit = audit_log
        self.budget = budget
        self.executor = executor
        self.resolver = resolver
        self.approver = approver
        self.engagement_id = scope.authorization.ticket or "engagement"
        # Route seeded-account logins through this choke-point: the executor's session manager
        # (if any) is bound to this pipeline so login requests are scope/budget/audit checked.
        sessions = getattr(executor, "sessions", None)
        if sessions is not None and hasattr(sessions, "attach_pipeline"):
            sessions.attach_pipeline(self)

    # ------------------------------------------------------------------ eval
    def _pre_checks(self, req: ToolCallRequest, checks: dict, rules: list):
        """Stages 0-2 shared by attack actions and setup (login) actions.
        Returns (deny_reason or "", resolved_ip)."""
        a = req.action
        if self.scope.is_expired():
            checks["scope_expiry"] = "fail"
            return f"scope contract expired or unparseable expiry ({self.scope.authorization.expires!r})", ""
        checks["scope_expiry"] = "pass"

        al = allowlist.check(self.scope, a, self.resolver)
        checks["allowlist"] = "pass" if al.ok else "fail"
        checks["resolved_ip"] = al.resolved_ip
        if not al.ok:
            return al.reason, al.resolved_ip

        sc = scope_validator.check(self.scope, a)
        checks["scope"] = "pass" if sc.ok else "fail"
        if not sc.ok:
            return sc.reason, al.resolved_ip
        if sc.matched_rule:
            rules.append(sc.matched_rule)
        return "", al.resolved_ip

    def evaluate(self, req: ToolCallRequest) -> tuple[PolicyDecision, str]:
        """Run stages 0-4. Returns (decision, resolved_ip). Does not execute or audit."""
        checks: dict = {}
        rules: list = []
        a = req.action

        why, resolved_ip = self._pre_checks(req, checks, rules)
        if why:
            return self._deny(req, checks, rules, why), resolved_ip

        rk = risk.classify(a, req.declared_tier)
        checks["risk_tier"] = rk.tier
        checks["risk_reason"] = rk.reason
        if rk.downgrade_attempt:
            checks["downgrade_attempt"] = True

        er = engine.decide(rk.tier, self.scope.action_policy, req.phase)
        rules.extend(er.matched_rules)
        decision = PolicyDecision(
            request_id=req.request_id,
            decision=er.decision,
            effective_tier=rk.tier,
            checks=checks,
            matched_rules=rules,
            policy_version=engine.POLICY_VERSION,
            reason=er.reason,
        )
        return decision, resolved_ip

    def _deny(self, req: ToolCallRequest, checks: dict, rules: list, reason: str) -> PolicyDecision:
        return PolicyDecision(
            request_id=req.request_id,
            decision=Decision.DENY,
            effective_tier=int(checks.get("risk_tier", 0) or 0),
            checks=checks,
            matched_rules=rules,
            policy_version=engine.POLICY_VERSION,
            reason=reason,
        )

    def _consume_budget(self, req: ToolCallRequest, decision: PolicyDecision) -> None:
        """Stage 6, fail-closed: any error in the tracker denies."""
        try:
            ok, why = self.budget.try_consume_request(req.action.target_host)
        except Exception as exc:  # noqa: BLE001
            ok, why = False, f"budget tracker error (fail-closed): {exc}"
        if not ok:
            decision.decision = Decision.DENY
            decision.reason = f"budget/circuit-breaker: {why}"
            decision.checks["rate_budget"] = "fail"
        else:
            decision.checks["rate_budget"] = "pass"
            if "throttled" in why:
                decision.checks["throttled"] = why

    # --------------------------------------------------------------- execute
    def execute(self, req: ToolCallRequest) -> PipelineResult:
        try:
            decision, resolved_ip = self.evaluate(req)
        except Exception as exc:  # noqa: BLE001 - fail closed on any unexpected error
            decision = self._deny(req, {"error": "exception"}, [], f"pipeline error (fail-closed): {exc}")
            resolved_ip = ""

        result = PipelineResult(decision=decision, resolved_ip=resolved_ip)
        approval_rec = {"required": decision.needs_approval, "status": "n/a"}

        # HITL for Tier 2
        if decision.needs_approval:
            if self.approver is None:
                decision.decision = Decision.DENY
                decision.reason = "Tier 2 requires approval but no approver configured (fail-closed)"
                approval_rec["status"] = "denied"
            else:
                try:
                    verdict = self.approver(req, decision) or {}
                    if not isinstance(verdict, dict):
                        raise TypeError(f"approver returned {type(verdict).__name__}, expected dict")
                except Exception as exc:  # noqa: BLE001 - an approver failure is a denial
                    verdict = {"granted": False, "error": str(exc)}
                if verdict.get("granted") is True:
                    approval_rec.update(
                        status="granted",
                        approver_user_id=str(verdict.get("approver_user_id", "")),
                        scope_bound=verdict.get("scope_bound", {}),
                    )
                    decision.decision = Decision.ALLOW
                else:
                    decision.decision = Decision.DENY
                    decision.reason = (
                        f"Tier 2 approver error (fail-closed): {verdict['error']}"
                        if verdict.get("error")
                        else "Tier 2 approval denied by human"
                    )
                    approval_rec["status"] = "denied"

        # Budget / rate limit (only if still allowed)
        if decision.allowed:
            self._consume_budget(req, decision)

        # AUDIT (before execution): intent + policy decision. If this write fails the
        # exception propagates and nothing is executed (fail-closed).
        ev_before = self._audit_before(req, decision, resolved_ip, approval_rec)
        result.audit_event_ids.append(ev_before.event_id)

        if not decision.allowed:
            result.blocked_reason = decision.reason
            return result

        # EXECUTE via the deterministic executor (the only place tools run)
        return self._run(
            req, decision, resolved_ip, result, lambda: self.executor.execute(req.action, resolved_ip)
        )

    def execute_setup(self, req: ToolCallRequest, send: Callable[[object, str], object]) -> PipelineResult:
        """Execute a setup request (seeded-account login) through stages 0-2 + 6 + 8.

        ``send(action, resolved_ip)`` performs the raw request (no session injection). The risk
        tier / approval stages are skipped — a login is not an attack action — but host, port,
        scheme, path, method, Host header, resolved IP, expiry and budget are all enforced, and
        the request is audited before and after with the body redacted.
        """
        checks: dict = {"setup": True}
        rules: list = []
        try:
            why, resolved_ip = self._pre_checks(req, checks, rules)
        except Exception as exc:  # noqa: BLE001
            why, resolved_ip = f"pipeline error (fail-closed): {exc}", ""
        if why:
            decision = self._deny(req, checks, rules, why)
        else:
            decision = PolicyDecision(
                request_id=req.request_id,
                decision=Decision.ALLOW,
                effective_tier=0,
                checks=checks,
                matched_rules=rules + ["setup.seeded_account_login"],
                policy_version=engine.POLICY_VERSION,
                reason="seeded-account session establishment (in scope)",
            )
            self._consume_budget(req, decision)
        result = PipelineResult(decision=decision, resolved_ip=resolved_ip)
        ev_before = self._audit_before(req, decision, resolved_ip, {"required": False, "status": "n/a"})
        result.audit_event_ids.append(ev_before.event_id)
        if not decision.allowed:
            result.blocked_reason = decision.reason
            return result
        return self._run(req, decision, resolved_ip, result, lambda: send(req.action, resolved_ip))

    def _run(self, req, decision, resolved_ip, result: PipelineResult, fn) -> PipelineResult:
        try:
            response = fn()
            result.executed = True
            result.response = response
        except Exception as exc:  # noqa: BLE001
            result.blocked_reason = f"executor error: {exc}"
            ev = self._audit_after(req, decision, resolved_ip, status="error", response=None, error=str(exc))
            result.audit_event_ids.append(ev.event_id)
            return result

        ev_after = self._audit_after(req, decision, resolved_ip, status="executed", response=response)
        result.audit_event_ids.append(ev_after.event_id)
        return result

    # ----------------------------------------------------------------- audit
    def _action_dict(self, req: ToolCallRequest, resolved_ip: str) -> dict:
        a = req.action
        setup = req.tool == "login"
        return {
            "class_tier": req.declared_tier,
            "tool": req.tool,
            "method": a.method,
            "scheme": a.scheme,
            "target_host": a.target_host,
            "port": a.port,
            "resolved_ip": resolved_ip,
            "path": a.path,
            "params_redacted": redact_params(a.query or {}),
            "use_session": a.use_session,
            "payload_class": a.payload_class,
            # never hash credentials: a hash of {"username":..,"password":..} is brute-forceable
            "payload_hash": ("<redacted:credentials>" if setup else sha256_hex(a.body)) if a.body else None,
        }

    def _audit_before(self, req, decision, resolved_ip, approval_rec) -> AuditEvent:
        ev = AuditEvent(
            engagement_id=req.engagement_id,
            phase=req.phase,
            actor={"type": "agent", "agent_role": req.actor_role, "profile": req.actor_profile},
            action=self._action_dict(req, resolved_ip),
            policy_decision={
                "decision": decision.decision,
                "effective_tier": decision.effective_tier,
                "checks": decision.checks,
                "matched_rules": decision.matched_rules,
                "policy_version": decision.policy_version,
                "reason": decision.reason,
            },
            intent={
                "hypothesis_id": req.hypothesis_id,
                "finding_id": req.finding_id,
                "rationale_summary": (req.rationale or "")[:280],
            },
            approval=approval_rec,
            execution={"status": "allowed" if decision.allowed else "blocked"},
            budget=self.budget.snapshot(),
        )
        return self.audit.append(ev)

    def _audit_after(self, req, decision, resolved_ip, status, response, error=None) -> AuditEvent:
        exec_block = {"status": status}
        if response is not None:
            exec_block.update(
                response_status=getattr(response, "status", None),
                response_hash=getattr(response, "body_sha256", ""),
                bytes=getattr(response, "size", 0),
                duration_ms=round(getattr(response, "duration_ms", 0.0), 2),
                headers_redacted=redact_headers(getattr(response, "headers", {}) or {}),
            )
        if error:
            exec_block["error"] = error
        ev = AuditEvent(
            engagement_id=req.engagement_id,
            phase=req.phase,
            actor={"type": "agent", "agent_role": req.actor_role, "profile": req.actor_profile},
            action=self._action_dict(req, resolved_ip),
            policy_decision={"decision": decision.decision, "effective_tier": decision.effective_tier},
            intent={"hypothesis_id": req.hypothesis_id, "finding_id": req.finding_id},
            execution=exec_block,
            budget=self.budget.snapshot(),
        )
        return self.audit.append(ev)
