"""ProbeRunner — the only way workers and the validator issue requests.

It wraps the policy pipeline so every probe is gated, audited, and (optionally) captured
as evidence. Nothing here decides whether a finding is real; it just executes vetted
Tier-0/1 reads and returns the outcome.
"""

from __future__ import annotations

import json as _json
import threading
from dataclasses import dataclass, field

from .schemas.toolcall import ToolAction, ToolCallRequest


class ProbeStats:
    """Thread-safe tally of every probe issued through :class:`ProbeRunner` for one engagement.

    Lets the engagement tell "ran and found nothing" from "never reached the target": a DAST run
    in which no request was executed (target down, or every request blocked by policy) is
    reported as *incomplete* rather than clean. Attach one to the pipeline as ``probe_stats``.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self.executed = 0
        self.blocked = 0  # denied by the policy pipeline (scope / tier / budget)
        self.errors = 0  # allowed, but the executor failed (connection refused, timeout, ...)
        self.last_error = ""
        self.last_blocked = ""

    def record(self, result) -> None:
        with self._lock:
            if getattr(result, "executed", False):
                self.executed += 1
                return
            reason = str(getattr(result, "blocked_reason", "") or "")
            if reason.startswith("executor error"):
                self.errors += 1
                self.last_error = reason
            else:
                self.blocked += 1
                self.last_blocked = reason

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "executed": self.executed,
                "blocked": self.blocked,
                "errors": self.errors,
                "last_error": self.last_error,
                "last_blocked": self.last_blocked,
            }


@dataclass
class ProbeOutcome:
    executed: bool
    response: object = None
    decision: object = None
    evidence: list = field(default_factory=list)
    audit_ids: list = field(default_factory=list)
    blocked_reason: str = ""

    @property
    def status(self):
        return getattr(self.response, "status", None)

    @property
    def body(self):
        return getattr(self.response, "body", "") or ""


class ProbeRunner:
    def __init__(
        self,
        pipeline,
        evidence_store,
        engagement_id,
        host,
        port,
        scheme="http",
        actor_role="test-worker",
        actor_profile="",
        phase="test",
    ):
        self.pipeline = pipeline
        self.evidence = evidence_store
        self.engagement_id = engagement_id
        self.host = host
        self.port = port
        self.scheme = scheme
        self.actor_role = actor_role
        self.actor_profile = actor_profile
        self.phase = phase

    def get(
        self,
        path,
        session,
        payload_class="boundary-probe",
        rationale="",
        hypothesis_id=None,
        capture=True,
        summary="",
        query=None,
        headers=None,
    ) -> ProbeOutcome:
        action = ToolAction(
            method="GET",
            target_host=self.host,
            port=self.port,
            scheme=self.scheme,
            path=path,
            query=dict(query or {}),
            use_session=session,
            headers=dict(headers or {}),
            payload_class=payload_class,
        )
        req = ToolCallRequest(
            engagement_id=self.engagement_id,
            actor_role=self.actor_role,
            actor_profile=self.actor_profile,
            action=action,
            declared_tier=1,
            rationale=rationale,
            hypothesis_id=hypothesis_id,
            phase=self.phase,
        )
        return self._execute(req, action, capture, summary)

    def post(
        self,
        path,
        json_body,
        session=None,
        payload_class="canary",
        rationale="",
        hypothesis_id=None,
        capture=True,
        summary="",
        headers=None,
        content_type=None,
    ) -> ProbeOutcome:
        """A gated POST with a JSON (or raw string) body. Still a typed ToolCallRequest through the
        one choke-point — POST classifies as Tier 2 (state-changing), so it is only permitted when
        the scope/approver authorizes it (e.g. --active, or an authorized LLM-endpoint assessment)."""
        body = json_body if isinstance(json_body, str) else _json.dumps(json_body)
        hdrs = dict(headers or {})
        if content_type:
            hdrs["Content-Type"] = content_type
        action = ToolAction(
            method="POST",
            target_host=self.host,
            port=self.port,
            scheme=self.scheme,
            path=path,
            body=body,
            body_class="json",
            use_session=session,
            headers=hdrs,
            payload_class=payload_class,
        )
        req = ToolCallRequest(
            engagement_id=self.engagement_id,
            actor_role=self.actor_role,
            actor_profile=self.actor_profile,
            action=action,
            declared_tier=2,
            rationale=rationale,
            hypothesis_id=hypothesis_id,
            phase=self.phase,
        )
        return self._execute(req, action, capture, summary)

    def _execute(self, req, action, capture, summary) -> ProbeOutcome:
        result = self.pipeline.execute(req)
        stats = getattr(self.pipeline, "probe_stats", None)
        if isinstance(stats, ProbeStats):
            stats.record(result)
        evs = []
        if capture and result.executed and self.evidence is not None:
            evs.append(self.evidence.put_request(action, result.resolved_ip, summary=summary))
            evs.append(self.evidence.put_response(result.response, summary=summary))
        return ProbeOutcome(
            executed=result.executed,
            response=result.response,
            decision=result.decision,
            evidence=evs,
            audit_ids=result.audit_event_ids,
            blocked_reason=str(getattr(result, "blocked_reason", "") or ""),
        )
