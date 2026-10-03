"""ProbeRunner — the only way workers and the validator issue requests.

It wraps the policy pipeline so every probe is gated, audited, and (optionally) captured
as evidence. Nothing here decides whether a finding is real; it just executes vetted
Tier-0/1 reads and returns the outcome.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .schemas.toolcall import ToolAction, ToolCallRequest


@dataclass
class ProbeOutcome:
    executed: bool
    response: object = None
    decision: object = None
    evidence: list = field(default_factory=list)
    audit_ids: list = field(default_factory=list)

    @property
    def status(self):
        return getattr(self.response, "status", None)

    @property
    def body(self):
        return getattr(self.response, "body", "") or ""


class ProbeRunner:
    def __init__(self, pipeline, evidence_store, engagement_id, host, port, scheme="http",
                 actor_role="test-worker", actor_profile="", phase="test"):
        self.pipeline = pipeline
        self.evidence = evidence_store
        self.engagement_id = engagement_id
        self.host = host
        self.port = port
        self.scheme = scheme
        self.actor_role = actor_role
        self.actor_profile = actor_profile
        self.phase = phase

    def get(self, path, session, payload_class="boundary-probe", rationale="",
            hypothesis_id=None, capture=True, summary="") -> ProbeOutcome:
        action = ToolAction(method="GET", target_host=self.host, port=self.port, scheme=self.scheme,
                            path=path, use_session=session, payload_class=payload_class)
        req = ToolCallRequest(engagement_id=self.engagement_id, actor_role=self.actor_role,
                              actor_profile=self.actor_profile, action=action, declared_tier=1,
                              rationale=rationale, hypothesis_id=hypothesis_id, phase=self.phase)
        result = self.pipeline.execute(req)
        evs = []
        if capture and result.executed and self.evidence is not None:
            evs.append(self.evidence.put_request(action, result.resolved_ip, summary=summary))
            evs.append(self.evidence.put_response(result.response, summary=summary))
        return ProbeOutcome(executed=result.executed, response=result.response,
                            decision=result.decision, evidence=evs, audit_ids=result.audit_event_ids)
