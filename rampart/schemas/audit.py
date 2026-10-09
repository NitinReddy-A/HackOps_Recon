"""The append-only, hash-chained audit event (blueprint section 12).

Every action is logged BEFORE execution (intent + policy decision) and AFTER (result),
covering allow, deny and approvals. The chain is verifiable: each event stores the hash
of the previous event, so tampering with any record breaks every later ``event_hash``.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field

from ..util import GENESIS_HASH, chain_hash, gen_id, now_iso


@dataclass
class AuditEvent:
    engagement_id: str
    phase: str
    actor: dict  # {type, agent_role, model, user_id}
    action: dict  # {class_tier, tool, method, target_host, resolved_ip, path, ...}
    policy_decision: dict = field(default_factory=dict)
    intent: dict = field(default_factory=dict)
    approval: dict = field(default_factory=dict)
    execution: dict = field(default_factory=dict)
    budget: dict = field(default_factory=dict)
    tenant_id: str = "default"
    ts: str = field(default_factory=now_iso)
    event_id: str = ""
    prev_hash: str = GENESIS_HASH
    event_hash: str = ""

    def __post_init__(self):
        if not self.event_id:
            self.event_id = gen_id("evt")

    def _body(self) -> dict:
        d = asdict(self)
        d.pop("event_hash", None)
        return d

    def finalize(self, prev_hash: str) -> AuditEvent:
        self.prev_hash = prev_hash
        self.event_hash = chain_hash(self._body(), prev_hash)
        return self

    def verify(self) -> bool:
        return self.event_hash == chain_hash(self._body(), self.prev_hash)

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> AuditEvent:
        known = {k: v for k, v in d.items() if k in cls.__annotations__}
        ev = cls(**{k: v for k, v in known.items() if k not in ("event_hash",)})
        ev.event_hash = d.get("event_hash", "")
        return ev
