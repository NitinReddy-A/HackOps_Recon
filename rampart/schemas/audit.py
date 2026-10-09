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
        """Strict: unknown keys, missing required keys and wrongly-typed fields raise
        ``ValueError`` — an injected extra field must not be silently dropped (it is not covered
        by the hash, so accepting it would let a forger annotate a verified log)."""
        if not isinstance(d, dict):
            raise ValueError(f"audit event must be a JSON object, got {type(d).__name__}")
        fields = cls.__annotations__
        unknown = sorted(k for k in d if k not in fields)
        if unknown:
            raise ValueError(f"unknown audit event field(s): {', '.join(unknown)}")
        missing = sorted(k for k in ("engagement_id", "phase", "actor", "action", "event_hash") if k not in d)
        if missing:
            raise ValueError(f"missing audit event field(s): {', '.join(missing)}")
        for k, v in d.items():
            if k in _DICT_FIELDS and not isinstance(v, dict):
                raise ValueError(f"audit event field {k!r} must be an object")
            if k in _STR_FIELDS and not isinstance(v, str):
                raise ValueError(f"audit event field {k!r} must be a string")
        ev = cls(**{k: v for k, v in d.items() if k != "event_hash"})
        ev.event_hash = d["event_hash"]
        return ev


_DICT_FIELDS = frozenset({"actor", "action", "policy_decision", "intent", "approval", "execution", "budget"})
_STR_FIELDS = frozenset({"engagement_id", "phase", "tenant_id", "ts", "event_id", "prev_hash", "event_hash"})
