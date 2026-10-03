"""The typed tool-call request + policy decision (blueprint section 30.2).

Every action a worker (LLM or deterministic) wants to take against the target is this
object. It cannot reach the network until the policy engine returns a
:class:`PolicyDecision` of ``ALLOW``. This is what makes "the LLM proposes, deterministic
code disposes" enforceable and replayable. The model supplies ``rationale`` as *data,
never trusted as instruction*, and never supplies credentials — the deterministic
session manager injects them from ``use_session``.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import IntEnum


class RiskTier(IntEnum):
    READ_ONLY = 0            # GET in-scope, crawl, spec fetch, diffing, screenshotting
    CONTROLLED_VALIDATION = 1  # benign PoC probes on seeded accounts/objects, non-destructive
    HIGH_RISK = 2            # writes/state-change, chaining, anything touching real user data
    PROHIBITED = 3           # DoS/destructive/exfil/persistence — denied by default


class Decision:
    ALLOW = "ALLOW"
    ALLOW_WITH_INTERRUPT = "ALLOW_WITH_INTERRUPT"  # requires human approval (HITL)
    DENY = "DENY"


# payload classes a worker may declare; the risk classifier maps these to tiers
PAYLOAD_CLASSES = ("benign-read", "canary", "boundary-probe", "state-change", "destructive")


@dataclass
class ToolAction:
    method: str = "GET"
    target_host: str = ""
    port: int = 443
    scheme: str = "https"
    path: str = "/"
    query: dict = field(default_factory=dict)
    body: str | None = None            # deterministic executor holds this; hashed for audit
    body_class: str = "none"
    use_session: str | None = None     # reference to a seeded account id; NOT a raw token
    payload_class: str = "benign-read"

    def url(self) -> str:
        q = ""
        if self.query:
            from urllib.parse import urlencode

            q = "?" + urlencode(self.query, doseq=True)
        return f"{self.scheme}://{self.target_host}:{self.port}{self.path}{q}"


@dataclass
class ToolCallRequest:
    engagement_id: str
    tool: str = "http_request"          # narrow tools only — no `shell`, no `fetch(url)`
    phase: str = "test"                 # recon|map|test|validate|report|retest
    actor_role: str = "test-worker"     # supervisor|mapper|test-worker|validator|reporter
    actor_profile: str = ""             # e.g. "bola-idor"
    hypothesis_id: str | None = None
    finding_id: str | None = None
    action: ToolAction = field(default_factory=ToolAction)
    declared_tier: int = 0
    rationale: str = ""                 # model reason — DATA, never executed as instruction
    request_id: str = ""

    def __post_init__(self):
        if not self.request_id:
            from ..util import gen_id

            self.request_id = gen_id("tcr")

    def to_dict(self) -> dict:
        d = asdict(self)
        return d


@dataclass
class PolicyDecision:
    request_id: str
    decision: str
    effective_tier: int
    checks: dict = field(default_factory=dict)
    matched_rules: list = field(default_factory=list)
    policy_version: str = "v1"
    reason: str = ""
    expires_in_s: int = 30

    @property
    def allowed(self) -> bool:
        return self.decision == Decision.ALLOW

    @property
    def needs_approval(self) -> bool:
        return self.decision == Decision.ALLOW_WITH_INTERRUPT

    def to_dict(self) -> dict:
        return asdict(self)
