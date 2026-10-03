"""The application model — the substrate that makes BOLA/IDOR decidable (section 30.3).

Authorization is only decidable if the platform knows *which object an endpoint returns,
which parameter selects it, and who owns it*. A flat endpoint list cannot express "user B
read user A's order"; this can. It is ordinary relational data — no graph DB at MVP.

Every ingested string carries a ``trust_level`` (OWASP LLM01 / ASI06): target-derived
text is ``untrusted`` and is never concatenated into an instruction context.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field


@dataclass
class Endpoint:
    id: str
    method: str
    path: str                       # template, e.g. /api/orders/{id}
    auth_required: bool = False
    returns_object_type: str | None = None
    object_selector: dict = field(default_factory=dict)  # {"param": "id", "in": "path"}
    observed_roles: list = field(default_factory=list)
    provenance: str = "crawl"        # crawl|spec|repo|manual
    trust_level: str = "untrusted"


@dataclass
class Principal:
    id: str
    role: str
    seeded: bool = True


@dataclass
class Obj:
    type: str
    id: str
    owner_principal: str
    seeded: bool = True
    signature: str | None = None     # a distinctive value the oracle looks for in responses


@dataclass
class Permission:
    role: str
    object_type: str
    action: str
    constraint: str = "owner_only"   # owner_only | any | role_scoped


@dataclass
class ApplicationModel:
    engagement_id: str
    endpoints: list = field(default_factory=list)
    roles: list = field(default_factory=list)
    principals: list = field(default_factory=list)
    objects: list = field(default_factory=list)
    permissions: list = field(default_factory=list)

    # ------------------------------------------------------------- helpers
    def endpoint(self, endpoint_id: str) -> Endpoint | None:
        return next((e for e in self.endpoints if e.id == endpoint_id), None)

    def principal(self, pid: str) -> Principal | None:
        return next((p for p in self.principals if p.id == pid), None)

    def objects_owned_by(self, principal_id: str, object_type: str | None = None) -> list:
        return [
            o for o in self.objects
            if o.owner_principal == principal_id and (object_type is None or o.type == object_type)
        ]

    def ownable_endpoints(self) -> list:
        """Endpoints that return an ownable object selected by a parameter — IDOR candidates."""
        return [e for e in self.endpoints if e.returns_object_type and e.object_selector]

    def to_dict(self) -> dict:
        return {
            "engagement_id": self.engagement_id,
            "endpoints": [asdict(e) for e in self.endpoints],
            "roles": list(self.roles),
            "principals": [asdict(p) for p in self.principals],
            "objects": [asdict(o) for o in self.objects],
            "permissions": [asdict(p) for p in self.permissions],
        }

    @classmethod
    def from_dict(cls, d: dict) -> "ApplicationModel":
        return cls(
            engagement_id=d.get("engagement_id", ""),
            endpoints=[Endpoint(**e) for e in d.get("endpoints", [])],
            roles=list(d.get("roles", [])),
            principals=[Principal(**p) for p in d.get("principals", [])],
            objects=[Obj(**o) for o in d.get("objects", [])],
            permissions=[Permission(**p) for p in d.get("permissions", [])],
        )
