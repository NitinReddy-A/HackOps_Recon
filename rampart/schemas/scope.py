"""The ``rampart.scope.yaml`` scope & authorization contract (blueprint section 30.1).

This is the R1 gate made concrete: an engagement will not start unless this parses,
an owner is named, the attestation is present, the contract has not expired, and the
target resolves inside ``in_scope`` with a ``resolved_ip_allowlist`` entry. It is data
the deterministic policy engine reads — never something the LLM can edit mid-run.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone

from .. import yaml_lite

# IP ranges that must never be reachable regardless of the operator's allowlist
# (cloud metadata, link-local, multicast, unspecified). Anti-SSRF, blueprint section 23.
_HARD_BLOCK_NETS = [
    ipaddress.ip_network("169.254.0.0/16"),  # link-local incl. 169.254.169.254 metadata
    ipaddress.ip_network("fe80::/10"),  # IPv6 link-local
    ipaddress.ip_network("224.0.0.0/4"),  # multicast
    ipaddress.ip_network("0.0.0.0/8"),  # "this network"
    ipaddress.ip_network("::/128"),  # unspecified
]


class ScopeError(ValueError):
    """Raised when a scope contract is missing, malformed, or fails validation."""


def _glob_to_regex(pattern: str) -> re.Pattern:
    """Path glob: ``**`` matches across ``/``; ``*`` matches within a segment."""
    out, i = [], 0
    while i < len(pattern):
        c = pattern[i]
        if c == "*":
            if pattern[i : i + 2] == "**":
                out.append(".*")
                i += 2
                continue
            out.append("[^/]*")
        else:
            out.append(re.escape(c))
        i += 1
    return re.compile("^" + "".join(out) + "$")


def path_glob_match(pattern: str, path: str) -> bool:
    return _glob_to_regex(pattern).match(path) is not None


@dataclass
class TestAccount:
    id: str
    role: str
    secret_ref: str = ""

    @classmethod
    def from_dict(cls, d: dict) -> TestAccount:
        return cls(id=str(d["id"]), role=str(d.get("role", "")), secret_ref=str(d.get("secret_ref", "")))


@dataclass
class HostScope:
    host: str
    ports: list[int] = field(default_factory=lambda: [443])
    paths_include: list[str] = field(default_factory=lambda: ["/**"])
    methods: list[str] = field(default_factory=lambda: ["GET"])

    @classmethod
    def from_dict(cls, d: dict) -> HostScope:
        return cls(
            host=str(d["host"]).lower(),
            ports=[int(p) for p in (d.get("ports") or [443])],
            paths_include=[str(p) for p in (d.get("paths_include") or ["/**"])],
            methods=[str(m).upper() for m in (d.get("methods") or ["GET"])],
        )


@dataclass
class Authorization:
    owner: str = ""
    authorized_by: str = ""
    ticket: str = ""
    attestation: str = ""
    expires: str = ""


@dataclass
class Limits:
    max_requests_per_host_per_min: int = 120
    max_total_requests: int = 50000
    max_concurrent_workers: int = 4
    budget_usd: float = 25.0
    max_tokens: int = 20_000_000


@dataclass
class ActionPolicy:
    default_tier_ceiling: int = 1
    tier2_requires_approval: bool = True
    tier3: str = "deny"


@dataclass
class EngagementScope:
    api_version: str
    kind: str
    authorization: Authorization
    in_scope: list[HostScope]
    paths_exclude: list[str]
    hosts_exclude: list[str]
    resolved_ip_allowlist: list[str]
    limits: Limits
    action_policy: ActionPolicy
    test_accounts: list[TestAccount]
    notify: dict
    source_path: str = ""

    # ------------------------------------------------------------------ parse
    @classmethod
    def from_file(cls, path: str) -> EngagementScope:
        try:
            with open(path, encoding="utf-8") as fh:
                text = fh.read()
        except FileNotFoundError as exc:
            raise ScopeError(f"scope contract not found: {path}") from exc
        obj = cls.from_text(text)
        obj.source_path = path
        return obj

    @classmethod
    def from_text(cls, text: str) -> EngagementScope:
        front = _extract_front_matter(text)
        try:
            data = yaml_lite.load(front)
        except Exception as exc:  # noqa: BLE001 - fail closed on any parse error
            raise ScopeError(f"could not parse scope contract: {exc}") from exc
        if not isinstance(data, dict):
            raise ScopeError("scope contract must be a YAML mapping")
        return cls.from_dict(data)

    @classmethod
    def from_dict(cls, d: dict) -> EngagementScope:
        scope = d.get("scope") or {}
        in_scope = [HostScope.from_dict(h) for h in (scope.get("in_scope") or [])]
        out = scope.get("out_of_scope") or {}
        return cls(
            api_version=str(d.get("apiVersion", "")),
            kind=str(d.get("kind", "")),
            authorization=Authorization(
                **{
                    k: str(v)
                    for k, v in (d.get("authorization") or {}).items()
                    if k in Authorization.__annotations__
                }
            ),
            in_scope=in_scope,
            paths_exclude=[str(p) for p in (out.get("paths_exclude") or [])],
            hosts_exclude=[str(h).lower() for h in (out.get("hosts_exclude") or [])],
            resolved_ip_allowlist=[str(c) for c in (scope.get("resolved_ip_allowlist") or [])],
            limits=Limits(
                **{k: v for k, v in (d.get("limits") or {}).items() if k in Limits.__annotations__}
            ),
            action_policy=ActionPolicy(
                **{
                    k: v
                    for k, v in (d.get("action_policy") or {}).items()
                    if k in ActionPolicy.__annotations__
                }
            ),
            test_accounts=[TestAccount.from_dict(a) for a in (d.get("test_accounts") or [])],
            notify=d.get("notify") or {},
        )

    # -------------------------------------------------------------- validate
    def validate(self) -> list[str]:
        """Return a list of human-readable problems; empty means the gate may open."""
        errs: list[str] = []
        if self.kind != "EngagementScope":
            errs.append(f"kind must be 'EngagementScope', got {self.kind!r}")
        if not self.authorization.owner:
            errs.append("authorization.owner is required (accountable human/team)")
        if not self.authorization.authorized_by:
            errs.append("authorization.authorized_by is required")
        if not self.authorization.attestation:
            errs.append("authorization.attestation is required (explicit permission statement)")
        if not self.in_scope:
            errs.append("scope.in_scope must list at least one host")
        if not self.resolved_ip_allowlist:
            errs.append("scope.resolved_ip_allowlist is required (anti-SSRF; fail-closed)")
        else:
            for cidr in self.resolved_ip_allowlist:
                try:
                    ipaddress.ip_network(cidr, strict=False)
                except ValueError:
                    errs.append(f"resolved_ip_allowlist entry is not a valid CIDR/IP: {cidr!r}")
        if self.authorization.expires:
            if self.is_expired():
                errs.append(
                    f"authorization.expires is in the past ({self.authorization.expires}); scope auto-expired"
                )
        else:
            errs.append("authorization.expires is required (scope must auto-expire, fail-closed)")
        if self.action_policy.default_tier_ceiling not in (0, 1, 2):
            errs.append("action_policy.default_tier_ceiling must be 0, 1 or 2")
        return errs

    # ------------------------------------------------------------- queries
    def is_expired(self, now: datetime | None = None) -> bool:
        if not self.authorization.expires:
            return True  # fail-closed: no expiry == treated as expired
        now = now or datetime.now(timezone.utc)
        try:
            exp = datetime.fromisoformat(self.authorization.expires.replace("Z", "+00:00"))
        except ValueError:
            return True
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        return now > exp

    def host_scope(self, host: str) -> HostScope | None:
        host = host.lower()
        for hx in self.hosts_exclude:
            if path_glob_match(hx.replace(".", r"\.").replace(r"\.*", "*"), host) or _host_glob(hx, host):
                return None
        for hs in self.in_scope:
            if hs.host == host:
                return hs
        return None

    def path_excluded(self, path: str) -> bool:
        return any(path_glob_match(p, path) for p in self.paths_exclude)

    def account(self, account_id: str) -> TestAccount | None:
        for a in self.test_accounts:
            if a.id == account_id:
                return a
        return None

    def ip_allowed(self, ip: str) -> bool:
        """True only if ``ip`` is inside the allowlist and not in a hard-blocked range."""
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        for net in _HARD_BLOCK_NETS:
            if addr.version == net.version and addr in net:
                return False
        for cidr in self.resolved_ip_allowlist:
            try:
                if addr in ipaddress.ip_network(cidr, strict=False):
                    return True
            except ValueError:
                continue
        return False


def _host_glob(pattern: str, host: str) -> bool:
    # supports "*.prod.acme.com"
    regex = "^" + re.escape(pattern).replace(r"\*", "[^.]+") + "$"
    return re.match(regex, host) is not None


def _extract_front_matter(text: str) -> str:
    """Return the YAML block. Supports an optional leading ``---`` fence so human
    prose can follow the machine-readable contract."""
    stripped = text.lstrip()
    if stripped.startswith("---"):
        rest = stripped[3:]
        # find the closing fence on its own line
        for marker in ("\n---", "\r\n---"):
            end = rest.find(marker)
            if end != -1:
                return rest[:end]
        return rest
    return text
