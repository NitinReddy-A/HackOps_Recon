"""The ``rampart.scope.yaml`` scope & authorization contract (blueprint section 30.1).

This is the R1 gate made concrete: an engagement will not start unless this parses,
an owner is named, the attestation is present, the contract has not expired, and the
target resolves inside ``in_scope`` with a ``resolved_ip_allowlist`` entry. It is data
the deterministic policy engine reads — never something the LLM can edit mid-run.

Parsing is strict and fail-closed: every field must have the expected type (a list of
strings must really be a list of strings — a bare string is never iterated character by
character), unknown ``limits``/``action_policy`` keys are rejected (a typo must not silently
fall back to a default), and paths are canonicalized before include/exclude matching so an
encoded or non-normalized spelling cannot walk around an exclusion.
"""

from __future__ import annotations

import datetime as _dt
import ipaddress
import posixpath
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from functools import lru_cache
from urllib.parse import unquote

from .. import yaml_lite

# IP ranges that must never be reachable regardless of the operator's allowlist
# (cloud metadata, link-local, multicast, unspecified). Anti-SSRF, blueprint section 23.
# IPv6 forms that embed an IPv4 address (IPv4-mapped, IPv4-compatible, NAT64, 6to4, Teredo)
# are unwrapped and the embedded address is checked too — see :func:`_ip_forms`.
_HARD_BLOCK_NETS = [
    ipaddress.ip_network("169.254.0.0/16"),  # link-local incl. 169.254.169.254 metadata
    ipaddress.ip_network("100.100.100.200/32"),  # Alibaba Cloud metadata
    ipaddress.ip_network("168.63.129.16/32"),  # Azure WireServer / host agent
    ipaddress.ip_network("192.0.0.192/32"),  # Oracle Cloud metadata (legacy)
    ipaddress.ip_network("224.0.0.0/4"),  # multicast
    ipaddress.ip_network("255.255.255.255/32"),  # limited broadcast
    ipaddress.ip_network("0.0.0.0/8"),  # "this network"
    ipaddress.ip_network("fe80::/10"),  # IPv6 link-local
    ipaddress.ip_network("fd00:ec2::254/128"),  # AWS IMDS over IPv6
    ipaddress.ip_network("ff00::/8"),  # IPv6 multicast
    ipaddress.ip_network("::/128"),  # unspecified
]
_NAT64_NETS = [ipaddress.ip_network("64:ff9b::/96"), ipaddress.ip_network("64:ff9b:1::/48")]
_V4_COMPAT_NET = ipaddress.ip_network("::/96")

# Strings a YAML author may have meant as "nothing" — never accepted as an owner/attestation.
_BLANKISH = {"", "none", "null", "~", "nil", "n/a"}

_METHOD_RE = re.compile(r"[A-Z][A-Z0-9_-]*\Z")


class ScopeError(ValueError):
    """Raised when a scope contract is missing, malformed, or fails validation."""


# --------------------------------------------------------------------------- #
# path canonicalization + globbing
# --------------------------------------------------------------------------- #
_CTRL_RE = re.compile(r"[\x00-\x1f\x7f]")
_PCT_RE = re.compile(r"%[0-9A-Fa-f]{2}")
_MAX_DECODE_ROUNDS = 3


class PathError(ValueError):
    """A request path that cannot be canonicalized safely (fail-closed: deny)."""


def _normalize_form(p: str) -> str:
    """Strip ``;params``, unify separators, collapse ``//``, resolve dot segments, drop the
    trailing slash. ``p`` must already be query-free."""
    p = p.replace("\\", "/")
    # matrix / path parameters (``/logout;jsessionid=1``) are dropped from every segment
    p = "/".join(seg.split(";", 1)[0] for seg in p.split("/"))
    p = re.sub(r"/{2,}", "/", p)
    if not p.startswith("/"):
        p = "/" + p
    p = posixpath.normpath(p)
    if p.startswith("//"):  # posixpath keeps a leading '//' (POSIX); we never want it
        p = "/" + p.lstrip("/")
    if p in (".", ""):
        p = "/"
    if len(p) > 1 and p.endswith("/"):
        p = p.rstrip("/") or "/"
    return p


def path_forms(path: str) -> list[str]:
    """Every normalized spelling a server might see for ``path``: the raw form and each
    successive percent-decoding (up to 3 rounds), all normalized. ``forms[-1]`` is the fully
    canonical path. Raises :class:`PathError` for anything we cannot reason about safely:
    non-string, empty, not origin-form (must start with ``/``), control characters/NUL (raw
    or after decoding), or still-encoded after 3 decode rounds."""
    if not isinstance(path, str) or not path:
        raise PathError("empty or non-string path")
    if _CTRL_RE.search(path):
        raise PathError(f"path contains control characters: {path!r}")
    if not path.startswith("/"):
        raise PathError(f"path must be origin-form (start with '/'): {path!r}")
    # query string / fragment are not part of the path
    cur = re.split(r"[?#]", path, maxsplit=1)[0]
    forms = [_normalize_form(cur)]
    for _ in range(_MAX_DECODE_ROUNDS):
        if not _PCT_RE.search(cur):
            break
        nxt = unquote(cur)  # invalid UTF-8 -> U+FFFD, rejected below
        if _CTRL_RE.search(nxt):
            raise PathError(f"path decodes to control characters/NUL: {path!r}")
        # a decoded '?' or '#' would split differently on a decoding server; treat as a separator
        nxt = re.split(r"[?#]", nxt, maxsplit=1)[0]
        cur = nxt
        forms.append(_normalize_form(cur))
    else:
        if _PCT_RE.search(cur):
            raise PathError(f"path is still percent-encoded after {_MAX_DECODE_ROUNDS} decodes: {path!r}")
    if "�" in forms[-1]:
        raise PathError(f"path decodes to invalid UTF-8: {path!r}")
    return forms


def canonical_path(path: str) -> str:
    """Fully decoded, normalized path used for scope decisions (see :func:`path_forms`)."""
    return path_forms(path)[-1]


@lru_cache(maxsize=1024)
def _glob_to_regex(pattern: str, exclusion: bool = False) -> re.Pattern:
    """Path glob: ``**`` matches across ``/``; ``*`` matches within a segment.

    The pattern is normalized like a path (trailing-slash insensitive). For EXCLUSIONS the
    match is also case-insensitive and a trailing ``/**`` matches the directory itself
    (``/api/admin/**`` excludes ``/api/admin``) — exclusions err on the side of matching more;
    inclusions keep the narrower, case-sensitive meaning.
    """
    pat = pattern
    if len(pat) > 1 and pat.endswith("/") and not pat.endswith("**/"):
        pat = pat.rstrip("/") or "/"
    tail = ""
    if pat.endswith("/**") and len(pat) > 3:
        pat, tail = pat[:-3], ("(?:/.*)?" if exclusion else "/.*")
    out, i = [], 0
    while i < len(pat):
        c = pat[i]
        if c == "*":
            if pat[i : i + 2] == "**":
                out.append(".*")
                i += 2
                continue
            out.append("[^/]*")
        else:
            out.append(re.escape(c))
        i += 1
    flags = re.IGNORECASE | re.DOTALL if exclusion else re.DOTALL
    return re.compile("^" + "".join(out) + tail + "$", flags)


def path_glob_match(pattern: str, path: str, exclusion: bool = False) -> bool:
    return _glob_to_regex(pattern, exclusion).match(path) is not None


# --------------------------------------------------------------------------- #
# strict field coercion
# --------------------------------------------------------------------------- #
def _mapping(v, name: str) -> dict:
    if v is None:
        return {}
    if not isinstance(v, dict):
        raise ScopeError(f"{name} must be a mapping, got {type(v).__name__}")
    return v


def _str_list(v, name: str, default: list | None = None) -> list[str]:
    if v is None:
        return list(default or [])
    if not isinstance(v, list):
        raise ScopeError(
            f"{name} must be a list of strings, got {type(v).__name__} {v!r} "
            '(write it as a YAML list, e.g. ["/a/**"])'
        )
    out = []
    for i, item in enumerate(v):
        if not isinstance(item, str):
            raise ScopeError(f"{name}[{i}] must be a string, got {type(item).__name__} {item!r}")
        item = item.strip()
        if not item:
            raise ScopeError(f"{name}[{i}] must not be empty")
        out.append(item)
    return out


def _text(v, name: str) -> str:
    """A scalar text field; ``None`` and "None"/"null"-like blanks become ``""`` (missing)."""
    if v is None:
        return ""
    if isinstance(v, bool) or not isinstance(v, (str, int, float)):
        raise ScopeError(f"{name} must be a string, got {type(v).__name__}")
    s = str(v).strip()
    return "" if s.lower() in _BLANKISH else s


def _timestamp_text(v, name: str) -> str:
    if v is None:
        return ""
    if isinstance(v, datetime):
        return v.isoformat()
    if isinstance(v, _dt.date):
        return v.isoformat()
    if not isinstance(v, str):
        raise ScopeError(f"{name} must be an ISO-8601 timestamp string, got {type(v).__name__} {v!r}")
    s = v.strip()
    return "" if s.lower() in _BLANKISH else s


def _int(v, name: str, lo: int | None = None, hi: int | None = None) -> int:
    if isinstance(v, bool):
        raise ScopeError(f"{name} must be an integer, got a boolean")
    if isinstance(v, str) and re.fullmatch(r"\s*[0-9]+\s*", v):
        v = int(v)
    if isinstance(v, float) and v.is_integer():
        v = int(v)
    if not isinstance(v, int):
        raise ScopeError(f"{name} must be an integer, got {type(v).__name__} {v!r}")
    if lo is not None and v < lo:
        raise ScopeError(f"{name} must be >= {lo}, got {v}")
    if hi is not None and v > hi:
        raise ScopeError(f"{name} must be <= {hi}, got {v}")
    return v


def _num(v, name: str) -> float:
    if isinstance(v, bool):
        raise ScopeError(f"{name} must be a number, got a boolean")
    if isinstance(v, str):
        try:
            v = float(v.strip())
        except ValueError:
            raise ScopeError(f"{name} must be a number, got {v!r}") from None
    if not isinstance(v, (int, float)) or v != v or v < 0 or v == float("inf"):
        raise ScopeError(f"{name} must be a finite non-negative number, got {v!r}")
    return float(v)


def _bool(v, name: str) -> bool:
    if not isinstance(v, bool):
        raise ScopeError(f"{name} must be true or false, got {type(v).__name__} {v!r}")
    return v


def _check_keys(d: dict, allowed, name: str) -> None:
    unknown = sorted(str(k) for k in d if k not in allowed)
    if unknown:
        raise ScopeError(f"unknown key(s) in {name}: {', '.join(unknown)} (allowed: {', '.join(allowed)})")


def _check_path_patterns(pats: list[str], name: str) -> None:
    for i, p in enumerate(pats):
        if not (p.startswith("/") or p.startswith("*")):
            raise ScopeError(f"{name}[{i}] must start with '/' (or '*'), got {p!r}")
        if _CTRL_RE.search(p):
            raise ScopeError(f"{name}[{i}] contains control characters")


@dataclass
class TestAccount:
    id: str
    role: str
    secret_ref: str = ""

    @classmethod
    def from_dict(cls, d: dict) -> TestAccount:
        d = _mapping(d, "test_accounts[]")
        acct_id = _text(d.get("id"), "test_accounts[].id")
        if not acct_id:
            raise ScopeError("test_accounts[].id is required")
        return cls(
            id=acct_id,
            role=_text(d.get("role"), "test_accounts[].role"),
            secret_ref=_text(d.get("secret_ref"), "test_accounts[].secret_ref"),
        )


@dataclass
class HostScope:
    host: str
    ports: list[int] = field(default_factory=lambda: [443])
    paths_include: list[str] = field(default_factory=lambda: ["/**"])
    methods: list[str] = field(default_factory=lambda: ["GET"])

    @classmethod
    def from_dict(cls, d: dict) -> HostScope:
        if not isinstance(d, dict):
            raise ScopeError(f"scope.in_scope entries must be mappings, got {type(d).__name__} {d!r}")
        host = _text(d.get("host"), "scope.in_scope[].host").lower().rstrip(".")
        if not host:
            raise ScopeError("scope.in_scope[].host is required")
        name = f"scope.in_scope[{host}]"
        raw_ports = d.get("ports")
        if raw_ports is None:
            ports = [443]
        elif not isinstance(raw_ports, list):
            raise ScopeError(
                f"{name}.ports must be a list of integers, got {type(raw_ports).__name__} {raw_ports!r}"
            )
        else:
            ports = [_int(p, f"{name}.ports[{i}]", 1, 65535) for i, p in enumerate(raw_ports)]
        includes = _str_list(d.get("paths_include"), f"{name}.paths_include", ["/**"])
        _check_path_patterns(includes, f"{name}.paths_include")
        methods = [m.upper() for m in _str_list(d.get("methods"), f"{name}.methods", ["GET"])]
        for m in methods:
            if not _METHOD_RE.match(m):
                raise ScopeError(f"{name}.methods contains an invalid HTTP method {m!r}")
        return cls(host=host, ports=ports, paths_include=includes, methods=methods)


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

    @classmethod
    def from_dict(cls, d) -> Limits:
        d = _mapping(d, "limits")
        _check_keys(d, cls.__annotations__, "limits")
        kw: dict = {}
        for k in (
            "max_requests_per_host_per_min",
            "max_total_requests",
            "max_concurrent_workers",
            "max_tokens",
        ):
            if k in d:
                kw[k] = _int(d[k], f"limits.{k}", lo=0)
        if "max_concurrent_workers" in kw and kw["max_concurrent_workers"] < 1:
            raise ScopeError("limits.max_concurrent_workers must be >= 1")
        if "budget_usd" in d:
            kw["budget_usd"] = _num(d["budget_usd"], "limits.budget_usd")
        return cls(**kw)


@dataclass
class ActionPolicy:
    default_tier_ceiling: int = 1
    tier2_requires_approval: bool = True
    tier3: str = "deny"

    @classmethod
    def from_dict(cls, d) -> ActionPolicy:
        d = _mapping(d, "action_policy")
        _check_keys(d, cls.__annotations__, "action_policy")
        kw: dict = {}
        if "default_tier_ceiling" in d:
            kw["default_tier_ceiling"] = _int(d["default_tier_ceiling"], "action_policy.default_tier_ceiling")
        if "tier2_requires_approval" in d:
            kw["tier2_requires_approval"] = _bool(
                d["tier2_requires_approval"], "action_policy.tier2_requires_approval"
            )
        if "tier3" in d:
            kw["tier3"] = _text(d["tier3"], "action_policy.tier3").lower()
        return cls(**kw)


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
        d = _mapping(d, "scope contract")
        scope = _mapping(d.get("scope"), "scope")
        raw_in = scope.get("in_scope")
        if raw_in is not None and not isinstance(raw_in, list):
            raise ScopeError(f"scope.in_scope must be a list of host entries, got {type(raw_in).__name__}")
        in_scope = [HostScope.from_dict(h) for h in (raw_in or [])]
        out = _mapping(scope.get("out_of_scope"), "scope.out_of_scope")
        auth_raw = _mapping(d.get("authorization"), "authorization")
        auth = Authorization(
            owner=_text(auth_raw.get("owner"), "authorization.owner"),
            authorized_by=_text(auth_raw.get("authorized_by"), "authorization.authorized_by"),
            ticket=_text(auth_raw.get("ticket"), "authorization.ticket"),
            attestation=_text(auth_raw.get("attestation"), "authorization.attestation"),
            expires=_timestamp_text(auth_raw.get("expires"), "authorization.expires"),
        )
        paths_exclude = _str_list(out.get("paths_exclude"), "scope.out_of_scope.paths_exclude")
        _check_path_patterns(paths_exclude, "scope.out_of_scope.paths_exclude")
        hosts_exclude = [
            h.lower().rstrip(".")
            for h in _str_list(out.get("hosts_exclude"), "scope.out_of_scope.hosts_exclude")
        ]
        raw_accts = d.get("test_accounts")
        if raw_accts is not None and not isinstance(raw_accts, list):
            raise ScopeError(f"test_accounts must be a list, got {type(raw_accts).__name__}")
        return cls(
            api_version=_text(d.get("apiVersion"), "apiVersion"),
            kind=_text(d.get("kind"), "kind"),
            authorization=auth,
            in_scope=in_scope,
            paths_exclude=paths_exclude,
            hosts_exclude=hosts_exclude,
            resolved_ip_allowlist=_str_list(
                scope.get("resolved_ip_allowlist"), "scope.resolved_ip_allowlist"
            ),
            limits=Limits.from_dict(d.get("limits")),
            action_policy=ActionPolicy.from_dict(d.get("action_policy")),
            test_accounts=[TestAccount.from_dict(a) for a in (raw_accts or [])],
            notify=_mapping(d.get("notify"), "notify"),
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
        for hs in self.in_scope:
            if not hs.ports:
                errs.append(f"scope.in_scope[{hs.host}].ports must list at least one port")
            if not hs.methods:
                errs.append(f"scope.in_scope[{hs.host}].methods must list at least one method")
        if not self.resolved_ip_allowlist:
            errs.append("scope.resolved_ip_allowlist is required (anti-SSRF; fail-closed)")
        else:
            for cidr in self.resolved_ip_allowlist:
                try:
                    ipaddress.ip_network(cidr, strict=False)
                except ValueError:
                    errs.append(f"resolved_ip_allowlist entry is not a valid CIDR/IP: {cidr!r}")
        if self.authorization.expires:
            if self.expires_at() is None:
                errs.append(
                    f"authorization.expires is unparseable ({self.authorization.expires!r}); "
                    "use an ISO-8601 timestamp such as 2026-12-31T23:59:59Z"
                )
            elif self.is_expired():
                errs.append(
                    f"authorization.expires is in the past ({self.authorization.expires}); scope auto-expired"
                )
        else:
            errs.append("authorization.expires is required (scope must auto-expire, fail-closed)")
        if self.action_policy.default_tier_ceiling not in (0, 1, 2):
            errs.append("action_policy.default_tier_ceiling must be 0, 1 or 2")
        if self.action_policy.tier3 != "deny":
            errs.append("action_policy.tier3 must be 'deny' (Tier 3 is never executed)")
        lim = self.limits
        if lim.max_total_requests < 1 or lim.max_requests_per_host_per_min < 1:
            errs.append("limits.max_total_requests and limits.max_requests_per_host_per_min must be >= 1")
        return errs

    # ------------------------------------------------------------- queries
    def expires_at(self) -> datetime | None:
        """The parsed expiry (UTC-aware), or None when missing/unparseable."""
        raw = self.authorization.expires
        if not raw:
            return None
        try:
            exp = datetime.fromisoformat(raw.replace("Z", "+00:00").replace("z", "+00:00"))
        except ValueError:
            return None
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        return exp

    def is_expired(self, now: datetime | None = None) -> bool:
        exp = self.expires_at()
        if exp is None:
            return True  # fail-closed: missing/unparseable expiry == treated as expired
        now = now or datetime.now(timezone.utc)
        return now > exp

    def host_excluded(self, host: str) -> bool:
        host = host.lower().rstrip(".")
        return any(_host_glob(hx, host) for hx in self.hosts_exclude)

    def host_scope(self, host: str) -> HostScope | None:
        host = (host or "").lower()
        if host.endswith("."):
            return None  # fail-closed: absolute-FQDN spellings are not matched to scope entries
        if self.host_excluded(host):
            return None
        for hs in self.in_scope:
            if hs.host == host:
                return hs
        return None

    def path_excluded(self, path: str) -> bool:
        """True if ANY normalized/decoded spelling of ``path`` matches an exclusion
        (case-insensitive, trailing-slash-insensitive). Malformed paths count as excluded."""
        try:
            forms = path_forms(path)
        except PathError:
            return True
        return any(path_glob_match(p, f, exclusion=True) for p in self.paths_exclude for f in forms)

    def path_included(self, hs: HostScope, path: str) -> str | None:
        """Return the matching include pattern if EVERY spelling of ``path`` is inside one of
        ``hs.paths_include`` (case-sensitive), else None. Malformed paths are never included."""
        try:
            forms = path_forms(path)
        except PathError:
            return None
        for pat in hs.paths_include:
            if all(path_glob_match(pat, f) for f in forms):
                return pat
        return None

    def account(self, account_id: str) -> TestAccount | None:
        for a in self.test_accounts:
            if a.id == account_id:
                return a
        return None

    def ip_allowed(self, ip: str) -> bool:
        """True only if ``ip`` is inside the allowlist and neither it nor any IPv4 address
        embedded in it (mapped/compat/NAT64/6to4/Teredo) is in a hard-blocked range."""
        try:
            addr = ipaddress.ip_address(str(ip).split("%", 1)[0])
        except ValueError:
            return False
        for form in _ip_forms(addr):
            for net in _HARD_BLOCK_NETS:
                if form.version == net.version and form in net:
                    return False
        for cidr in self.resolved_ip_allowlist:
            try:
                net = ipaddress.ip_network(cidr, strict=False)
            except ValueError:
                continue
            if addr.version == net.version and addr in net:
                return True
        return False


def _ip_forms(addr) -> list:
    """``addr`` plus every IPv4 address an IPv6 address may embed/translate to."""
    forms = [addr]
    if addr.version != 6:
        return forms
    if addr.ipv4_mapped is not None:
        forms.append(addr.ipv4_mapped)
    if addr.sixtofour is not None:
        forms.append(addr.sixtofour)
    if addr.teredo is not None:
        forms.extend(addr.teredo)
    packed = addr.packed
    if any(addr in n for n in _NAT64_NETS) or (addr in _V4_COMPAT_NET and int(addr) > 1):
        forms.append(ipaddress.IPv4Address(packed[-4:]))
    return forms


@lru_cache(maxsize=256)
def _host_regex(pattern: str) -> re.Pattern:
    pattern = pattern.lower().rstrip(".")
    prefix = ""
    for lead in ("**.", "*."):
        if pattern.startswith(lead):
            pattern = pattern[len(lead) :]
            prefix = r"(?:[^.]+\.)+"  # any subdomain depth (one or more labels)
            break
    body = re.escape(pattern).replace(r"\*", "[^.]*")
    return re.compile("^" + prefix + body + "$")


def _host_glob(pattern: str, host: str) -> bool:
    """``*.acme.com`` / ``**.acme.com`` exclude every subdomain at any depth (not the apex);
    a ``*`` elsewhere matches within one label; otherwise exact (case-insensitive)."""
    return _host_regex(pattern).match(host) is not None


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
