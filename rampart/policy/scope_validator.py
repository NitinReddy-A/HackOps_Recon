"""Stage 2 — scope validator.

Validates the concrete request (host, path prefix, method) against the engagement rules:
in-scope path globs, explicit exclusions (e.g. ``/admin/billing/**``, ``/logout``), and
permitted methods. Excluded paths win over included ones (deny-by-default).
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from ..schemas.scope import EngagementScope, PathError, canonical_path
from ..schemas.toolcall import ToolAction


@dataclass
class ScopeResult:
    ok: bool
    reason: str = ""
    matched_rule: str = ""


_RESERVED_TLDS = (".example", ".invalid", ".test")
_HOSTNAME_RE = re.compile(r"[a-z0-9.-]+\Z")


def _host_header_ok(value: str, target_host: str, port: int) -> bool:
    v = value.strip().lower()
    if not v or _CTRL.search(v):
        return False
    name, _, p = v.rpartition(":") if v.count(":") == 1 else (v, "", "")
    if p and (not p.isdigit() or int(p) != port):
        return False
    if name == target_host:
        return True
    # Rampart's own deterministic canaries only: "rampart-*" under a reserved TLD
    return bool(_HOSTNAME_RE.match(name)) and name.startswith("rampart-") and name.endswith(_RESERVED_TLDS)


_CTRL = re.compile(r"[\x00-\x20\x7f]")


def check(scope: EngagementScope, action: ToolAction) -> ScopeResult:
    host = action.target_host.lower()
    hs = scope.host_scope(host)
    if hs is None:
        return ScopeResult(False, reason=f"host {host!r} not in scope")

    if str(action.scheme or "").lower() not in ("http", "https"):
        return ScopeResult(False, reason=f"scheme {action.scheme!r} not permitted (http/https only)")

    # Decisions are made on the canonical path (percent-decoded, ;params/query stripped, '//' and
    # dot-segments collapsed). An exclusion matching ANY decoding stage wins; malformed paths
    # (control chars, not origin-form, over-encoded) are denied outright.
    try:
        canonical = canonical_path(action.path)
    except PathError as exc:
        return ScopeResult(False, reason=f"malformed request path (fail-closed): {exc}")

    if scope.path_excluded(action.path):
        return ScopeResult(
            False, reason=f"path {action.path!r} (canonical {canonical!r}) is explicitly out of scope"
        )

    method = action.method or ""
    if method != method.strip() or method.upper() not in hs.methods:
        return ScopeResult(
            False, reason=f"method {method!r} not permitted for {host!r} (allowed: {hs.methods})"
        )

    # A caller-supplied Host header could route a request for the vetted in-scope IP to a
    # different (out-of-scope) virtual host on the same server. Only the scope-checked target
    # itself, or a Rampart canary ("rampart-*") under an RFC 2606/6761 reserved TLD that cannot
    # be a real vhost (the host-header-injection oracle's probe), is permitted.
    for k, v in (action.headers or {}).items():
        if str(k).strip().lower() == "host" and not _host_header_ok(str(v), host, action.port):
            return ScopeResult(
                False, reason=f"caller-supplied Host header {str(v)[:80]!r} is not permitted (fail-closed)"
            )

    pat = scope.path_included(hs, action.path)
    if pat is not None:
        i = hs.paths_include.index(pat)
        return ScopeResult(
            True, reason="path in scope", matched_rule=f"scope.in_scope[{host}].paths_include[{i}]"
        )

    return ScopeResult(False, reason=f"path {action.path!r} does not match any in-scope pattern")
