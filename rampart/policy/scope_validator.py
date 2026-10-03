"""Stage 2 — scope validator.

Validates the concrete request (host, path prefix, method) against the engagement rules:
in-scope path globs, explicit exclusions (e.g. ``/admin/billing/**``, ``/logout``), and
permitted methods. Excluded paths win over included ones (deny-by-default).
"""
from __future__ import annotations

from dataclasses import dataclass

from ..schemas.scope import EngagementScope, path_glob_match
from ..schemas.toolcall import ToolAction


@dataclass
class ScopeResult:
    ok: bool
    reason: str = ""
    matched_rule: str = ""


def check(scope: EngagementScope, action: ToolAction) -> ScopeResult:
    host = action.target_host.lower()
    hs = scope.host_scope(host)
    if hs is None:
        return ScopeResult(False, reason=f"host {host!r} not in scope")

    if scope.path_excluded(action.path):
        return ScopeResult(False, reason=f"path {action.path!r} is explicitly out of scope")

    if action.method.upper() not in hs.methods:
        return ScopeResult(False, reason=f"method {action.method} not permitted for {host!r} (allowed: {hs.methods})")

    for i, pat in enumerate(hs.paths_include):
        if path_glob_match(pat, action.path):
            return ScopeResult(True, reason="path in scope", matched_rule=f"scope.in_scope[{host}].paths_include[{i}]")

    return ScopeResult(False, reason=f"path {action.path!r} does not match any in-scope pattern")
