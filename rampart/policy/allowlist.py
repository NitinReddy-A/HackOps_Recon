"""Stage 1 — target allowlist + resolved-IP check (anti-SSRF / DNS-rebinding).

The host must be explicitly in scope, the port must be permitted, and — critically —
the DNS name is re-resolved at execution time and the *resolved IP* is re-checked
against the operator's allowlist. This defeats DNS rebinding and coerced SSRF to
internal/cloud-metadata endpoints (blueprint section 23, threat #5).
"""

from __future__ import annotations

import socket
from dataclasses import dataclass

from ..schemas.scope import EngagementScope
from ..schemas.toolcall import ToolAction


@dataclass
class AllowlistResult:
    ok: bool
    resolved_ip: str = ""
    reason: str = ""


def default_resolver(host: str) -> list[str]:
    """Resolve a host to its IPs. Returns [] on failure (fail-closed upstream)."""
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError:
        return []
    ips = []
    for info in infos:
        ip = info[4][0]
        if ip not in ips:
            ips.append(ip)
    return ips


def check(scope: EngagementScope, action: ToolAction, resolver=default_resolver) -> AllowlistResult:
    host = action.target_host.lower()
    hs = scope.host_scope(host)
    if hs is None:
        return AllowlistResult(False, reason=f"host {host!r} is not in scope (or is excluded)")
    if action.port not in hs.ports:
        return AllowlistResult(
            False, reason=f"port {action.port} not permitted for {host!r} (allowed: {hs.ports})"
        )

    ips = resolver(host)
    if not ips:
        return AllowlistResult(False, reason=f"could not resolve {host!r} (fail-closed)")
    # EVERY resolved IP must be allowlisted — a single rebind-to-internal answer denies.
    for ip in ips:
        if not scope.ip_allowed(ip):
            return AllowlistResult(
                False,
                resolved_ip=ip,
                reason=f"resolved IP {ip} for {host!r} is not in resolved_ip_allowlist "
                "(or is a hard-blocked range)",
            )
    return AllowlistResult(True, resolved_ip=ips[0], reason="host+port+resolved-IP in scope")
