"""Native, dependency-free LIVE infrastructure / exposed-services scanner.

The runtime complement to the STATIC IaC scanner in :mod:`rampart.iac`: it makes strictly
NON-DESTRUCTIVE TCP/TLS observations (a TCP connect + a tiny passive banner read; a read-only
TLS handshake) against an authorized, in-scope host to prove that a sensitive backend service is
reachable, or that a TLS endpoint has an expired/self-signed certificate or an obsolete protocol.

Exposed-service findings are CONFIRMED observation-oracle findings (two independent connects plus
a closed-control-port negative control); TLS findings are ``firm`` evidence. :func:`scan_infra`
is graceful — unreachable/refused/timeout/out-of-scope all yield ``[]`` and it never raises.

Trust boundary: these sockets bypass Rampart's HTTP policy choke-point, so :func:`scan_infra`
enforces scope itself (fail-closed): it requires a ``scope`` + ``resolver``, and only ever connects
to ports listed in the host's scoped ``ports``. :mod:`.sidechannel` holds the audit/budget guard
shared with the gRPC and browser engines.
"""

from __future__ import annotations

from .scanner import SENSITIVE_SERVICES, is_sensitive_port, scan_infra
from .sidechannel import ScanOutcome, SideChannelGuard, skip_reason_of

__all__ = [
    "SENSITIVE_SERVICES",
    "is_sensitive_port",
    "scan_infra",
    "ScanOutcome",
    "SideChannelGuard",
    "skip_reason_of",
]
