"""Optional gRPC / gRPC-Web security-scan module — reflection exposure (graceful if absent).

OPTIONAL extra (``rampart-appsec[grpc]``). The zero-dependency core never imports ``grpcio`` at
load time; it is imported lazily inside :func:`available` / :func:`_list_services`, so this
package always imports cleanly. With ``grpcio``/``grpcio-reflection`` absent (or the server
unreachable / reflection disabled), :func:`scan_grpc` degrades to a no-op and returns ``[]``.

Trust boundary: a gRPC channel makes its OWN network requests outside Rampart's HTTP policy
pipeline, so :func:`scan_grpc` enforces the ``scope`` it is given (host, scoped port, resolved-IP
allowlist; fail-closed) and audits/budgets every RPC. A missing dependency or an out-of-scope
target is reported via the result's ``skip_reason``.
"""

from __future__ import annotations

from .scan import (
    available,
    install_hint,
    is_grpc_response,
    scan_grpc,
    scan_grpc_methods,
)

__all__ = [
    "available",
    "install_hint",
    "is_grpc_response",
    "scan_grpc",
    "scan_grpc_methods",
]
