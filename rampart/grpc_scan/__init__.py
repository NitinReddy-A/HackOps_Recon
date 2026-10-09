"""Optional gRPC / gRPC-Web security-scan module — reflection exposure (graceful if absent).

OPTIONAL extra (``rampart-appsec[grpc]``). The zero-dependency core never imports ``grpcio`` at
load time; it is imported lazily inside :func:`available` / :func:`_list_services`, so this
package always imports cleanly. With ``grpcio``/``grpcio-reflection`` absent (or the server
unreachable / reflection disabled), :func:`scan_grpc` degrades to a no-op and returns ``[]``.

Trust boundary: a gRPC channel makes its OWN network requests and is NOT policed by Rampart's
scope choke-point, so the caller must only ever point :func:`scan_grpc` at an already in-scope,
authorized host:port.
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
