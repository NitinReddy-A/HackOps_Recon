"""gRPC / gRPC-Web security scan — server-reflection exposure (graceful if grpcio absent).

Analogous to the GraphQL *introspection-enabled* check: a gRPC server with **server reflection**
turned on hands any client its complete service/method/message schema, i.e. a full API map,
without needing the ``.proto`` files. That is an information-disclosure exposure (CWE-200) and,
like introspection, it is a deterministic observation — reflection either lists services or it
does not — so the resulting finding can honestly carry ``confidence=confirmed`` /
``verification.validated=True`` without any LLM guesswork.

Graceful degradation
---------------------
``grpcio`` / ``grpcio-reflection`` are an **optional** extra. This module imports cleanly with
them absent — every grpc import is done lazily *inside* :func:`available` and
:func:`_list_services`. :func:`scan_grpc` never raises: if the packages are missing (or the
server is unreachable / reflection is disabled) it simply returns ``[]`` and the caller logs the
install hint. The zero-dependency core is unaffected.

Trust boundary
--------------
:func:`_list_services` opens its **own** gRPC channel to ``host:port``; that traffic does NOT
pass through Rampart's HTTP policy choke-point (the ``ProbeRunner`` / scope pipeline). The caller
MUST therefore only ever point :func:`scan_grpc` at a host:port that is already authorized and
in-scope for the engagement; this module trusts the caller on scope and enforces none itself.

Testing seam
------------
Reflection is factored into :func:`_list_services` (the network half) and
:func:`_reflection_finding` (a pure Finding builder). Tests monkeypatch ``_list_services`` to
inject a fake service list (or an exception) so the whole module can be exercised with neither a
live gRPC server nor ``grpcio`` installed.
"""
from __future__ import annotations

from ..schemas.finding import CVSS, Evidence, Finding, Remediation, Reproduction, State, Verification
from ..util import now_iso

install_hint = "pip install rampart-appsec[grpc]"

# gRPC / gRPC-Web content-types (prefix match) and the trailer/header that marks a gRPC response.
_GRPC_CONTENT_HINTS = ("application/grpc", "grpc-web")

_CVSS = CVSS(
    version="4.0", base_score=5.3, severity="medium",
    vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
    v31_fallback={"base_score": 5.3, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"},
)


# --------------------------------------------------------------------------- detection
def is_grpc_response(headers: dict) -> bool:
    """True if ``headers`` look like a gRPC / gRPC-Web response (case-insensitive).

    Fires on a ``grpc-status`` header/trailer, or a ``content-type`` of ``application/grpc``
    (incl. ``+proto``/``+json`` suffixes), ``application/grpc-web``, ``application/grpc-web-text``
    or bare ``grpc-web-text``.
    """
    if not headers:
        return False
    ci = {str(k).lower(): str(v).lower() for k, v in headers.items()}
    if "grpc-status" in ci:
        return True
    ctype = ci.get("content-type", "")
    return any(hint in ctype for hint in _GRPC_CONTENT_HINTS)


# --------------------------------------------------------------------------- availability
def available() -> bool:
    """True only if ``grpcio`` and ``grpcio-reflection`` import (lazy; never raises).

    The module itself imports fine without them — this is the only place the packages are
    probed, so the caller can log :data:`install_hint` when it returns False.
    """
    try:
        import grpc  # noqa: F401  (lazy — package is optional)
        from grpc_reflection.v1alpha import reflection_pb2  # noqa: F401
        return True
    except Exception:  # noqa: BLE001 — not installed / broken import
        return False


# --------------------------------------------------------------------------- reflection seam
def _list_services(host, port, scheme="grpc", timeout: float = 8.0) -> list:
    """Attempt gRPC **server reflection** against ``host:port``; return the service names.

    Raises ``ImportError`` when ``grpcio``/``grpcio-reflection`` are absent, and may raise on an
    unreachable server or a reflection RPC error. :func:`scan_grpc` wraps this in try/except;
    tests monkeypatch it to return a fake list (or raise) without a live server or grpcio.
    """
    import grpc  # lazy — module imports fine without grpcio installed
    from grpc_reflection.v1alpha import reflection_pb2, reflection_pb2_grpc

    target = f"{host}:{port}"
    secure = str(scheme or "").lower() in ("https", "grpcs", "tls", "ssl")
    channel = (grpc.secure_channel(target, grpc.ssl_channel_credentials())
               if secure else grpc.insecure_channel(target))
    try:
        stub = reflection_pb2_grpc.ServerReflectionStub(channel)
        request = reflection_pb2.ServerReflectionRequest(list_services="*")
        services: list = []
        for resp in stub.ServerReflectionInfo(iter([request]), timeout=timeout):
            lsr = getattr(resp, "list_services_response", None)
            if lsr is None:
                continue
            for svc in getattr(lsr, "service", []):
                name = getattr(svc, "name", "") or ""
                if name and name not in services:
                    services.append(name)
        return services
    finally:
        try:
            channel.close()
        except Exception:  # noqa: BLE001
            pass


# --------------------------------------------------------------------------- finding builder
def _reflection_finding(services, application, target_url, engagement_id: str = "") -> Finding:
    """Build the confirmed 'gRPC server reflection enabled' Finding from a service list (pure)."""
    services = [s for s in (services or []) if s]
    svc_list = ", ".join(services) if services else "(none reported)"
    f = Finding(
        engagement_id=engagement_id,
        title="gRPC server reflection enabled",
        vuln_class="information-disclosure",
        severity="medium",
        confidence="confirmed",
        state=State.VALIDATED,
        cwe=["CWE-200"],
        owasp={"web_2025": ["A05:2021-Security Misconfiguration"],
               "api_2023": ["API9:2023-Improper Inventory Management"]},
        cvss=_CVSS,
        asset={"type": "grpc", "application": application, "environment": "authorized",
               "target": target_url},
        endpoint={"method": "POST", "url": target_url, "auth_required": False,
                  "service": "grpc.reflection.v1alpha.ServerReflection"},
        description=(
            f"The gRPC server has server reflection enabled and enumerated its services: {svc_list}. "
            "Reflection exposes the full service/method/message schema to any client, giving an "
            "attacker a complete API map without the .proto files (analogous to GraphQL introspection)."),
        impact=("Leaks the full gRPC API surface (services, methods, message types) to clients, "
                "easing reconnaissance and targeted attacks against individual RPCs."),
        root_cause=("The gRPC reflection service (grpc.reflection.v1alpha.ServerReflection) is "
                    "registered on an exposed/production server."),
        reproduction=Reproduction(
            prerequisites=["A reachable gRPC endpoint"],
            steps=["Open a gRPC channel to host:port",
                   "Call grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo with list_services='*'",
                   "Observe the server enumerate its registered services"],
            deterministic=True),
        remediation=Remediation(
            summary="Disable gRPC server reflection in production.",
            type="config",
            guidance=("Do not register the reflection service on internet-facing/production servers, or "
                      "gate it behind authentication and an allow-list; expose reflection only in trusted "
                      "development environments (CWE-200)."),
            effort="low"),
        references=["https://github.com/grpc/grpc/blob/master/doc/server-reflection.md",
                    "https://cwe.mitre.org/data/definitions/200.html"],
        compliance_control_refs=["SOC2:CC6.1", "ISO27001:A.8.9"],
        dedupe_key=f"{application}:grpc-reflection:{target_url}",
        tags=["grpc", "reflection", "information-disclosure"],
        verification=Verification(
            method="grpc-reflection", validated=True, validated_at=now_iso(),
            validator="grpc-reflection", independent_reproduction=True, reproductions=1,
            false_positive_checks=[
                f"server reflection returned {len(services)} service(s): {svc_list}",
                "deterministic: reflection either returns services or it does not (no inference)"],
            confidence_score=0.98),
    )
    f.evidence.append(Evidence(type="note", summary=f"gRPC reflection listed services: {svc_list}"))
    f.assert_consistent()  # 'confirmed' is only legal with verification.validated=True
    return f


# --------------------------------------------------------------------------- entry point
def scan_grpc(host, port, scheme, application, target_url, timeout: float = 8.0) -> list:
    """Scan a gRPC endpoint for a server-reflection exposure.

    Attempts gRPC server reflection via :func:`_list_services`; if it lists services, returns a
    single confirmed CWE-200 finding. Returns ``[]`` when grpcio is absent, the server is
    unreachable, reflection is disabled, or anything goes wrong — :func:`_list_services` carries
    the lazy grpc import, so when the packages are missing it raises ``ImportError`` and this
    function degrades gracefully. Never raises.
    """
    try:
        services = _list_services(host, port, scheme, timeout=timeout)
    except Exception:  # noqa: BLE001 — grpcio absent / unreachable / RPC error: degrade to no-op
        return []
    if not services:
        return []
    url = target_url or f"{scheme or 'grpc'}://{host}:{port}"
    return [_reflection_finding(services, application, url, engagement_id="")]
