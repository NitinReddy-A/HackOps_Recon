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
server is unreachable / reflection is disabled) it returns an empty result; a missing package is
reported as ``result.skip_reason == "grpc: skipped — pip install rampart-appsec[grpc]"`` so the
caller can print it. The zero-dependency core is unaffected.

Trust boundary
--------------
:func:`_list_services` opens its **own** gRPC channel to ``host:port``; that traffic does NOT
pass through Rampart's HTTP policy choke-point (the ``ProbeRunner`` / scope pipeline). When given a
``scope`` (+ ``resolver``), :func:`scan_grpc` enforces it itself and fails closed — the host must be
in scope, the port must be one of its scoped ``ports`` and every resolved IP must be allowlisted —
and every RPC is audited/budgeted through :class:`~rampart.infra.sidechannel.SideChannelGuard`.
With ``scope=None`` (library/test use) the caller remains responsible for scope.

Testing seam
------------
Reflection is factored into :func:`_list_services` (the network half) and
:func:`_reflection_finding` (a pure Finding builder). Tests monkeypatch ``_list_services`` to
inject a fake service list (or an exception) so the whole module can be exercised with neither a
live gRPC server nor ``grpcio`` installed.
"""

from __future__ import annotations

import inspect
import re

from ..infra.sidechannel import ScanOutcome, guard_from
from ..schemas.finding import CVSS, Evidence, Finding, Remediation, Reproduction, State, Verification
from ..util import now_iso

install_hint = "pip install rampart-appsec[grpc]"

# gRPC / gRPC-Web content-types (prefix match) and the trailer/header that marks a gRPC response.
_GRPC_CONTENT_HINTS = ("application/grpc", "grpc-web")

_CVSS = CVSS(
    version="4.0",
    base_score=5.3,
    severity="medium",
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
    channel = (
        grpc.secure_channel(target, grpc.ssl_channel_credentials())
        if secure
        else grpc.insecure_channel(target)
    )
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
def _reflection_finding(services, application, target_url, engagement_id: str = "", methods=None) -> Finding:
    """Build the confirmed 'gRPC server reflection enabled' Finding from a service list (pure).

    ``methods`` is OPTIONAL: when ``None``/empty the finding is byte-for-byte the original
    service-only exposure (existing behaviour / tests unchanged). When a method list (as produced
    by :func:`_list_methods`) is supplied, one extra sentence listing the method count + a few
    ``/pkg.Svc/Method`` names is appended to the description and an evidence note is added — nothing
    else changes.
    """
    services = [s for s in (services or []) if s]
    svc_list = ", ".join(services) if services else "(none reported)"
    methods = methods or []
    full_names = [m.get("full_method", "") for m in methods if m.get("full_method")]
    _sample = ", ".join(full_names[:5])
    _more = "" if len(full_names) <= 5 else f" (+{len(full_names) - 5} more)"
    description = (
        f"The gRPC server has server reflection enabled and enumerated its services: {svc_list}. "
        "Reflection exposes the full service/method/message schema to any client, giving an "
        "attacker a complete API map without the .proto files (analogous to GraphQL introspection)."
    )
    if full_names:
        description += (
            f" Reflection further enumerated {len(full_names)} RPC method(s) from the service "
            f"descriptors, e.g.: {_sample}{_more}."
        )
    f = Finding(
        engagement_id=engagement_id,
        title="gRPC server reflection enabled",
        vuln_class="information-disclosure",
        severity="medium",
        confidence="confirmed",
        state=State.VALIDATED,
        cwe=["CWE-200"],
        owasp={
            "web_2025": ["A05:2021-Security Misconfiguration"],
            "api_2023": ["API9:2023-Improper Inventory Management"],
        },
        cvss=_CVSS,
        asset={"type": "grpc", "application": application, "environment": "authorized", "target": target_url},
        endpoint={
            "method": "POST",
            "url": target_url,
            "auth_required": False,
            "service": "grpc.reflection.v1alpha.ServerReflection",
        },
        description=description,
        impact=(
            "Leaks the full gRPC API surface (services, methods, message types) to clients, "
            "easing reconnaissance and targeted attacks against individual RPCs."
        ),
        root_cause=(
            "The gRPC reflection service (grpc.reflection.v1alpha.ServerReflection) is "
            "registered on an exposed/production server."
        ),
        reproduction=Reproduction(
            prerequisites=["A reachable gRPC endpoint"],
            steps=[
                "Open a gRPC channel to host:port",
                "Call grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo with list_services='*'",
                "Observe the server enumerate its registered services",
            ],
            deterministic=True,
        ),
        remediation=Remediation(
            summary="Disable gRPC server reflection in production.",
            type="config",
            guidance=(
                "Do not register the reflection service on internet-facing/production servers, or "
                "gate it behind authentication and an allow-list; expose reflection only in trusted "
                "development environments (CWE-200)."
            ),
            effort="low",
        ),
        references=[
            "https://github.com/grpc/grpc/blob/master/doc/server-reflection.md",
            "https://cwe.mitre.org/data/definitions/200.html",
        ],
        compliance_control_refs=["SOC2:CC6.1", "ISO27001:A.8.9"],
        dedupe_key=f"{application}:grpc-reflection:{target_url}",
        tags=["grpc", "reflection", "information-disclosure"],
        verification=Verification(
            method="grpc-reflection",
            validated=True,
            validated_at=now_iso(),
            validator="grpc-reflection",
            independent_reproduction=True,
            reproductions=1,
            false_positive_checks=[
                f"server reflection returned {len(services)} service(s): {svc_list}",
                "deterministic: reflection either returns services or it does not (no inference)",
            ],
            confidence_score=0.98,
        ),
    )
    f.evidence.append(Evidence(type="note", summary=f"gRPC reflection listed services: {svc_list}"))
    if full_names:
        f.evidence.append(
            Evidence(
                type="note", summary=f"gRPC reflection listed {len(full_names)} method(s): {_sample}{_more}"
            )
        )
    f.assert_consistent()  # 'confirmed' is only legal with verification.validated=True
    return f


# --------------------------------------------------------------------------- method-listing seam
def _list_methods(host, port, scheme="grpc", timeout: float = 8.0, guard=None) -> list:
    """Enumerate each service's **methods** via server reflection (network seam, lazy grpc).

    Lists the services (``list_services='*'``) then, for each, fetches the ``FileDescriptorProto``
    (``file_containing_symbol=<service>``) and walks the service/method descriptors. Returns a list
    of dicts ``{"service", "method", "full_method": "/pkg.Svc/Method", "input_type", "output_type"}``.
    Raises ``ImportError`` when ``grpcio``/``grpcio-reflection`` are absent (like
    :func:`_list_services`); descriptor parsing is best-effort and any per-symbol error is skipped.
    Callers wrap this in try/except and degrade to ``[]``; tests monkeypatch it so neither a live
    server nor grpcio is ever needed. ``guard`` (a :class:`SideChannelGuard`) admits + audits each
    per-service ``file_containing_symbol`` RPC; a denied RPC is skipped.
    """
    import grpc  # lazy — module imports fine without grpcio installed
    from google.protobuf import descriptor_pb2
    from grpc_reflection.v1alpha import reflection_pb2, reflection_pb2_grpc

    target = f"{host}:{port}"
    secure = str(scheme or "").lower() in ("https", "grpcs", "tls", "ssl")
    channel = (
        grpc.secure_channel(target, grpc.ssl_channel_credentials())
        if secure
        else grpc.insecure_channel(target)
    )
    methods: list = []
    try:
        stub = reflection_pb2_grpc.ServerReflectionStub(channel)

        # 1) enumerate the registered service names.
        services: list = []
        req = reflection_pb2.ServerReflectionRequest(list_services="*")
        for resp in stub.ServerReflectionInfo(iter([req]), timeout=timeout):
            lsr = getattr(resp, "list_services_response", None)
            if lsr is None:
                continue
            for svc in getattr(lsr, "service", []):
                name = getattr(svc, "name", "") or ""
                if name and name not in services:
                    services.append(name)

        # 2) fetch the file descriptor that CONTAINS each service symbol, then walk its methods.
        seen: set = set()
        for svc_name in services:
            if guard is not None:
                ok, _why = guard.admit(
                    str(host),
                    {
                        "kind": "grpc-rpc",
                        "method": "POST",
                        "port": port,
                        "path": "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo",
                        "purpose": f"file_containing_symbol={svc_name}",
                    },
                )
                if not ok:
                    continue
            req = reflection_pb2.ServerReflectionRequest(file_containing_symbol=svc_name)
            try:
                responses = stub.ServerReflectionInfo(iter([req]), timeout=timeout)
            except Exception:  # noqa: BLE001 — a bad symbol must not abort the rest
                continue
            for resp in responses:
                fdr = getattr(resp, "file_descriptor_response", None)
                if fdr is None:
                    continue
                for raw in getattr(fdr, "file_descriptor_proto", []):
                    try:
                        fdp = descriptor_pb2.FileDescriptorProto()
                        fdp.ParseFromString(raw)
                    except Exception:  # noqa: BLE001 — best-effort descriptor parse
                        continue
                    pkg = fdp.package or ""
                    for sdp in fdp.service:
                        full_svc = f"{pkg}.{sdp.name}" if pkg else sdp.name
                        for mdp in sdp.method:
                            full_method = f"/{full_svc}/{mdp.name}"
                            if full_method in seen:
                                continue
                            seen.add(full_method)
                            methods.append(
                                {
                                    "service": full_svc,
                                    "method": mdp.name,
                                    "full_method": full_method,
                                    "input_type": (mdp.input_type or "").lstrip("."),
                                    "output_type": (mdp.output_type or "").lstrip("."),
                                }
                            )
        return methods
    finally:
        try:
            channel.close()
        except Exception:  # noqa: BLE001
            pass


# --------------------------------------------------------------------------- invocation seam
def _invoke_method(
    host, port, scheme, full_method, metadata=None, request_bytes: bytes = b"", timeout: float = 8.0
) -> dict:
    """Invoke a unary RPC generically with pass-through serializers (network seam, lazy grpc).

    Opens a channel and calls ``channel.unary_unary(full_method, request_serializer=identity,
    response_deserializer=identity)`` with the given ``metadata`` (default ``None`` =
    *unauthenticated*) and ``request_bytes`` (default empty). Returns
    ``{"code": <StatusCode.name|'OK'>, "ok": bool, "response_len": int, "details": str}``; on a
    ``grpc.RpcError`` it reads ``err.code()``/``err.details()``. Raises ``ImportError`` when grpcio
    is absent. Monkeypatched in tests so no live server is needed.
    """
    import grpc  # lazy — module imports fine without grpcio installed

    target = f"{host}:{port}"
    secure = str(scheme or "").lower() in ("https", "grpcs", "tls", "ssl")
    channel = (
        grpc.secure_channel(target, grpc.ssl_channel_credentials())
        if secure
        else grpc.insecure_channel(target)
    )
    try:
        rpc = channel.unary_unary(
            full_method,
            request_serializer=lambda b: b,
            response_deserializer=lambda b: b,
        )
        try:
            resp = rpc(request_bytes, metadata=(metadata or None), timeout=timeout)
            body = resp if isinstance(resp, (bytes, bytearray)) else (resp or b"")
            return {"code": "OK", "ok": True, "response_len": len(body), "details": ""}
        except grpc.RpcError as err:  # noqa: BLE001 — surfaced as a status code, not a raise
            code = err.code()
            name = getattr(code, "name", None) or str(code)
            details = ""
            try:
                details = err.details() or ""
            except Exception:  # noqa: BLE001
                details = ""
            return {"code": name, "ok": False, "response_len": 0, "details": details}
    finally:
        try:
            channel.close()
        except Exception:  # noqa: BLE001
            pass


# --------------------------------------------------------------------------- read/mutate classification
# The FIRST word of a method name must be exactly one of these for it to count as a read.
READ_VERBS = frozenset(
    {
        "get",
        "list",
        "read",
        "describe",
        "query",
        "search",
        "find",
        "fetch",
        "lookup",
        "check",
        "count",
        "health",
        "watch",
        "ping",
        "status",
        "show",
        "view",
        "exists",
    }
)
# If ANY word of the method name is one of these, it is treated as mutating (never auto-invoked).
MUTATING_VERBS = frozenset(
    {
        "create", "update", "delete", "del", "remove", "rm", "purge", "reset", "set", "put", "post",
        "add", "write", "checkout", "buy", "pay", "send", "cancel", "drop", "insert", "upsert",
        "modify", "patch", "execute", "exec", "run", "start", "stop", "kill", "transfer", "approve",
        "grant", "revoke", "mutate", "rotate", "issue", "submit", "commit", "apply", "assign",
        "unassign", "register", "unregister", "enable", "disable", "restart", "reboot", "shutdown",
        "destroy", "erase", "clear", "truncate", "wipe", "import", "upload", "merge", "move", "rename",
        "replace", "refund", "charge", "order", "place", "book", "reserve", "confirm", "accept",
        "reject", "deny", "block", "unblock", "ban", "unban", "lock", "unlock", "invite", "publish",
        "unpublish", "deploy", "trigger", "invoke", "call", "process", "sync", "flush", "evict",
        "expire", "invalidate", "archive", "unarchive", "restore", "rollback", "scale", "resize",
        "attach", "detach", "link", "unlink", "subscribe", "unsubscribe", "follow", "unfollow",
        "like", "vote", "mark", "save", "store", "push", "pop", "enqueue", "dequeue", "increment",
        "decrement", "incr", "decr", "toggle", "change", "edit", "generate", "new", "make", "init",
        "initialize", "provision", "deprovision", "allocate", "release", "claim", "redeem",
        "withdraw", "deposit", "sell", "purchase", "mint", "burn", "seed", "migrate", "upgrade",
        "install", "uninstall", "reindex", "compact", "verify", "login", "logout", "signup",
        "signin", "signout", "authenticate", "authorize", "consume", "ack", "nack", "acquire",
        "renew", "refresh", "retry", "resend", "notify", "emit", "broadcast", "dispatch", "schedule",
        "unschedule", "suspend", "resume", "pause", "terminate", "close", "open", "fork", "clone",
        "copy", "export", "batch", "bulk", "fire",
    }
)  # fmt: skip
# Back-compat aliases (pre-word-split names).
READ_PREFIXES = tuple(sorted(READ_VERBS))
MUTATING_PREFIXES = tuple(sorted(MUTATING_VERBS))

_CAMEL_1 = re.compile(r"([A-Z]+)([A-Z][a-z])")
_CAMEL_2 = re.compile(r"([a-z0-9])([A-Z])")


def _method_words(method_name) -> list[str]:
    """Split ``GetOrCreateUser`` / ``get_or_create_user`` / ``HTTPGetX`` into lower-case words."""
    name = str(method_name or "")
    name = _CAMEL_1.sub(r"\1_\2", name)
    name = _CAMEL_2.sub(r"\1_\2", name)
    return [w for w in re.split(r"[^A-Za-z0-9]+", name.lower()) if w]


def _is_read_method(method_name) -> bool:
    """True iff the method is unambiguously a READ (fail-closed classifier).

    The name is split into words (CamelCase and snake_case); it is a read only when the FIRST
    word is exactly a read verb (:data:`READ_VERBS`) AND NO word is a mutating verb
    (:data:`MUTATING_VERBS`). So ``GetUser``/``list_orders`` are reads, while ``Checkout``,
    ``GetOrCreateUser``, ``ReadAndDelete``, ``QueryAndPurge``, ``HealthReset`` and ``Getaway``
    are not — anything that might write is never auto-invoked.
    """
    words = _method_words(method_name)
    if not words or words[0] not in READ_VERBS:
        return False
    return not any(w in MUTATING_VERBS for w in words)


# --------------------------------------------------------------------------- method-level findings
def _plaintext_finding(application, target_url, engagement_id, scheme) -> Finding:
    """Firm CWE-319 finding: the gRPC server answered over an insecure (non-TLS) channel."""
    sch = str(scheme or "grpc")
    f = Finding(
        engagement_id=engagement_id,
        title="gRPC served over plaintext (no TLS)",
        vuln_class="GRPC_PLAINTEXT",
        severity="medium",
        confidence="firm",
        state=State.EVIDENCE_FOUND,
        cwe=["CWE-319"],
        owasp={"web_2021": ["A02:2021-Cryptographic Failures"]},
        cvss=CVSS(
            version="3.1",
            base_score=5.9,
            severity="medium",
            vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
            v31_fallback={"base_score": 5.9, "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N"},
        ),
        asset={"type": "grpc", "application": application, "environment": "authorized", "target": target_url},
        endpoint={"method": "POST", "url": target_url, "auth_required": False, "scheme": sch},
        description=(
            f"The gRPC endpoint answered over an insecure, non-TLS channel (scheme='{sch}'). RPC "
            "requests, responses and any bearer tokens/metadata travel unencrypted and can be read "
            "or tampered with by a network attacker (CWE-319)."
        ),
        impact=(
            "Credentials, tokens and message payloads on this channel are exposed to passive "
            "eavesdropping and active man-in-the-middle tampering."
        ),
        root_cause="The gRPC server accepts insecure (h2c / plaintext) connections instead of TLS.",
        reproduction=Reproduction(
            prerequisites=["A reachable gRPC endpoint"],
            steps=[
                "Open an INSECURE gRPC channel to host:port (no TLS credentials)",
                "Complete server reflection / an RPC over that channel",
                "Observe the server answers without requiring TLS",
            ],
            deterministic=True,
        ),
        remediation=Remediation(
            summary="Serve gRPC only over TLS; disable plaintext/h2c listeners.",
            type="config",
            guidance=(
                "Terminate gRPC on TLS (grpcs) with a valid certificate and disable insecure "
                "listeners; require ALPN 'h2' over TLS and reject h2c (CWE-319)."
            ),
            effort="medium",
        ),
        references=[
            "https://cwe.mitre.org/data/definitions/319.html",
            "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
        ],
        compliance_control_refs=["SOC2:CC6.7", "ISO27001:A.8.24"],
        dedupe_key=f"{application}:grpc-plaintext:{target_url}",
        tags=["grpc", "transport", "plaintext", "tls"],
        verification=Verification(
            method="grpc-transport-probe",
            validated=False,
            validator="grpc-scan",
            independent_reproduction=False,
            reproductions=1,
            false_positive_checks=[
                f"the server completed reflection/RPC over an insecure channel (scheme='{sch}')"
            ],
            confidence_score=0.7,
        ),
    )
    f.evidence.append(Evidence(type="note", summary=f"gRPC reachable over plaintext scheme '{sch}' (no TLS)"))
    f.assert_consistent()
    return f


def _unauth_confirmed_finding(
    application, target_url, engagement_id, open_methods, control_method, first_open, rep_code
) -> Finding:
    """Confirmed GRPC_UNAUTH_METHOD: open methods + a negative control proving auth CAN be enforced."""
    open_list = ", ".join(open_methods)
    f = Finding(
        engagement_id=engagement_id,
        title="gRPC methods invocable without authentication",
        vuln_class="GRPC_UNAUTH_METHOD",
        severity="high",
        confidence="confirmed",
        state=State.VALIDATED,
        cwe=["CWE-306", "CWE-285"],
        owasp={"api_2023": ["API2:2023-Broken Authentication", "API5:2023-BFLA"]},
        cvss=CVSS(
            version="3.1",
            base_score=7.5,
            severity="high",
            vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            v31_fallback={"base_score": 7.5, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
        ),
        asset={"type": "grpc", "application": application, "environment": "authorized", "target": target_url},
        endpoint={"method": "POST", "url": target_url, "auth_required": False, "service": first_open},
        description=(
            f"These gRPC methods returned OK/data when invoked with NO authentication metadata: "
            f"{open_list}. A negative control on the SAME server ({control_method}) returned "
            "UNAUTHENTICATED/PERMISSION_DENIED unauthenticated, proving the server CAN enforce auth "
            "— so the open methods are a real missing-authentication / broken function-level "
            "authorization gap, not a public-by-design server (CWE-306 / CWE-285)."
        ),
        impact=(
            "Unauthenticated clients can call these RPCs directly, reading data or exercising "
            "function-level operations that should require authentication/authorization."
        ),
        root_cause=(
            "The listed RPCs are served without an auth/authorization interceptor while "
            "other methods on the same server enforce one (inconsistent, per-handler auth)."
        ),
        reproduction=Reproduction(
            prerequisites=["A reachable gRPC endpoint with server reflection"],
            steps=[
                "Enumerate methods via server reflection",
                f"Invoke {first_open} over a channel with NO auth metadata and an empty request",
                "Observe an OK/data response (no UNAUTHENTICATED)",
                f"Confirm control method {control_method} returns UNAUTHENTICATED unauthenticated",
                f"Re-invoke {first_open} a second time and observe the same unauthenticated result",
            ],
            deterministic=True,
        ),
        remediation=Remediation(
            summary="Require authentication/authorization on every RPC via a server interceptor.",
            type="code_patch",
            guidance=(
                "Install a deny-by-default auth interceptor that rejects unauthenticated calls, "
                "and enforce per-method authorization centrally rather than per-handler "
                "(CWE-306, CWE-285)."
            ),
            effort="medium",
        ),
        references=[
            "https://cwe.mitre.org/data/definitions/306.html",
            "https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/",
        ],
        compliance_control_refs=["SOC2:CC6.1", "ISO27001:A.8.3"],
        dedupe_key=f"{application}:grpc-unauth-method:{target_url}",
        tags=["grpc", "auth", "bfla", "unauthenticated"],
        verification=Verification(
            method="grpc-unauth-invoke",
            validated=True,
            validated_at=now_iso(),
            validator="grpc-scan",
            independent_reproduction=True,
            reproductions=2,
            false_positive_checks=[
                f"negative control: {control_method} returned UNAUTHENTICATED/PERMISSION_DENIED "
                "unauthenticated (the server CAN enforce auth, so this is not public-by-design)",
                f"reproduction 1: first invocation of {first_open} with no auth metadata returned OK/data",
                f"reproduction 2: independent re-invocation of {first_open} with no auth metadata "
                f"returned '{rep_code}'",
            ],
            confidence_score=0.9,
        ),
    )
    f.evidence.append(Evidence(type="note", summary=f"unauthenticated gRPC methods: {open_list}"))
    f.evidence.append(
        Evidence(type="note", summary=f"negative control (auth enforced unauthenticated): {control_method}")
    )
    f.assert_consistent()
    return f


def _unauth_firm_finding(application, target_url, engagement_id, open_methods) -> Finding:
    """Firm indicator: EVERY probed method is open (no negative control) — may be public by design."""
    open_list = ", ".join(open_methods)
    f = Finding(
        engagement_id=engagement_id,
        title="all gRPC methods invocable without authentication (verify intended)",
        vuln_class="GRPC_UNAUTH_METHOD",
        severity="high",
        confidence="firm",
        state=State.EVIDENCE_FOUND,
        cwe=["CWE-306", "CWE-285"],
        owasp={"api_2023": ["API2:2023-Broken Authentication", "API5:2023-BFLA"]},
        cvss=CVSS(
            version="3.1",
            base_score=7.5,
            severity="high",
            vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            v31_fallback={"base_score": 7.5, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
        ),
        asset={"type": "grpc", "application": application, "environment": "authorized", "target": target_url},
        endpoint={"method": "POST", "url": target_url, "auth_required": False},
        description=(
            f"Every probed gRPC method answered OK/data with NO authentication metadata "
            f"({open_list}), and NO method returned UNAUTHENTICATED/PERMISSION_DENIED. Without a "
            "negative control this cannot be confirmed as a gap — the server may be public by "
            "design — so it is reported as an indicator to verify (fail-closed: NOT confirmed)."
        ),
        impact=(
            "If authentication is intended, unauthenticated clients can call every RPC; if the "
            "service is intentionally public this is expected — manual verification required."
        ),
        root_cause=(
            "No method on the server rejected an unauthenticated call, so either auth is "
            "absent everywhere or the service is intentionally public."
        ),
        reproduction=Reproduction(
            prerequisites=["A reachable gRPC endpoint with server reflection"],
            steps=[
                "Enumerate methods via server reflection",
                "Invoke each read-ish method with NO auth metadata and an empty request",
                "Observe every method answers OK/data (none returns UNAUTHENTICATED)",
            ],
            deterministic=True,
        ),
        remediation=Remediation(
            summary="Confirm whether the service is intended to be public; if not, require auth on every RPC.",
            type="config",
            guidance=(
                "If the service is not meant to be public, add a deny-by-default auth "
                "interceptor and per-method authorization (CWE-306, CWE-285)."
            ),
            effort="medium",
        ),
        references=[
            "https://cwe.mitre.org/data/definitions/306.html",
            "https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/",
        ],
        compliance_control_refs=["SOC2:CC6.1", "ISO27001:A.8.3"],
        dedupe_key=f"{application}:grpc-unauth-method-all:{target_url}",
        tags=["grpc", "auth", "bfla", "unauthenticated", "verify"],
        verification=Verification(
            method="grpc-unauth-invoke",
            validated=False,
            validator="grpc-scan",
            independent_reproduction=False,
            reproductions=1,
            false_positive_checks=[
                "no negative control found: every probed method answered unauthenticated, so the "
                "server may be intentionally public (fail-closed: not confirmed)"
            ],
            confidence_score=0.5,
        ),
    )
    f.evidence.append(
        Evidence(type="note", summary=f"all probed methods open unauthenticated (no control): {open_list}")
    )
    return f


# --------------------------------------------------------------------------- scope / audit helpers
_SKIP_MISSING = f"grpc: skipped — {install_hint}"


def _call_seam(fn, *args, guard=None, **kw):
    """Call a network seam, passing ``guard`` only if the (possibly monkeypatched) seam accepts it."""
    if guard is not None:
        try:
            params = inspect.signature(fn).parameters
            if "guard" in params or any(p.kind is inspect.Parameter.VAR_KEYWORD for p in params.values()):
                kw["guard"] = guard
        except (TypeError, ValueError):
            pass
    return fn(*args, **kw)


def _scope_refusal(scope, resolver, host, port) -> str:
    """ "" when ``host:port`` is authorized by ``scope`` (host in scope, port in its ``ports``,
    every resolved IP allowlisted); otherwise the refusal reason. ``scope=None`` = caller-trusted."""
    if scope is None:
        return ""
    try:
        hs = scope.host_scope(str(host))
    except Exception:  # noqa: BLE001
        hs = None
    if hs is None:
        return f"grpc: refused — host {host!r} is not in scope"
    try:
        allowed_ports = {int(p) for p in (getattr(hs, "ports", None) or [])}
        port_i = int(port)
    except (TypeError, ValueError):
        return f"grpc: refused — invalid port {port!r}"
    if port_i not in allowed_ports:
        return (
            f"grpc: refused — port {port_i} is not authorized for {host!r} (allowed: {sorted(allowed_ports)})"
        )
    if resolver is None:
        from ..policy.allowlist import default_resolver as resolver
    try:
        ips = [str(i) for i in (resolver(str(host)) or [])]
    except Exception:  # noqa: BLE001
        ips = []
    if not ips:
        return f"grpc: refused — could not resolve {host!r} (fail-closed)"
    for ip in ips:
        try:
            ok = bool(scope.ip_allowed(ip))
        except Exception:  # noqa: BLE001
            ok = False
        if not ok:
            return f"grpc: refused — resolved IP {ip} for {host!r} is not in resolved_ip_allowlist"
    return ""


def _admit(guard, host, port, path: str, purpose: str) -> bool:
    ok, _why = guard.admit(
        str(host),
        {"kind": "grpc-rpc", "method": "POST", "port": port, "path": path, "purpose": purpose},
    )
    return ok


_REFLECTION_RPC = "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo"


def _is_insecure(scheme) -> bool:
    return str(scheme or "").lower() in ("grpc", "http", "h2c", "")


def scan_grpc_methods(
    host,
    port,
    scheme,
    application,
    target_url,
    engagement_id: str = "",
    active: bool = False,
    read_only: bool = True,
    timeout: float = 8.0,
    methods: list | None = None,
    include_plaintext: bool = True,
    audit=None,
    budget=None,
    guard=None,
) -> list:
    """Per-RPC gRPC checks: plaintext transport (passive) + (active-only) unauthenticated invocation.

    Enumeration (``_list_methods``) is always non-destructive; pass ``methods`` to reuse an
    enumeration already done. Actual RPC INVOCATION happens ONLY when ``active=True`` and, while
    ``read_only=True`` (the default), ONLY for unambiguous read methods (:func:`_is_read_method`)
    — mutating RPCs are never auto-invoked. Every RPC is admitted/audited/budgeted through the
    guard (``audit``/``budget``); a killed budget stops the sweep. Returns ``[]`` on any failure
    or when nothing is reachable. Never raises.

    Findings:
      * ``GRPC_PLAINTEXT`` (firm) — emitted when the server answered AND the scheme is insecure
        (passive; ``include_plaintext=False`` lets :func:`scan_grpc` avoid a duplicate).
      * ``GRPC_UNAUTH_METHOD`` (confirmed) — aggregated, only if >=1 read-ish method is invocable
        unauthenticated AND >=1 method is properly gated (negative control). If every probed method
        is open (no control) a firm "verify intended" indicator is emitted instead (fail-closed).
    """
    g = guard_from(
        guard,
        audit=audit,
        budget=budget,
        engagement_id=engagement_id,
        tool="grpc-scan",
        actor_role="grpc-worker",
    )
    if methods is None:
        if not _admit(g, host, port, _REFLECTION_RPC, "list_services + method enumeration"):
            return []
        try:
            methods = _call_seam(_list_methods, host, port, scheme, timeout=timeout, guard=g)
        except Exception:  # noqa: BLE001 — grpcio absent / unreachable / RPC error: degrade to no-op
            methods = []
    if not methods:
        return []

    url = target_url or f"{scheme or 'grpc'}://{host}:{port}"
    findings: list = []

    # --- plaintext transport: the server answered, so if the channel is insecure this is firm. ---
    if include_plaintext and _is_insecure(scheme):
        findings.append(_plaintext_finding(application, url, engagement_id, scheme))

    # --- unauthenticated invocation: active-gated, read-ish only by default. ---
    if not active:
        return findings

    open_methods: list = []  # read-ish methods that answered OK/data with NO auth
    gated_methods: list = []  # negative controls: UNAUTHENTICATED / PERMISSION_DENIED
    for m in methods:
        if g.killed:
            break
        name = m.get("method", "")
        full = m.get("full_method", "")
        if not full:
            continue
        # read_only=True (default) => invoke ONLY read-ish methods; never mutating ones.
        if read_only and not _is_read_method(name):
            continue
        if not _admit(g, host, port, full, "unauthenticated read invocation"):
            continue
        try:
            res = _invoke_method(host, port, scheme, full, metadata=None, request_bytes=b"", timeout=timeout)
        except Exception:  # noqa: BLE001 — a single bad invoke must not abort the sweep
            continue
        raw_code = res.get("code")
        code = str(raw_code or "").upper()
        is_gated = code in ("UNAUTHENTICATED", "PERMISSION_DENIED") or raw_code in (16, 7)
        try:
            rlen = int(res.get("response_len") or 0)
        except Exception:  # noqa: BLE001
            rlen = 0
        is_open = (res.get("ok") is True) or code == "OK" or (not is_gated and rlen > 0)
        if is_gated:
            gated_methods.append(full)
        elif is_open:
            open_methods.append(full)

    if not open_methods:
        return findings  # nothing invocable unauthenticated (e.g. all gated) -> no unauth finding

    if gated_methods:
        first_open = open_methods[0]
        # Reproduce the first open method a 2nd time (independent re-derivation -> reproductions>=2).
        rep: dict = {}
        if _admit(g, host, port, first_open, "unauthenticated read invocation (reproduction)"):
            try:
                rep = _invoke_method(
                    host, port, scheme, first_open, metadata=None, request_bytes=b"", timeout=timeout
                )
            except Exception:  # noqa: BLE001
                rep = {}
        rep_code = str(rep.get("code") or "")
        if rep_code.upper() != "OK" and rep.get("ok") is not True:
            return findings  # the open result did not reproduce -> fail-closed, no confirmed finding
        findings.append(
            _unauth_confirmed_finding(
                application, url, engagement_id, open_methods, gated_methods[0], first_open, rep_code
            )
        )
    else:
        # Every probed method is open: no negative control -> cannot confirm (fail-closed).
        findings.append(_unauth_firm_finding(application, url, engagement_id, open_methods))
    return findings


# --------------------------------------------------------------------------- entry point
def scan_grpc(
    host,
    port,
    scheme,
    application,
    target_url,
    timeout: float = 8.0,
    active: bool = False,
    engagement_id: str = "",
    scope=None,
    resolver=None,
    audit=None,
    budget=None,
    guard=None,
) -> ScanOutcome:
    """Scan a gRPC endpoint for a server-reflection exposure (+ per-RPC checks).

    * Scope (when ``scope`` is given): ``host`` must be in scope, ``port`` must be one of its
      scoped ``ports`` and every resolved IP must be allowlisted — otherwise NO channel is opened
      and the result carries ``skip_reason``. (``scope=None`` keeps the legacy caller-trusted mode.)
    * Reflection via :func:`_list_services`; if it lists services, a confirmed CWE-200 finding
      enriched with the enumerated methods (:func:`_list_methods`, graceful on failure).
    * Passive: a firm ``GRPC_PLAINTEXT`` finding when the server answered over an insecure scheme.
    * ``active=True``: read-only unauthenticated-invocation checks (:func:`scan_grpc_methods`).

    ``engagement_id`` is stamped on every finding; ``audit``/``budget`` record + meter one event per
    RPC. Returns a :class:`ScanOutcome` (a list; ``skip_reason`` is set when grpcio is missing —
    ``"grpc: skipped — pip install rampart-appsec[grpc]"`` — or the target is out of scope). Never
    raises.
    """
    out = ScanOutcome()
    refusal = _scope_refusal(scope, resolver, host, port)
    if refusal:
        out.skip_reason = refusal
        return out
    g = guard_from(
        guard,
        audit=audit,
        budget=budget,
        engagement_id=engagement_id,
        tool="grpc-scan",
        actor_role="grpc-worker",
    )
    if not _admit(g, host, port, _REFLECTION_RPC, "list_services"):
        out.skip_reason = "grpc: stopped — budget exhausted or kill-switch engaged"
        return out
    try:
        services = _call_seam(_list_services, host, port, scheme, timeout=timeout)
    except ImportError:
        out.skip_reason = _SKIP_MISSING
        return out
    except Exception:  # noqa: BLE001 — unreachable / RPC error: degrade to no-op
        return out
    if not services:
        return out
    url = target_url or f"{scheme or 'grpc'}://{host}:{port}"
    methods: list = []
    if _admit(g, host, port, _REFLECTION_RPC, "list_services + method enumeration"):
        try:
            methods = _call_seam(_list_methods, host, port, scheme, timeout=timeout, guard=g)
        except Exception:  # noqa: BLE001 — method listing is best-effort; reflection finding still stands
            methods = []
    out.append(_reflection_finding(services, application, url, engagement_id=engagement_id, methods=methods))
    # Passive: the server answered reflection, so an insecure scheme is itself the observation.
    if _is_insecure(scheme):
        out.append(_plaintext_finding(application, url, engagement_id, scheme))
    if active and methods:
        out.extend(
            scan_grpc_methods(
                host,
                port,
                scheme,
                application,
                url,
                engagement_id=engagement_id,
                active=True,
                timeout=timeout,
                methods=methods,
                include_plaintext=False,
                guard=g,
            )
        )
    return out
