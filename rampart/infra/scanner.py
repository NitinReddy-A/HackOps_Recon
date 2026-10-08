"""Native, dependency-free LIVE infrastructure / exposed-services scanner.

This is the *runtime* complement to the STATIC IaC scanner in :mod:`rampart.iac`. Where the IaC
scanner reads a repository and flags dangerous literals in Terraform/CFN/K8s/Dockerfiles, this
module makes real (but strictly NON-DESTRUCTIVE) TCP/TLS observations against an authorized,
in-scope host to prove that a sensitive backend service — a database, a cache, a container API,
etc. — is actually reachable from this network position, or that a TLS endpoint presents an
expired/self-signed certificate or negotiates an obsolete protocol.

Non-destructive contract
-------------------------
The only things this module ever does on the wire are:

* a plain TCP ``connect`` followed by a *tiny* passive ``recv`` (a few hundred bytes) to capture
  whatever banner the service volunteers — many services (redis, mongodb, postgres, raw HTTP)
  stay silent and simply *accept* the connection, which is itself the signal; and
* for TLS ports, a TLS handshake whose sole purpose is to READ the presented certificate and the
  negotiated protocol version.

It NEVER sends a protocol command, never authenticates, never writes, and never attempts to
change any state. ``scan_infra`` is graceful: an unreachable host, a refused connection, a
timeout, a DNS failure or any other error yields no finding and never raises — it returns ``[]``.

Oracle / trust model (mirrors :mod:`rampart.scanners.misconfig`)
----------------------------------------------------------------
For an exposed sensitive service the observation *is* the oracle: the service either accepts a
TCP connection or it does not. We re-derive the observation on **two independent connects**
(two reproductions) and we run a **negative control** — a connect to a port we expect closed on
the same host — so a host that answers on *everything* (a tarpit / accept-all firewall) cannot
produce a false "open". Only when the control port is confirmed closed do we emit a
``confidence='confirmed'`` / ``verification.validated=True`` finding. TLS certificate / protocol
findings are weaker evidence (``confidence='firm'``, ``validated=False``).

Trust boundary
--------------
Like the gRPC and headless-browser engines, this scanner opens its **own** sockets that do NOT
pass through Rampart's HTTP policy choke-point (the ``ProbeRunner`` / scope pipeline). The caller
is therefore responsible for only ever pointing :func:`scan_infra` at a host:port that is already
authorized and in-scope. As a defence-in-depth aid, :func:`scan_infra` will — when given a
``resolver`` and a ``scope`` — resolve the host and fail **closed** unless the resolved IP is
inside ``scope.ip_allowed`` before it opens a single socket.
"""
from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone

from ..schemas.finding import CVSS, Finding, Remediation, Reproduction, State, Verification
from ..util import now_iso

# --------------------------------------------------------------------------- service catalogue
# port -> (service_name, severity). These are services that should generally NOT be reachable
# from an untrusted network position; reaching them is a Security-Misconfiguration exposure.
SENSITIVE_SERVICES: dict[int, tuple[str, str]] = {
    22: ("ssh", "medium"),
    23: ("telnet", "high"),
    1433: ("mssql", "high"),
    2375: ("docker-api", "critical"),      # unauthenticated Docker daemon == host RCE
    2376: ("docker-api", "critical"),
    2379: ("etcd", "high"),
    3306: ("mysql", "high"),
    3389: ("rdp", "high"),
    5432: ("postgres", "high"),
    5601: ("kibana", "medium"),
    5900: ("vnc", "high"),
    6379: ("redis", "high"),
    8500: ("consul", "medium"),
    9000: ("service-9000", "medium"),       # various (Portainer/MinIO/SonarQube/php-fpm…)
    9092: ("kafka", "medium"),
    9200: ("elasticsearch", "high"),
    11211: ("memcached", "high"),
    15672: ("rabbitmq-mgmt", "medium"),
    27017: ("mongodb", "high"),
}

# TLS ports on which we attempt a (read-only) certificate / protocol inspection.
_TLS_PORTS: frozenset[int] = frozenset({443, 8443})

# Obsolete / weak negotiated protocol versions (CWE-326).
_OBSOLETE_TLS: frozenset[str] = frozenset({"SSLv2", "SSLv3", "TLSv1", "TLSv1.0", "TLSv1.1"})

# High ports used as a NEGATIVE CONTROL: we expect them closed. If a sensitive port looks open
# but one of these ALSO looks open, the host is answering indiscriminately and we must not
# confirm. Several candidates make the control robust to an occasional unlucky collision.
_CONTROL_PORTS: tuple[int, ...] = (59991, 60997, 61999)

# Minimal, PASSIVE banner signatures: if a service volunteers a banner, does it look like the
# protocol we expect on that port? Matching is case-insensitive substring over the decoded
# banner. Absence of a match is NOT disqualifying (most of these services are silent on a bare
# connect); a match merely strengthens the finding. Keys are service names from the table above.
_BANNER_SIGNATURES: dict[str, tuple[str, ...]] = {
    "ssh": ("ssh-",),
    "telnet": ("\xff\xfb", "\xff\xfd", "\xff\xfe", "\xff\xfc"),  # IAC negotiation bytes
    "mysql": ("mysql", "mariadb"),           # greeting carries a NUL-terminated version string
    "mssql": (),
    "postgres": (),
    "redis": ("-err", "+pong", "redis"),     # silent on a bare connect; tokens appear if poked
    "mongodb": (),
    "vnc": ("rfb",),                           # VNC server greets with "RFB 003.00x"
    "rdp": (),
    "elasticsearch": ("elasticsearch", "lucene", "\"cluster_name\""),
    "kibana": ("kibana",),
    "memcached": ("version", "stat"),
    "docker-api": ("docker", "\"apiversion\""),
    "etcd": ("etcd",),
    "consul": ("consul",),
    "kafka": (),
    "rabbitmq-mgmt": ("rabbitmq",),
    "service-9000": (),
}

# CVSS per severity bucket (4.0 base with a 3.1 fallback). Network, no privileges, no UI.
_CVSS_BY_SEV: dict[str, CVSS] = {
    "critical": CVSS(
        version="4.0", base_score=9.3, severity="critical",
        vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
        v31_fallback={"base_score": 9.8,
                      "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}),
    "high": CVSS(
        version="4.0", base_score=7.5, severity="high",
        vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
        v31_fallback={"base_score": 7.5,
                      "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}),
    "medium": CVSS(
        version="4.0", base_score=5.3, severity="medium",
        vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
        v31_fallback={"base_score": 5.3,
                      "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"}),
    "low": CVSS(
        version="4.0", base_score=3.7, severity="low",
        vector="CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
        v31_fallback={"base_score": 3.7,
                      "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N"}),
}

_IMPACT_BY_SEV = {
    "critical": ("Direct takeover: an unauthenticated control-plane/management service is reachable, "
                 "enabling remote code execution, data destruction and host compromise."),
    "high": ("Sensitive data exposure and lateral movement: the backend can be enumerated and, if it "
             "lacks strong authentication, read or abused directly from this network position."),
    "medium": ("Expanded attack surface: a management/support service is reachable and can be "
               "fingerprinted and probed for weak credentials or known CVEs."),
    "low": ("Minor information disclosure / expanded attack surface from an avoidably reachable service."),
}


# --------------------------------------------------------------------------- helpers
def is_sensitive_port(port: int) -> bool:
    """True if ``port`` is a well-known sensitive service port (see :data:`SENSITIVE_SERVICES`)."""
    try:
        return int(port) in SENSITIVE_SERVICES
    except (TypeError, ValueError):
        return False


def _banner_snippet(banner: str, limit: int = 160) -> str:
    """A short, printable rendering of a raw banner for the finding description."""
    if not banner:
        return ""
    cleaned = "".join(ch if (32 <= ord(ch) < 127) else "." for ch in banner)
    cleaned = cleaned.strip()
    return cleaned[:limit]


def _protocol_hint(service: str, banner: str) -> str:
    """Return the matched signature if the banner looks like ``service`` speaking, else ""."""
    if not banner:
        return ""
    low = banner.lower()
    for sig in _BANNER_SIGNATURES.get(service, ()):  # noqa: SIM110 - explicit for clarity
        if sig and sig.lower() in low:
            return sig
    return ""


def _tcp_probe(host: str, ip: str | None, port: int, timeout: float = 1.0) -> dict | None:
    """Non-destructive TCP probe: connect and attempt a tiny passive banner read.

    Returns ``{"open": bool, "banner": str}``. A refused connection or a timeout is reported as
    ``{"open": False, "banner": ""}`` (a definitive "not reachable" signal the negative control
    relies on). Returns ``None`` only on a lookup-style error (e.g. DNS failure) where "open" is
    genuinely unknown. Never raises.
    """
    target = ip or host
    try:
        with socket.create_connection((target, int(port)), timeout=timeout) as sock:
            sock.settimeout(min(timeout, 1.0))
            banner = ""
            try:
                data = sock.recv(512)
                if data:
                    banner = data.decode("latin-1", "replace")
            except (socket.timeout, OSError):
                banner = ""          # silent service — accepting the connection IS the signal
            return {"open": True, "banner": banner}
    except (ConnectionRefusedError, socket.timeout, TimeoutError):
        return {"open": False, "banner": ""}
    except socket.gaierror:
        return None                  # name resolution failed — "open" is unknown
    except OSError:
        # network unreachable / reset / etc. — treat as not-open (no finding), still a usable
        # negative-control signal ("did not answer").
        return {"open": False, "banner": ""}
    except Exception:  # noqa: BLE001 - last-resort guard; never raise out of a probe
        return None


def _negative_control(host: str, ip: str | None, timeout: float) -> tuple[bool, int]:
    """Probe high ports we expect closed. Return (control_is_closed, control_port_used).

    ``control_is_closed`` is True as soon as one candidate is confirmed NOT open — proving the
    host is not answering indiscriminately, which is the precondition for honestly confirming a
    sensitive port. If every candidate looks open (or none could be probed), returns False.
    """
    for port in _CONTROL_PORTS:
        probe = _tcp_probe(host, ip, port, timeout=timeout)
        if probe is not None and probe.get("open") is False:
            return True, port
    return False, _CONTROL_PORTS[0]


# --------------------------------------------------------------------------- minimal X.509 parse
def _read_tlv(der: bytes, off: int) -> tuple[int, int, int]:
    """Read one DER TLV at ``off``; return (tag, value_start, value_end). value_end is also the
    start of the next element (DER is contiguous)."""
    tag = der[off]
    first = der[off + 1]
    if first & 0x80:
        n = first & 0x7F
        length = int.from_bytes(der[off + 2:off + 2 + n], "big")
        vstart = off + 2 + n
    else:
        length = first
        vstart = off + 2
    return tag, vstart, vstart + length


def _parse_asn1_time(tag: int, raw: bytes) -> datetime:
    s = raw.decode("ascii")
    if tag == 0x17:              # UTCTime: YYMMDDHHMMSS[Z]
        yy = int(s[0:2])
        year = 2000 + yy if yy < 50 else 1900 + yy
        rest = s[2:]
    elif tag == 0x18:            # GeneralizedTime: YYYYMMDDHHMMSS[Z]
        year = int(s[0:4])
        rest = s[4:]
    else:
        raise ValueError("unsupported ASN.1 time tag")
    month = int(rest[0:2]); day = int(rest[2:4]); hour = int(rest[4:6])
    minute = int(rest[6:8]) if len(rest) >= 8 and rest[6:8].isdigit() else 0
    second = int(rest[8:10]) if len(rest) >= 10 and rest[8:10].isdigit() else 0
    return datetime(year, month, day, hour, minute, second, tzinfo=timezone.utc)


def _parse_x509(der: bytes) -> dict:
    """Extract {``not_after``: datetime, ``self_signed``: bool} from a DER X.509 cert.

    Self-signed is detected by an exact byte-for-byte equality of the issuer and subject Name
    structures (self-issued). Raises on a malformed/unsupported encoding; the caller guards it.
    """
    def read(o):
        return _read_tlv(der, o)

    _, cs, _ = read(0)                     # Certificate SEQUENCE
    _, ts, _ = read(cs)                    # TBSCertificate SEQUENCE
    off = ts
    tag, _, ve = read(off)                 # [0] version (optional) OR serialNumber
    if tag == 0xA0:                        # EXPLICIT version tag
        off = ve
        _, _, ve = read(off)               # serialNumber
    off = ve
    _, _, ve = read(off)                   # signature AlgorithmIdentifier
    off = ve
    issuer_start = off
    _, _, ve = read(off)                   # issuer Name
    issuer_der = der[issuer_start:ve]
    off = ve
    _, vs, ve = read(off)                  # validity SEQUENCE
    validity_start = vs
    off = ve
    subject_start = off
    _, _, ve = read(off)                   # subject Name
    subject_der = der[subject_start:ve]

    t1_tag, _, t1_end = read(validity_start)          # notBefore
    t2_tag, t2_s, t2_e = read(t1_end)                 # notAfter
    not_after = _parse_asn1_time(t2_tag, der[t2_s:t2_e])
    return {"not_after": not_after, "self_signed": issuer_der == subject_der}


def _tls_probe(host: str, ip: str | None, port: int, timeout: float = 2.0) -> dict | None:
    """Non-destructive TLS handshake that READS the certificate and negotiated protocol only.

    Uses an unverified context (``check_hostname=False`` / ``CERT_NONE``) so the handshake does
    not fail on an expired/self-signed cert, and lowers the minimum protocol version so an
    obsolete protocol can be observed (best effort — the local OpenSSL build may refuse very old
    versions). Returns a dict ``{"tls", "proto", "cert", "expired", "self_signed"}`` or ``None``.
    Never raises.
    """
    target = ip or host
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            ctx.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
        except (ValueError, AttributeError, OSError):
            pass  # build does not permit lowering — obsolete-protocol detection simply won't fire
        with socket.create_connection((target, int(port)), timeout=timeout) as raw:
            raw.settimeout(timeout)
            with ctx.wrap_socket(raw, server_hostname=(host or None)) as tls:
                proto = tls.version() or ""
                der = b""
                try:
                    der = tls.getpeercert(binary_form=True) or b""
                except (ValueError, OSError):
                    der = b""
        not_after_iso = ""
        expired = False
        self_signed = False
        if der:
            try:
                parsed = _parse_x509(der)
                na = parsed.get("not_after")
                if isinstance(na, datetime):
                    not_after_iso = na.isoformat().replace("+00:00", "Z")
                    expired = datetime.now(timezone.utc) > na
                self_signed = bool(parsed.get("self_signed"))
            except Exception:  # noqa: BLE001 - cert parse is best effort; handshake data stands
                pass
        return {"tls": True, "proto": proto,
                "cert": {"not_after": not_after_iso, "self_signed": self_signed},
                "expired": expired, "self_signed": self_signed}
    except Exception:  # noqa: BLE001 - unreachable / non-TLS / handshake error: no TLS finding
        return None


# --------------------------------------------------------------------------- finding builders
def _exposed_service_finding(engagement_id: str, host: str, ip: str | None, port: int, svc: str,
                             severity: str, banner: str, application: str, control_port: int,
                             reproductions: int) -> Finding:
    """Build the CONFIRMED 'exposed sensitive service' finding (observation-oracle, validated)."""
    severity = severity if severity in _CVSS_BY_SEV else "medium"
    target = f"{host}:{port}"
    snippet = _banner_snippet(banner)
    hint = _protocol_hint(svc, banner)
    desc = (f"The sensitive service '{svc}' is reachable over the network at {target}: a plain TCP "
            f"connect succeeds on two independent attempts.")
    if snippet:
        desc += f" The service volunteered a banner: {snippet!r}."
    else:
        desc += " The service accepted the connection without volunteering a banner (silent accept)."
    if hint:
        desc += f" The banner matches the expected '{svc}' protocol signature ({hint!r})."

    fp_checks = [
        "service answered on 2 independent connects (two reproductions)",
        f"a closed control port (:{control_port}) on the same host did NOT answer (negative control)",
    ]
    if hint:
        fp_checks.append(f"banner confirmed the '{svc}' protocol (signature {hint!r})")

    f = Finding(
        engagement_id=engagement_id,
        title=f"Exposed sensitive service: {svc} on :{port}",
        vuln_class="EXPOSED_SERVICE",
        severity=severity,
        confidence="confirmed",
        state=State.VALIDATED,
        cwe=["CWE-284", "CWE-668"],
        owasp={"web_2021": ["A05:2021-Security Misconfiguration"]},
        cvss=_CVSS_BY_SEV[severity],
        asset={"type": "infrastructure", "application": application,
               "environment": "authorized", "target": target},
        endpoint={"method": "TCP", "url": target, "auth_required": False},
        description=desc,
        impact=_IMPACT_BY_SEV.get(severity, _IMPACT_BY_SEV["medium"]),
        root_cause=("A sensitive backend service is reachable from this network position; it should "
                    "be firewalled/bound to localhost."),
        reproduction=Reproduction(
            prerequisites=["Network reachability to the target host"],
            steps=[f"TCP connect to {host}:{port}",
                   "Observe the service responds / accepts the connection"],
            deterministic=True),
        remediation=Remediation(
            summary="Restrict the service to a private network / bind to localhost / add a firewall rule.",
            type="config_change",
            guidance=(f"Do not expose {svc} ({port}/tcp) to untrusted networks: bind it to 127.0.0.1 or a "
                      "private interface, place it behind a firewall / security-group allow-list, and "
                      "require strong authentication. Verify no other network path reaches it (CWE-284/668)."),
            effort="medium"),
        references=["https://cwe.mitre.org/data/definitions/284.html",
                    "https://cwe.mitre.org/data/definitions/668.html"],
        compliance_control_refs=["SOC2:CC6.1", "SOC2:CC6.6"],
        dedupe_key=f"infra:{host}:{port}:{svc}",
        tags=["infra", "exposed-service", "network"],
        verification=Verification(
            method="tcp-connect-probe", validated=True, validated_at=now_iso(),
            validator="infra-scan", independent_reproduction=True, reproductions=reproductions,
            false_positive_checks=fp_checks, confidence_score=0.9),
    )
    f.assert_consistent()
    return f


def _tls_cert_finding(engagement_id: str, host: str, port: int, issue: str, severity: str,
                      not_after: str, proto: str, application: str) -> Finding:
    target = f"{host}:{port}"
    desc = f"The TLS endpoint at {target} presents a certificate that is {issue}"
    if not_after:
        desc += f" (notAfter={not_after})"
    desc += f". Negotiated protocol: {proto or 'unknown'}."
    f = Finding(
        engagement_id=engagement_id,
        title=f"TLS certificate issue ({issue}) on :{port}",
        vuln_class="TLS_MISCONFIG",
        severity=severity,
        confidence="firm",
        state=State.EVIDENCE_FOUND,
        cwe=["CWE-295"],
        owasp={"web_2021": ["A02:2021-Cryptographic Failures"]},
        cvss=_CVSS_BY_SEV.get(severity, _CVSS_BY_SEV["medium"]),
        asset={"type": "infrastructure", "application": application,
               "environment": "authorized", "target": target},
        endpoint={"method": "TLS", "url": target, "auth_required": False},
        description=desc,
        impact=("Clients cannot establish trust in the endpoint; the condition enables "
                "machine-in-the-middle attacks and often signals unmanaged/abandoned infrastructure."),
        root_cause="The TLS certificate is expired or self-signed (not issued by a trusted CA).",
        reproduction=Reproduction(
            prerequisites=["Network reachability to the TLS port"],
            steps=[f"TLS handshake to {host}:{port}", "Read the presented X.509 certificate",
                   "Observe the expiry / self-signed condition"],
            deterministic=True),
        remediation=Remediation(
            summary="Install a valid, CA-issued certificate and automate renewal.",
            type="config_change",
            guidance=("Replace the certificate with one from a trusted CA (e.g. ACME/Let's Encrypt), "
                      "automate renewal well before expiry, and retire unused TLS endpoints (CWE-295)."),
            effort="low"),
        references=["https://cwe.mitre.org/data/definitions/295.html"],
        compliance_control_refs=["SOC2:CC6.1", "SOC2:CC6.7"],
        dedupe_key=f"infra-tls:{host}:{port}:cert",
        tags=["infra", "tls", "certificate"],
        verification=Verification(
            method="tls-cert-probe", validated=False, validated_at=now_iso(),
            validator="infra-scan", independent_reproduction=False, reproductions=1,
            false_positive_checks=[f"certificate read over TLS is {issue}"],
            confidence_score=0.7),
    )
    f.assert_consistent()
    return f


def _tls_proto_finding(engagement_id: str, host: str, port: int, proto: str,
                       application: str) -> Finding:
    target = f"{host}:{port}"
    f = Finding(
        engagement_id=engagement_id,
        title=f"Obsolete TLS protocol negotiated ({proto}) on :{port}",
        vuln_class="TLS_WEAK_PROTOCOL",
        severity="medium",
        confidence="firm",
        state=State.EVIDENCE_FOUND,
        cwe=["CWE-326"],
        owasp={"web_2021": ["A02:2021-Cryptographic Failures"]},
        cvss=_CVSS_BY_SEV["medium"],
        asset={"type": "infrastructure", "application": application,
               "environment": "authorized", "target": target},
        endpoint={"method": "TLS", "url": target, "auth_required": False},
        description=(f"The TLS endpoint at {target} negotiated an obsolete protocol version "
                     f"({proto}), which has known cryptographic weaknesses."),
        impact="Weak/obsolete TLS can be downgraded or broken, exposing traffic to interception.",
        root_cause="The server still enables a deprecated TLS/SSL protocol version.",
        reproduction=Reproduction(
            prerequisites=["Network reachability to the TLS port"],
            steps=[f"TLS handshake to {host}:{port}", f"Observe the negotiated version is {proto}"],
            deterministic=True),
        remediation=Remediation(
            summary="Disable SSLv3/TLSv1.0/TLSv1.1; require TLSv1.2+ (prefer TLSv1.3).",
            type="config_change",
            guidance=("Configure the server/load balancer to accept only TLSv1.2 and TLSv1.3 with "
                      "modern cipher suites, and disable all earlier protocol versions (CWE-326)."),
            effort="low"),
        references=["https://cwe.mitre.org/data/definitions/326.html"],
        compliance_control_refs=["SOC2:CC6.1", "SOC2:CC6.7"],
        dedupe_key=f"infra-tls:{host}:{port}:proto",
        tags=["infra", "tls", "weak-protocol"],
        verification=Verification(
            method="tls-cert-probe", validated=False, validated_at=now_iso(),
            validator="infra-scan", independent_reproduction=False, reproductions=1,
            false_positive_checks=[f"server negotiated obsolete protocol {proto}"],
            confidence_score=0.7),
    )
    f.assert_consistent()
    return f


def _tls_findings(engagement_id: str, host: str, ip: str | None, port: int, info: dict,
                  application: str) -> list[Finding]:
    out: list[Finding] = []
    expired = bool(info.get("expired"))
    self_signed = bool(info.get("self_signed"))
    proto = info.get("proto") or ""
    not_after = (info.get("cert") or {}).get("not_after", "")
    if expired or self_signed:
        if expired and self_signed:
            issue, severity = "expired and self-signed", "medium"
        elif expired:
            issue, severity = "expired", "medium"
        else:
            issue, severity = "self-signed", "low"
        out.append(_tls_cert_finding(engagement_id, host, port, issue, severity,
                                     not_after, proto, application))
    if proto in _OBSOLETE_TLS:
        out.append(_tls_proto_finding(engagement_id, host, port, proto, application))
    return out


# --------------------------------------------------------------------------- entry point
def scan_infra(host: str, ports: list[int], engagement_id: str = "", target_url: str = "",
               application: str = "", resolver=None, scope=None, connect_timeout: float = 1.0,
               tls: bool = True, service_map: dict | None = None) -> list[Finding]:
    """Scope-gated, non-destructive live infra / exposed-services scan.

    Parameters
    ----------
    host, ports:
        The authorized, in-scope host and the TCP ports to probe.
    resolver, scope:
        When BOTH are provided, ``host`` is resolved via ``resolver(host) -> [ip, ...]`` and the
        first resolved IP must satisfy ``scope.ip_allowed(ip)`` before any socket is opened; if
        not, the scan returns ``[]`` (fail-closed). When ``scope`` is ``None`` the host is probed
        directly and **the caller is responsible for only passing an in-scope host/ports** (this
        scanner's sockets bypass the HTTP policy pipeline — same contract as the gRPC/browser
        engines). ``scope`` given without a ``resolver`` also fails closed.
    service_map:
        Optional override of :data:`SENSITIVE_SERVICES` (``{port: (service_name, severity)}``),
        primarily so tests can mark an ephemeral port sensitive.

    Returns one CONFIRMED ``EXPOSED_SERVICE`` finding per sensitive port proven reachable on two
    independent connects (with a passing negative control), plus ``firm`` TLS certificate /
    protocol findings for TLS ports. Never raises: any error yields ``[]`` / no finding.
    """
    findings: list[Finding] = []
    if not host or not ports:
        return findings
    smap = service_map if service_map is not None else SENSITIVE_SERVICES
    try:
        ip: str | None = None
        if scope is not None:
            if resolver is None:
                return []  # fail-closed: cannot verify scope without a resolver
            try:
                ips = list(resolver(host) or [])
            except Exception:  # noqa: BLE001 - resolver failure is fail-closed
                return []
            if not ips:
                return []
            ip = ips[0]
            try:
                if not scope.ip_allowed(ip):
                    return []  # fail-closed: resolved IP is out of scope
            except Exception:  # noqa: BLE001 - a broken scope is fail-closed
                return []

        control_closed, control_port = _negative_control(host, ip, connect_timeout)

        for raw_port in ports:
            try:
                port = int(raw_port)
            except (TypeError, ValueError):
                continue

            if port in smap:
                svc, severity = smap[port]
                first = _tcp_probe(host, ip, port, timeout=connect_timeout)
                if first is not None and first.get("open"):
                    second = _tcp_probe(host, ip, port, timeout=connect_timeout)
                    connects_ok = 1 + (1 if (second is not None and second.get("open")) else 0)
                    if connects_ok >= 2 and control_closed:
                        banner = first.get("banner") or (second.get("banner") if second else "") or ""
                        findings.append(_exposed_service_finding(
                            engagement_id, host, ip, port, svc, severity, banner,
                            application, control_port, connects_ok))

            if tls and port in _TLS_PORTS:
                info = _tls_probe(host, ip, port, timeout=max(connect_timeout, 2.0))
                if info is not None and info.get("tls"):
                    findings.extend(_tls_findings(engagement_id, host, ip, port, info, application))
    except Exception:  # noqa: BLE001 - absolute guarantee: scan_infra never raises
        return findings
    return findings
