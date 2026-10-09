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
(two reproductions) and we run a **negative control** — a connect to an *in-scope* port we
expect closed on the same host — so a host that answers on *everything* (a tarpit / accept-all
firewall) cannot produce a false "open". Only when the control port is confirmed closed do we
emit a ``confidence='confirmed'`` / ``verification.validated=True`` finding; when the scope
authorizes no spare port to use as a control the finding is honestly downgraded to ``firm``.
TLS certificate / protocol findings are weaker evidence (``confidence='firm'``,
``validated=False``).

Trust boundary
--------------
Like the gRPC and headless-browser engines, this scanner opens its **own** sockets that do NOT
pass through Rampart's HTTP policy choke-point (the ``ProbeRunner`` / scope pipeline). It
therefore enforces scope itself and fails **closed**: no scope → no connection; host not in scope,
unresolvable, or any resolved IP outside ``resolved_ip_allowlist`` → no connection; and only the
host's scoped ``ports`` (including the negative-control port) are ever connected to. Every
connect is audited and budgeted through :class:`~rampart.infra.sidechannel.SideChannelGuard`.
"""

from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone

from ..schemas.finding import CVSS, Finding, Remediation, Reproduction, State, Verification
from ..util import now_iso
from .sidechannel import ScanOutcome, guard_from

# --------------------------------------------------------------------------- service catalogue
# port -> (service_name, severity). These are services that should generally NOT be reachable
# from an untrusted network position; reaching them is a Security-Misconfiguration exposure.
SENSITIVE_SERVICES: dict[int, tuple[str, str]] = {
    22: ("ssh", "medium"),
    23: ("telnet", "high"),
    1433: ("mssql", "high"),
    2375: ("docker-api", "critical"),  # unauthenticated Docker daemon == host RCE
    2376: ("docker-api", "critical"),
    2379: ("etcd", "high"),
    3306: ("mysql", "high"),
    3389: ("rdp", "high"),
    5432: ("postgres", "high"),
    5601: ("kibana", "medium"),
    5900: ("vnc", "high"),
    6379: ("redis", "high"),
    8500: ("consul", "medium"),
    9000: ("service-9000", "medium"),  # various (Portainer/MinIO/SonarQube/php-fpm…)
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

# NEGATIVE CONTROL ports are no longer hard-coded: a control connect is still a connection to
# the target, so it must be authorized like any other. Controls are chosen from the host's
# scoped ``ports`` (see :func:`_control_candidates`); with none available, findings are reported
# ``firm`` (accept-all host not ruled out) instead of ``confirmed``.

# Minimal, PASSIVE banner signatures: if a service volunteers a banner, does it look like the
# protocol we expect on that port? Matching is case-insensitive substring over the decoded
# banner. Absence of a match is NOT disqualifying (most of these services are silent on a bare
# connect); a match merely strengthens the finding. Keys are service names from the table above.
_BANNER_SIGNATURES: dict[str, tuple[str, ...]] = {
    "ssh": ("ssh-",),
    "telnet": ("\xff\xfb", "\xff\xfd", "\xff\xfe", "\xff\xfc"),  # IAC negotiation bytes
    "mysql": ("mysql", "mariadb"),  # greeting carries a NUL-terminated version string
    "mssql": (),
    "postgres": (),
    "redis": ("-err", "+pong", "redis"),  # silent on a bare connect; tokens appear if poked
    "mongodb": (),
    "vnc": ("rfb",),  # VNC server greets with "RFB 003.00x"
    "rdp": (),
    "elasticsearch": ("elasticsearch", "lucene", '"cluster_name"'),
    "kibana": ("kibana",),
    "memcached": ("version", "stat"),
    "docker-api": ("docker", '"apiversion"'),
    "etcd": ("etcd",),
    "consul": ("consul",),
    "kafka": (),
    "rabbitmq-mgmt": ("rabbitmq",),
    "service-9000": (),
}

# CVSS per severity bucket (4.0 base with a 3.1 fallback). Network, no privileges, no UI.
_CVSS_BY_SEV: dict[str, CVSS] = {
    "critical": CVSS(
        version="4.0",
        base_score=9.3,
        severity="critical",
        vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
        v31_fallback={"base_score": 9.8, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
    ),
    "high": CVSS(
        version="4.0",
        base_score=7.5,
        severity="high",
        vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
        v31_fallback={"base_score": 7.5, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
    ),
    "medium": CVSS(
        version="4.0",
        base_score=5.3,
        severity="medium",
        vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
        v31_fallback={"base_score": 5.3, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"},
    ),
    "low": CVSS(
        version="4.0",
        base_score=3.7,
        severity="low",
        vector="CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
        v31_fallback={"base_score": 3.7, "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N"},
    ),
}

_IMPACT_BY_SEV = {
    "critical": (
        "Direct takeover: an unauthenticated control-plane/management service is reachable, "
        "enabling remote code execution, data destruction and host compromise."
    ),
    "high": (
        "Sensitive data exposure and lateral movement: the backend can be enumerated and, if it "
        "lacks strong authentication, read or abused directly from this network position."
    ),
    "medium": (
        "Expanded attack surface: a management/support service is reachable and can be "
        "fingerprinted and probed for weak credentials or known CVEs."
    ),
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
            except (TimeoutError, OSError):
                banner = ""  # silent service — accepting the connection IS the signal
            return {"open": True, "banner": banner}
    except (ConnectionRefusedError, TimeoutError):
        return {"open": False, "banner": ""}
    except socket.gaierror:
        return None  # name resolution failed — "open" is unknown
    except OSError:
        # network unreachable / reset / etc. — treat as not-open (no finding), still a usable
        # negative-control signal ("did not answer").
        return {"open": False, "banner": ""}
    except Exception:  # noqa: BLE001 - last-resort guard; never raise out of a probe
        return None


def _control_candidates(
    scoped_ports: set, requested: set, smap: dict, explicit: list | None = None
) -> list[int]:
    """In-scope ports usable as a NEGATIVE CONTROL (expected closed). Never an unscoped port.

    ``explicit`` (operator-chosen control ports) wins, but is still intersected with the scope.
    Otherwise: every scoped port that is not itself a candidate (not requested, not a sensitive
    service, not a TLS port) — e.g. a ``ports: [8080, 6379, 18999]`` scope uses 18999.
    """
    if explicit:
        out = []
        for p in explicit:
            try:
                p = int(p)
            except (TypeError, ValueError):
                continue
            if p in scoped_ports and p not in smap and p not in out:
                out.append(p)
        return out
    return [p for p in sorted(scoped_ports) if p not in requested and p not in smap and p not in _TLS_PORTS]


# --------------------------------------------------------------------------- minimal X.509 parse
def _read_tlv(der: bytes, off: int) -> tuple[int, int, int]:
    """Read one DER TLV at ``off``; return (tag, value_start, value_end). value_end is also the
    start of the next element (DER is contiguous)."""
    tag = der[off]
    first = der[off + 1]
    if first & 0x80:
        n = first & 0x7F
        length = int.from_bytes(der[off + 2 : off + 2 + n], "big")
        vstart = off + 2 + n
    else:
        length = first
        vstart = off + 2
    return tag, vstart, vstart + length


def _parse_asn1_time(tag: int, raw: bytes) -> datetime:
    s = raw.decode("ascii")
    if tag == 0x17:  # UTCTime: YYMMDDHHMMSS[Z]
        yy = int(s[0:2])
        year = 2000 + yy if yy < 50 else 1900 + yy
        rest = s[2:]
    elif tag == 0x18:  # GeneralizedTime: YYYYMMDDHHMMSS[Z]
        year = int(s[0:4])
        rest = s[4:]
    else:
        raise ValueError("unsupported ASN.1 time tag")
    month = int(rest[0:2])
    day = int(rest[2:4])
    hour = int(rest[4:6])
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

    _, cs, _ = read(0)  # Certificate SEQUENCE
    _, ts, _ = read(cs)  # TBSCertificate SEQUENCE
    off = ts
    tag, _, ve = read(off)  # [0] version (optional) OR serialNumber
    if tag == 0xA0:  # EXPLICIT version tag
        off = ve
        _, _, ve = read(off)  # serialNumber
    off = ve
    _, _, ve = read(off)  # signature AlgorithmIdentifier
    off = ve
    issuer_start = off
    _, _, ve = read(off)  # issuer Name
    issuer_der = der[issuer_start:ve]
    off = ve
    _, vs, ve = read(off)  # validity SEQUENCE
    validity_start = vs
    off = ve
    subject_start = off
    _, _, ve = read(off)  # subject Name
    subject_der = der[subject_start:ve]

    t1_tag, _, t1_end = read(validity_start)  # notBefore
    t2_tag, t2_s, t2_e = read(t1_end)  # notAfter
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
        return {
            "tls": True,
            "proto": proto,
            "cert": {"not_after": not_after_iso, "self_signed": self_signed},
            "expired": expired,
            "self_signed": self_signed,
        }
    except Exception:  # noqa: BLE001 - unreachable / non-TLS / handshake error: no TLS finding
        return None


# --------------------------------------------------------------------------- finding builders
def _exposed_service_finding(
    engagement_id: str,
    host: str,
    ip: str | None,
    port: int,
    svc: str,
    severity: str,
    banner: str,
    application: str,
    control_port: int | None,
    reproductions: int,
) -> Finding:
    """Build the 'exposed sensitive service' finding (observation-oracle).

    CONFIRMED/validated when an in-scope negative-control port was proven closed; ``firm`` and
    unvalidated when no in-scope control port was available (``control_port=None``) — an
    accept-all host / tarpit cannot then be ruled out, so we refuse to claim confirmation.
    """
    severity = severity if severity in _CVSS_BY_SEV else "medium"
    target = f"{host}:{port}"
    snippet = _banner_snippet(banner)
    hint = _protocol_hint(svc, banner)
    desc = (
        f"The sensitive service '{svc}' is reachable over the network at {target}: a plain TCP "
        f"connect succeeds on two independent attempts."
    )
    if snippet:
        desc += f" The service volunteered a banner: {snippet!r}."
    else:
        desc += " The service accepted the connection without volunteering a banner (silent accept)."
    if hint:
        desc += f" The banner matches the expected '{svc}' protocol signature ({hint!r})."

    controlled = control_port is not None
    fp_checks = ["service answered on 2 independent connects (two reproductions)"]
    if controlled:
        fp_checks.append(
            f"a closed in-scope control port (:{control_port}) on the same host did NOT answer (negative control)"
        )
    else:
        fp_checks.append(
            "NO negative control: the scope authorizes no spare port to use as a closed control, so an "
            "accept-all host / tarpit is not ruled out (reported firm, not confirmed)"
        )
    if hint:
        fp_checks.append(f"banner confirmed the '{svc}' protocol (signature {hint!r})")

    f = Finding(
        engagement_id=engagement_id,
        title=f"Exposed sensitive service: {svc} on :{port}",
        vuln_class="EXPOSED_SERVICE",
        severity=severity,
        confidence="confirmed" if controlled else "firm",
        state=State.VALIDATED if controlled else State.EVIDENCE_FOUND,
        cwe=["CWE-284", "CWE-668"],
        owasp={"web_2021": ["A05:2021-Security Misconfiguration"]},
        cvss=_CVSS_BY_SEV[severity],
        asset={
            "type": "infrastructure",
            "application": application,
            "environment": "authorized",
            "target": target,
        },
        endpoint={"method": "TCP", "url": target, "auth_required": False},
        description=desc,
        impact=_IMPACT_BY_SEV.get(severity, _IMPACT_BY_SEV["medium"]),
        root_cause=(
            "A sensitive backend service is reachable from this network position; it should "
            "be firewalled/bound to localhost."
        ),
        reproduction=Reproduction(
            prerequisites=["Network reachability to the target host"],
            steps=[f"TCP connect to {host}:{port}", "Observe the service responds / accepts the connection"],
            deterministic=True,
        ),
        remediation=Remediation(
            summary="Restrict the service to a private network / bind to localhost / add a firewall rule.",
            type="config_change",
            guidance=(
                f"Do not expose {svc} ({port}/tcp) to untrusted networks: bind it to 127.0.0.1 or a "
                "private interface, place it behind a firewall / security-group allow-list, and "
                "require strong authentication. Verify no other network path reaches it (CWE-284/668)."
            ),
            effort="medium",
        ),
        references=[
            "https://cwe.mitre.org/data/definitions/284.html",
            "https://cwe.mitre.org/data/definitions/668.html",
        ],
        compliance_control_refs=["SOC2:CC6.1", "SOC2:CC6.6"],
        dedupe_key=f"infra:{host}:{port}:{svc}",
        tags=["infra", "exposed-service", "network"],
        verification=Verification(
            method="tcp-connect-probe",
            validated=controlled,
            validated_at=now_iso(),
            validator="infra-scan",
            independent_reproduction=True,
            reproductions=reproductions,
            false_positive_checks=fp_checks,
            confidence_score=0.9 if controlled else 0.6,
        ),
    )
    f.assert_consistent()
    return f


def _tls_cert_finding(
    engagement_id: str,
    host: str,
    port: int,
    issue: str,
    severity: str,
    not_after: str,
    proto: str,
    application: str,
) -> Finding:
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
        asset={
            "type": "infrastructure",
            "application": application,
            "environment": "authorized",
            "target": target,
        },
        endpoint={"method": "TLS", "url": target, "auth_required": False},
        description=desc,
        impact=(
            "Clients cannot establish trust in the endpoint; the condition enables "
            "machine-in-the-middle attacks and often signals unmanaged/abandoned infrastructure."
        ),
        root_cause="The TLS certificate is expired or self-signed (not issued by a trusted CA).",
        reproduction=Reproduction(
            prerequisites=["Network reachability to the TLS port"],
            steps=[
                f"TLS handshake to {host}:{port}",
                "Read the presented X.509 certificate",
                "Observe the expiry / self-signed condition",
            ],
            deterministic=True,
        ),
        remediation=Remediation(
            summary="Install a valid, CA-issued certificate and automate renewal.",
            type="config_change",
            guidance=(
                "Replace the certificate with one from a trusted CA (e.g. ACME/Let's Encrypt), "
                "automate renewal well before expiry, and retire unused TLS endpoints (CWE-295)."
            ),
            effort="low",
        ),
        references=["https://cwe.mitre.org/data/definitions/295.html"],
        compliance_control_refs=["SOC2:CC6.1", "SOC2:CC6.7"],
        dedupe_key=f"infra-tls:{host}:{port}:cert",
        tags=["infra", "tls", "certificate"],
        verification=Verification(
            method="tls-cert-probe",
            validated=False,
            validated_at=now_iso(),
            validator="infra-scan",
            independent_reproduction=False,
            reproductions=1,
            false_positive_checks=[f"certificate read over TLS is {issue}"],
            confidence_score=0.7,
        ),
    )
    f.assert_consistent()
    return f


def _tls_proto_finding(engagement_id: str, host: str, port: int, proto: str, application: str) -> Finding:
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
        asset={
            "type": "infrastructure",
            "application": application,
            "environment": "authorized",
            "target": target,
        },
        endpoint={"method": "TLS", "url": target, "auth_required": False},
        description=(
            f"The TLS endpoint at {target} negotiated an obsolete protocol version "
            f"({proto}), which has known cryptographic weaknesses."
        ),
        impact="Weak/obsolete TLS can be downgraded or broken, exposing traffic to interception.",
        root_cause="The server still enables a deprecated TLS/SSL protocol version.",
        reproduction=Reproduction(
            prerequisites=["Network reachability to the TLS port"],
            steps=[f"TLS handshake to {host}:{port}", f"Observe the negotiated version is {proto}"],
            deterministic=True,
        ),
        remediation=Remediation(
            summary="Disable SSLv3/TLSv1.0/TLSv1.1; require TLSv1.2+ (prefer TLSv1.3).",
            type="config_change",
            guidance=(
                "Configure the server/load balancer to accept only TLSv1.2 and TLSv1.3 with "
                "modern cipher suites, and disable all earlier protocol versions (CWE-326)."
            ),
            effort="low",
        ),
        references=["https://cwe.mitre.org/data/definitions/326.html"],
        compliance_control_refs=["SOC2:CC6.1", "SOC2:CC6.7"],
        dedupe_key=f"infra-tls:{host}:{port}:proto",
        tags=["infra", "tls", "weak-protocol"],
        verification=Verification(
            method="tls-cert-probe",
            validated=False,
            validated_at=now_iso(),
            validator="infra-scan",
            independent_reproduction=False,
            reproductions=1,
            false_positive_checks=[f"server negotiated obsolete protocol {proto}"],
            confidence_score=0.7,
        ),
    )
    f.assert_consistent()
    return f


def _tls_findings(
    engagement_id: str, host: str, ip: str | None, port: int, info: dict, application: str
) -> list[Finding]:
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
        out.append(
            _tls_cert_finding(engagement_id, host, port, issue, severity, not_after, proto, application)
        )
    if proto in _OBSOLETE_TLS:
        out.append(_tls_proto_finding(engagement_id, host, port, proto, application))
    return out


# --------------------------------------------------------------------------- entry point
_NO_SCOPE = "infra: refused — no scope contract given (fail-closed; no connection made)"


def scan_infra(
    host: str,
    ports: list[int] | None = None,
    engagement_id: str = "",
    target_url: str = "",
    application: str = "",
    resolver=None,
    scope=None,
    connect_timeout: float = 1.0,
    tls: bool = True,
    service_map: dict | None = None,
    control_ports: list[int] | None = None,
    audit=None,
    budget=None,
    guard=None,
) -> ScanOutcome:
    """Scope-gated, non-destructive live infra / exposed-services scan.

    Scope is MANDATORY (fail-closed). Before a single socket is opened:

    * ``scope`` must be given (an :class:`~rampart.schemas.scope.EngagementScope`, or any object
      with ``host_scope(host)`` and ``ip_allowed(ip)``) — without it the scan refuses;
    * ``host`` must be in scope (``scope.host_scope(host)`` not ``None``);
    * ``resolver(host)`` must return IPs and EVERY one must satisfy ``scope.ip_allowed`` (a
      missing resolver also refuses);
    * only ports in the host's scoped ``ports`` list are ever connected to — the probed set is
      ``ports ∩ scope ports`` (``ports=None`` means "every catalogued sensitive/TLS port"), and
      negative-control ports are chosen from the scoped ports too (``control_ports`` lets the
      operator name them, still intersected with scope). With no in-scope control port available,
      exposed-service findings are reported ``firm`` rather than ``confirmed``.

    ``audit`` / ``budget`` (or a prebuilt ``guard``) record one audit event per TCP connect / TLS
    handshake and consume one budget request each; a killed budget stops the scan.

    Returns a :class:`ScanOutcome` (a ``list`` of findings; ``.skip_reason`` explains a refusal,
    ``.notes`` lists ports skipped as out of scope). Never raises.
    """
    out = ScanOutcome()
    if not host:
        out.skip_reason = "infra: no host given"
        return out
    if ports is not None and not ports:
        out.skip_reason = "infra: no ports requested"
        return out
    if scope is None:
        out.skip_reason = _NO_SCOPE
        return out
    smap = service_map if service_map is not None else SENSITIVE_SERVICES
    g = guard_from(
        guard,
        audit=audit,
        budget=budget,
        engagement_id=engagement_id,
        tool="infra-scan",
        actor_role="infra-worker",
    )
    try:
        # ---- scope gate (no socket before this passes) ---------------------------------------
        try:
            hs = scope.host_scope(host)
        except Exception:  # noqa: BLE001 - a broken / duck-typed scope without host_scope fails closed
            hs = None
        if hs is None:
            out.skip_reason = f"infra: refused — host {host!r} is not in scope"
            return out
        if resolver is None:
            out.skip_reason = "infra: refused — no resolver to verify the resolved IP against scope"
            return out
        try:
            ips = [str(i) for i in (resolver(host) or [])]
        except Exception:  # noqa: BLE001 - resolver failure is fail-closed
            ips = []
        if not ips:
            out.skip_reason = f"infra: refused — could not resolve {host!r} (fail-closed)"
            return out
        for cand in ips:
            try:
                ok_ip = bool(scope.ip_allowed(cand))
            except Exception:  # noqa: BLE001
                ok_ip = False
            if not ok_ip:
                out.skip_reason = (
                    f"infra: refused — resolved IP {cand} for {host!r} is not in resolved_ip_allowlist"
                )
                return out
        ip = ips[0]
        try:
            scoped_ports = {int(p) for p in (getattr(hs, "ports", None) or [])}
        except (TypeError, ValueError):
            scoped_ports = set()

        # ---- candidate ports = requested ∩ scope -------------------------------------------
        if ports is None:
            requested_list = sorted(set(smap) | set(_TLS_PORTS))
        else:
            requested_list = []
            for raw in ports:
                try:
                    p = int(raw)
                except (TypeError, ValueError):
                    continue
                if p not in requested_list:
                    requested_list.append(p)
        probe_ports = [p for p in requested_list if p in scoped_ports]
        skipped = [p for p in requested_list if p not in scoped_ports]
        if skipped:
            out.notes.append(
                f"infra: {len(skipped)} candidate port(s) not authorized by the scope for {host!r} — not probed"
            )
        if not probe_ports:
            out.notes.append(
                f"infra: no candidate port is authorized by the scope for {host!r} "
                f"(scoped ports: {sorted(scoped_ports)}); nothing probed"
            )
            return out

        def _connect(port: int, purpose: str):
            ok, _why = g.admit(
                host,
                {
                    "kind": "tcp-connect",
                    "method": "TCP",
                    "port": port,
                    "resolved_ip": ip or "",
                    "purpose": purpose,
                },
            )
            if not ok:
                return None
            return _tcp_probe(host, ip, port, timeout=connect_timeout)

        controls = _control_candidates(scoped_ports, set(requested_list), smap, control_ports)
        control_state: dict = {"done": False, "closed": False, "port": None}

        def _run_control() -> None:
            # Lazily, once, and only when a sensitive port actually looked open twice.
            if control_state["done"]:
                return
            control_state["done"] = True
            for cport in controls:
                if g.killed:
                    return
                probe = _connect(cport, "negative-control")
                if probe is not None and probe.get("open") is False:
                    control_state["closed"], control_state["port"] = True, cport
                    return

        for port in probe_ports:
            if g.killed:
                out.notes.append("infra: stopped — engagement kill-switch engaged")
                break
            if port in smap:
                svc, severity = smap[port]
                first = _connect(port, "probe")
                if first is not None and first.get("open"):
                    second = _connect(port, "reproduction")
                    connects_ok = 1 + (1 if (second is not None and second.get("open")) else 0)
                    if connects_ok >= 2:
                        _run_control()
                        # every in-scope control ALSO answered => accept-all host => no finding.
                        if control_state["closed"] or not controls:
                            banner = first.get("banner") or (second.get("banner") if second else "") or ""
                            out.append(
                                _exposed_service_finding(
                                    engagement_id,
                                    host,
                                    ip,
                                    port,
                                    svc,
                                    severity,
                                    banner,
                                    application,
                                    control_state["port"] if control_state["closed"] else None,
                                    connects_ok,
                                )
                            )

            if tls and port in _TLS_PORTS and not g.killed:
                ok, _why = g.admit(
                    host,
                    {"kind": "tls-handshake", "method": "TLS", "port": port, "resolved_ip": ip or ""},
                )
                if ok:
                    info = _tls_probe(host, ip, port, timeout=max(connect_timeout, 2.0))
                    if info is not None and info.get("tls"):
                        out.extend(_tls_findings(engagement_id, host, ip, port, info, application))
    except Exception:  # noqa: BLE001 - absolute guarantee: scan_infra never raises
        return out
    return out
