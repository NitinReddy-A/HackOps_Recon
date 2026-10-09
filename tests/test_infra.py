"""Tests for the LIVE infrastructure / exposed-services scanner (rampart/infra).

Stdlib only. A throwaway loopback TCP server on an ephemeral port stands in for a sensitive
service; the ephemeral port is injected as "sensitive" via the ``service_map`` override so no
real backend is required. No network egress beyond 127.0.0.1 / unroutable TEST-NET addresses.
"""

import socket
import threading

from rampart.infra import SENSITIVE_SERVICES, is_sensitive_port, scan_infra
from rampart.schemas.finding import State


# --------------------------------------------------------------------------- throwaway server
class _FakeService:
    """A loopback TCP server that accepts connections and optionally sends a fixed banner."""

    def __init__(self, banner: bytes = b""):
        self.banner = banner
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.port = self.sock.getsockname()[1]
        self._stop = False
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        while not self._stop:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            try:
                if self.banner:
                    conn.sendall(self.banner)
            except OSError:
                pass
            finally:
                try:
                    conn.close()
                except OSError:
                    pass

    def close(self):
        self._stop = True
        try:
            self.sock.close()
        except OSError:
            pass


def _free_closed_port() -> int:
    """Grab an ephemeral port number, then release it so nothing is listening there."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


# --------------------------------------------------------------------------- catalogue / helper
def test_is_sensitive_port_and_catalogue():
    assert is_sensitive_port(22) is True
    assert is_sensitive_port(6379) is True
    assert is_sensitive_port(2375) is True
    assert is_sensitive_port(54321) is False
    assert is_sensitive_port("not-a-port") is False
    # docker-api must be the critical entry; a couple of the high-value DB ports present.
    assert SENSITIVE_SERVICES[2375] == ("docker-api", "critical")
    assert SENSITIVE_SERVICES[3306][1] == "high"
    assert SENSITIVE_SERVICES[27017][0] == "mongodb"


# --------------------------------------------------------------------------- confirmed finding
def test_open_sensitive_port_yields_one_confirmed_finding():
    svc = _FakeService(banner=b"SSH-2.0-OpenSSH_8.9p1\r\n")
    try:
        findings = scan_infra(
            "127.0.0.1",
            [svc.port],
            engagement_id="eng-1",
            application="demo",
            service_map={svc.port: ("ssh", "high")},
        )
    finally:
        svc.close()

    assert len(findings) == 1
    f = findings[0]
    assert f.vuln_class == "EXPOSED_SERVICE"
    assert f.severity == "high"
    assert f.confidence == "confirmed"
    assert f.state == State.VALIDATED
    assert f.verification.validated is True
    assert f.verification.method == "tcp-connect-probe"
    assert f.verification.reproductions >= 2
    assert f.verification.independent_reproduction is True
    # asset/endpoint target and the title both carry the port.
    assert str(svc.port) in f.asset["target"]
    assert str(svc.port) in f.endpoint["url"]
    assert str(svc.port) in f.title
    assert "CWE-284" in f.cwe and "CWE-668" in f.cwe
    # negative control + two-connect oracle recorded in the FP checks.
    assert any("negative control" in c for c in f.verification.false_positive_checks)
    # the SSH banner should have been recognised as the expected protocol.
    assert any("protocol" in c for c in f.verification.false_positive_checks)
    f.assert_consistent()


def test_silent_service_is_still_confirmed_by_reachability():
    # Many sensitive services (redis/mongo/postgres) stay silent: accepting the connect is enough.
    svc = _FakeService(banner=b"")
    try:
        findings = scan_infra(
            "127.0.0.1", [svc.port], connect_timeout=0.4, service_map={svc.port: ("test-redis", "high")}
        )
    finally:
        svc.close()
    assert len(findings) == 1
    assert findings[0].confidence == "confirmed"
    assert findings[0].verification.validated is True


# --------------------------------------------------------------------------- no false positives
def test_closed_port_yields_no_finding():
    port = _free_closed_port()
    findings = scan_infra("127.0.0.1", [port], connect_timeout=0.4, service_map={port: ("test-svc", "high")})
    assert findings == []


def test_open_but_non_sensitive_port_is_ignored():
    svc = _FakeService(banner=b"hello")
    try:
        # Empty service map => the open port is not considered sensitive => no finding.
        findings = scan_infra("127.0.0.1", [svc.port], connect_timeout=0.4, service_map={})
    finally:
        svc.close()
    assert findings == []


# --------------------------------------------------------------------------- graceful degradation
def test_unreachable_host_returns_empty_and_never_raises():
    # 192.0.2.0/24 is TEST-NET-1 (RFC 5737): guaranteed unroutable. Tiny timeout keeps it quick.
    findings = scan_infra(
        "192.0.2.1",
        [22, 3306, 6379],
        connect_timeout=0.2,
        service_map={22: ("ssh", "medium"), 3306: ("mysql", "high"), 6379: ("redis", "high")},
    )
    assert findings == []


def test_empty_inputs_are_graceful():
    assert scan_infra("", [22]) == []
    assert scan_infra("127.0.0.1", []) == []


# --------------------------------------------------------------------------- scope gating
def test_fail_closed_when_scope_disallows_ip():
    class _DenyScope:
        def ip_allowed(self, ip):
            return False

    # Even though 127.0.0.1 would be reachable, an out-of-scope IP must yield nothing (no socket).
    findings = scan_infra(
        "app.example.test",
        [22],
        resolver=lambda h: ["127.0.0.1"],
        scope=_DenyScope(),
        service_map={22: ("ssh", "medium")},
    )
    assert findings == []


def test_scope_given_without_resolver_fails_closed():
    class _AllowScope:
        def ip_allowed(self, ip):
            return True

    findings = scan_infra("127.0.0.1", [22], scope=_AllowScope(), service_map={22: ("ssh", "medium")})
    assert findings == []


def test_scope_allowed_ip_is_probed_and_confirmed():
    class _AllowScope:
        def ip_allowed(self, ip):
            return True

    svc = _FakeService(banner=b"")
    try:
        findings = scan_infra(
            "host.example.test",
            [svc.port],
            connect_timeout=0.4,
            resolver=lambda h: ["127.0.0.1"],
            scope=_AllowScope(),
            service_map={svc.port: ("test-svc", "high")},
        )
    finally:
        svc.close()
    assert len(findings) == 1
    assert findings[0].verification.validated is True
    # host (not the resolved IP) is used for the human-facing target label.
    assert "host.example.test" in findings[0].asset["target"]
