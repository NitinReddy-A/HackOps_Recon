"""Tests for the LIVE infrastructure / exposed-services scanner (rampart/infra).

Stdlib only. A throwaway loopback TCP server on an ephemeral port stands in for a sensitive
service; the ephemeral port is injected as "sensitive" via the ``service_map`` override so no
real backend is required. No network egress beyond 127.0.0.1 / unroutable TEST-NET addresses.
"""

import socket
import threading

from rampart.infra import SENSITIVE_SERVICES, is_sensitive_port, scan_infra, skip_reason_of
from rampart.schemas.finding import State
from rampart.schemas.scope import EngagementScope


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


# --------------------------------------------------------------------------- scope helpers
def _scope(ports, host="127.0.0.1", allow=("127.0.0.1/32",)):
    return EngagementScope.from_dict(
        {
            "apiVersion": "security-agent/v1",
            "kind": "EngagementScope",
            "scope": {
                "in_scope": [{"host": host, "ports": list(ports)}],
                "resolved_ip_allowlist": list(allow),
            },
        }
    )


def _loopback(_h):
    return ["127.0.0.1"]


def _scan(host, ports, scoped_ports, **kw):
    kw.setdefault("connect_timeout", 0.4)
    return scan_infra(host, ports, scope=_scope(scoped_ports, host=host), resolver=_loopback, **kw)


class _ConnectLog:
    """Record every socket.create_connection target made by the scanner (and still connect)."""

    def __init__(self, monkeypatch):
        import rampart.infra.scanner as mod

        self.ports = []
        orig = socket.create_connection

        def logged(addr, *a, **k):
            self.ports.append(int(addr[1]))
            return orig(addr, *a, **k)

        monkeypatch.setattr(mod.socket, "create_connection", logged)


# --------------------------------------------------------------------------- confirmed finding
def test_open_sensitive_port_yields_one_confirmed_finding():
    svc = _FakeService(banner=b"SSH-2.0-OpenSSH_8.9p1\r\n")
    control = _free_closed_port()
    try:
        findings = _scan(
            "127.0.0.1",
            [svc.port],
            [svc.port, control],
            engagement_id="eng-1",
            application="demo",
            service_map={svc.port: ("ssh", "high")},
        )
    finally:
        svc.close()

    assert len(findings) == 1
    f = findings[0]
    assert f.engagement_id == "eng-1"
    assert f.vuln_class == "EXPOSED_SERVICE"
    assert f.severity == "high"
    assert f.confidence == "confirmed"
    assert f.state == State.VALIDATED
    assert f.verification.validated is True
    assert f.verification.method == "tcp-connect-probe"
    assert f.verification.reproductions >= 2
    assert f.verification.independent_reproduction is True
    assert str(svc.port) in f.asset["target"]
    assert str(svc.port) in f.endpoint["url"]
    assert str(svc.port) in f.title
    assert "CWE-284" in f.cwe and "CWE-668" in f.cwe
    # the negative control used the IN-SCOPE closed port.
    assert any("negative control" in c and f":{control}" in c for c in f.verification.false_positive_checks)
    assert any("protocol" in c for c in f.verification.false_positive_checks)
    f.assert_consistent()


def test_silent_service_is_still_confirmed_by_reachability():
    svc = _FakeService(banner=b"")
    control = _free_closed_port()
    try:
        findings = _scan(
            "127.0.0.1", [svc.port], [svc.port, control], service_map={svc.port: ("test-redis", "high")}
        )
    finally:
        svc.close()
    assert len(findings) == 1
    assert findings[0].confidence == "confirmed"
    assert findings[0].verification.validated is True


def test_without_in_scope_control_port_finding_is_firm_not_confirmed():
    # The scope authorizes only the sensitive port itself: no spare port may be touched as a
    # control, so an accept-all host cannot be ruled out -> firm, unvalidated.
    svc = _FakeService(banner=b"")
    try:
        findings = _scan("127.0.0.1", [svc.port], [svc.port], service_map={svc.port: ("test-svc", "high")})
    finally:
        svc.close()
    assert len(findings) == 1
    f = findings[0]
    assert f.confidence == "firm"
    assert f.verification.validated is False
    assert any("NO negative control" in c for c in f.verification.false_positive_checks)
    f.assert_consistent()


def test_accept_all_host_yields_no_finding():
    # Both the sensitive port and the in-scope control port answer -> tarpit -> nothing.
    svc = _FakeService(banner=b"")
    ctrl = _FakeService(banner=b"")
    try:
        findings = _scan(
            "127.0.0.1", [svc.port], [svc.port, ctrl.port], service_map={svc.port: ("test-svc", "high")}
        )
    finally:
        svc.close()
        ctrl.close()
    assert findings == []


# --------------------------------------------------------------------------- no false positives
def test_closed_port_yields_no_finding():
    port = _free_closed_port()
    findings = _scan("127.0.0.1", [port], [port], service_map={port: ("test-svc", "high")})
    assert findings == []


def test_open_but_non_sensitive_port_is_ignored():
    svc = _FakeService(banner=b"hello")
    try:
        findings = _scan("127.0.0.1", [svc.port], [svc.port], service_map={})
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
        scope=_scope([22, 3306, 6379], host="192.0.2.1", allow=("192.0.2.0/24",)),
        resolver=lambda h: ["192.0.2.1"],
        service_map={22: ("ssh", "medium"), 3306: ("mysql", "high"), 6379: ("redis", "high")},
    )
    assert findings == []


def test_empty_inputs_are_graceful():
    assert scan_infra("", [22]) == []
    assert scan_infra("127.0.0.1", []) == []


# --------------------------------------------------------------------------- scope gating (C-2)
def test_no_scope_refuses_without_any_connection(monkeypatch):
    log = _ConnectLog(monkeypatch)
    svc = _FakeService(banner=b"")
    try:
        out = scan_infra("127.0.0.1", [svc.port], service_map={svc.port: ("test-svc", "high")})
    finally:
        svc.close()
    assert out == []
    assert log.ports == []
    assert "no scope" in skip_reason_of(out)


def test_only_scoped_ports_are_ever_connected(monkeypatch):
    """Regression for C-2: the catalogue of ~20 well-known ports + a hard-coded control port
    (59991) used to be connected to regardless of the scope's port list."""
    log = _ConnectLog(monkeypatch)
    svc = _FakeService(banner=b"")
    control = _free_closed_port()
    try:
        out = _scan(
            "127.0.0.1",
            sorted(set(SENSITIVE_SERVICES) | {443, 8443, svc.port}),
            [svc.port, control],
            service_map={**SENSITIVE_SERVICES, svc.port: ("test", "high")},
        )
    finally:
        svc.close()
    assert len(out) == 1 and out[0].confidence == "confirmed"
    assert set(log.ports) <= {svc.port, control}, log.ports
    assert 59991 not in log.ports and 22 not in log.ports and 6379 not in log.ports
    assert any("not authorized" in n for n in out.notes)


def test_default_catalogue_is_intersected_with_scope(monkeypatch):
    log = _ConnectLog(monkeypatch)
    out = _scan("127.0.0.1", None, [_free_closed_port()])
    assert out == []
    assert log.ports == []  # no catalogued port is in scope -> nothing probed, not even a control


def test_explicit_control_ports_outside_scope_are_ignored(monkeypatch):
    log = _ConnectLog(monkeypatch)
    svc = _FakeService(banner=b"")
    try:
        out = _scan(
            "127.0.0.1",
            [svc.port],
            [svc.port],
            control_ports=[59991],
            service_map={svc.port: ("test", "high")},
        )
    finally:
        svc.close()
    assert 59991 not in log.ports
    assert len(out) == 1 and out[0].confidence == "firm"


def test_fail_closed_when_scope_disallows_ip(monkeypatch):
    log = _ConnectLog(monkeypatch)
    out = scan_infra(
        "app.example.test",
        [22],
        resolver=lambda h: ["127.0.0.1"],
        scope=_scope([22], host="app.example.test", allow=("10.0.0.0/8",)),
        service_map={22: ("ssh", "medium")},
    )
    assert out == [] and log.ports == []
    assert "resolved_ip_allowlist" in skip_reason_of(out)


def test_any_resolved_ip_out_of_scope_fails_closed(monkeypatch):
    log = _ConnectLog(monkeypatch)
    out = scan_infra(
        "app.example.test",
        [22],
        resolver=lambda h: ["127.0.0.1", "10.1.2.3"],
        scope=_scope([22], host="app.example.test"),
        service_map={22: ("ssh", "medium")},
    )
    assert out == [] and log.ports == []


def test_host_not_in_scope_fails_closed(monkeypatch):
    log = _ConnectLog(monkeypatch)
    out = scan_infra(
        "other.example.test",
        [22],
        resolver=_loopback,
        scope=_scope([22], host="app.example.test"),
        service_map={22: ("ssh", "medium")},
    )
    assert out == [] and log.ports == []
    assert "not in scope" in skip_reason_of(out)


def test_scope_given_without_resolver_fails_closed(monkeypatch):
    log = _ConnectLog(monkeypatch)
    out = scan_infra("127.0.0.1", [22], scope=_scope([22]), service_map={22: ("ssh", "medium")})
    assert out == [] and log.ports == []


def test_scope_allowed_ip_is_probed_and_confirmed():
    svc = _FakeService(banner=b"")
    control = _free_closed_port()
    try:
        findings = _scan(
            "host.example.test", [svc.port], [svc.port, control], service_map={svc.port: ("test-svc", "high")}
        )
    finally:
        svc.close()
    assert len(findings) == 1
    assert findings[0].verification.validated is True
    assert "host.example.test" in findings[0].asset["target"]


# --------------------------------------------------------------------------- audit / budget (C-11)
def test_every_connect_is_audited_and_budgeted(tmp_path):
    from rampart.audit import AuditLog
    from rampart.policy.budget import BudgetTracker
    from rampart.schemas.scope import Limits

    audit = AuditLog(str(tmp_path / "audit.jsonl"))
    budget = BudgetTracker(Limits())
    svc = _FakeService(banner=b"")
    control = _free_closed_port()
    try:
        out = _scan(
            "127.0.0.1",
            [svc.port],
            [svc.port, control],
            engagement_id="ENG-9",
            audit=audit,
            budget=budget,
            service_map={svc.port: ("test", "high")},
        )
    finally:
        svc.close()
    assert len(out) == 1
    events = audit.read_all()
    # probe + reproduction + negative control = 3 connects, one event each
    assert len(events) == 3
    assert {e.action["purpose"] for e in events} == {"probe", "reproduction", "negative-control"}
    assert all(e.engagement_id == "ENG-9" and e.action["tool"] == "infra-scan" for e in events)
    assert budget.total_requests == 3
    assert audit.verify_chain()[0]


def test_killed_budget_stops_before_any_connect(monkeypatch):
    from rampart.policy.budget import BudgetTracker
    from rampart.schemas.scope import Limits

    log = _ConnectLog(monkeypatch)
    budget = BudgetTracker(Limits())
    budget.kill("operator stop")
    svc = _FakeService(banner=b"")
    try:
        out = _scan("127.0.0.1", [svc.port], [svc.port], budget=budget, service_map={svc.port: ("t", "high")})
    finally:
        svc.close()
    assert out == [] and log.ports == []
