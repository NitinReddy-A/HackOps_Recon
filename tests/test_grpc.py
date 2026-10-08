"""Tests for the OPTIONAL gRPC security-scan module (rampart/grpc_scan).

No real gRPC server and no grpcio are required. The network half (_list_services) is factored
behind a monkeypatchable seam, and the "grpcio absent" degradation is the default state of the
test environment (grpcio is intentionally NOT installed). These pass whether or not grpcio
happens to be present on the host.
"""
import rampart.grpc_scan.scan as scan_mod
from rampart.grpc_scan import available, is_grpc_response, scan_grpc
from rampart.grpc_scan.scan import _reflection_finding


# --------------------------------------------------------------------- is_grpc_response
def test_is_grpc_response_true_for_grpc_content_types():
    assert is_grpc_response({"Content-Type": "application/grpc"}) is True
    assert is_grpc_response({"content-type": "application/grpc+proto"}) is True
    assert is_grpc_response({"Content-Type": "application/grpc-web"}) is True
    assert is_grpc_response({"content-type": "application/grpc-web-text"}) is True
    assert is_grpc_response({"CONTENT-TYPE": "grpc-web-text"}) is True


def test_is_grpc_response_true_for_grpc_status_header():
    assert is_grpc_response({"grpc-status": "0"}) is True
    assert is_grpc_response({"Grpc-Status": "12"}) is True


def test_is_grpc_response_false_for_non_grpc():
    assert is_grpc_response({"Content-Type": "text/html"}) is False
    assert is_grpc_response({"content-type": "application/json"}) is False
    assert is_grpc_response({}) is False
    assert is_grpc_response(None) is False


# --------------------------------------------------------------------- _reflection_finding (pure)
def test_reflection_finding_confirmed_cwe200_lists_services():
    f = _reflection_finding(["pkg.Service1", "pkg.Service2"], "app", "http://h:50051")
    assert "CWE-200" in f.cwe
    assert f.verification.validated is True
    assert f.verification.method == "grpc-reflection"
    assert f.verification.validator == "grpc-reflection"
    assert f.confidence == "confirmed"
    assert "pkg.Service1" in f.description
    assert "pkg.Service2" in f.description
    # the trust primitive: confirmed is only legal with validated=True
    f.assert_consistent()


# --------------------------------------------------------------------- scan_grpc seam
def test_scan_grpc_returns_finding_when_reflection_lists_services(monkeypatch):
    monkeypatch.setattr(scan_mod, "_list_services",
                        lambda host, port, scheme, timeout=8.0: ["pkg.A", "pkg.B"])
    findings = scan_grpc("h", 50051, "grpc", "app", "http://h:50051")
    assert len(findings) == 1
    f = findings[0]
    assert "CWE-200" in f.cwe
    assert f.verification.validated is True
    assert "pkg.A" in f.description and "pkg.B" in f.description


def test_scan_grpc_graceful_when_list_services_raises(monkeypatch):
    def _boom(*a, **k):
        raise RuntimeError("no grpcio / unreachable server")

    monkeypatch.setattr(scan_mod, "_list_services", _boom)
    assert scan_grpc("h", 50051, "grpc", "app", "http://h:50051") == []


def test_scan_grpc_returns_empty_when_no_services(monkeypatch):
    monkeypatch.setattr(scan_mod, "_list_services", lambda *a, **k: [])
    assert scan_grpc("h", 50051, "grpc", "app", "http://h:50051") == []


# --------------------------------------------------------------------- graceful import / availability
def test_module_imports_cleanly_without_grpcio():
    # Importing must never require grpcio (all grpc imports are lazy, inside functions).
    assert scan_mod is not None
    assert hasattr(scan_mod, "scan_grpc")


def test_available_returns_bool_without_raising():
    # Honours the real environment: returns a bool and never raises, grpcio present or not.
    val = available()
    assert isinstance(val, bool)
