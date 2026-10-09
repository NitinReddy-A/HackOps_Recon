"""Tests for the OPTIONAL gRPC security-scan module (rampart/grpc_scan).

No real gRPC server and no grpcio are required. The network half (_list_services) is factored
behind a monkeypatchable seam, and the "grpcio absent" degradation is the default state of the
test environment (grpcio is intentionally NOT installed). These pass whether or not grpcio
happens to be present on the host.
"""

import rampart.grpc_scan.scan as scan_mod
from rampart.grpc_scan import available, is_grpc_response, scan_grpc, scan_grpc_methods
from rampart.grpc_scan.scan import _is_read_method, _reflection_finding


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
    monkeypatch.setattr(
        scan_mod, "_list_services", lambda host, port, scheme, timeout=8.0: ["pkg.A", "pkg.B"]
    )
    findings = scan_grpc("h", 50051, "grpc", "app", "http://h:50051")
    refl = [f for f in findings if f.vuln_class == "information-disclosure"]
    assert len(refl) == 1
    f = refl[0]
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


# ===================================================================== per-RPC method scanning
# All of the following monkeypatch the two NEW network seams (_list_methods / _invoke_method) so
# neither a live gRPC server nor grpcio is ever required (same discipline as the existing tests).


def _m(svc, method, **extra):
    """Build one method dict as _list_methods would return it."""
    d = {
        "service": svc,
        "method": method,
        "full_method": f"/{svc}/{method}",
        "input_type": "",
        "output_type": "",
    }
    d.update(extra)
    return d


# --------------------------------------------------------------------- read/mutate classification
def test_is_read_method_classification():
    for ok in (
        "GetUser",
        "ListAccounts",
        "DescribeNode",
        "QueryLogs",
        "SearchDocs",
        "HealthCheck",
        "WatchStatus",
        "CountItems",
        "ExistsKey",
        "readConfig",
    ):
        assert _is_read_method(ok) is True, ok
    # mutating prefixes always lose — fail-closed so writes are never auto-invoked.
    for bad in (
        "CreateUser",
        "UpdateAccount",
        "DeleteUser",
        "SetConfig",
        "RemoveKey",
        "RotateSecret",
        "RevokeToken",
        "DropTable",
        "PurgeCache",
        "ResetState",
    ):
        assert _is_read_method(bad) is False, bad
    # neither prefix -> not read (so not invoked under read_only)
    assert _is_read_method("DoSomething") is False
    assert _is_read_method("") is False


# --------------------------------------------------------------------- reflection now lists methods
def test_scan_grpc_reflection_description_mentions_methods(monkeypatch):
    monkeypatch.setattr(scan_mod, "_list_services", lambda host, port, scheme, timeout=8.0: ["pkg.A"])
    monkeypatch.setattr(
        scan_mod, "_list_methods", lambda host, port, scheme, timeout=8.0: [_m("pkg.A", "GetThing")]
    )
    findings = scan_grpc("h", 50051, "grpc", "app", "http://h:50051")  # active defaults False
    # reflection exposure + the PASSIVE plaintext-transport observation (scheme 'grpc'); no invocation
    assert sorted(f.vuln_class for f in findings) == ["GRPC_PLAINTEXT", "information-disclosure"]
    f = [x for x in findings if x.vuln_class == "information-disclosure"][0]
    assert f.vuln_class == "information-disclosure"
    assert "CWE-200" in f.cwe
    assert "pkg.A" in f.description
    assert "/pkg.A/GetThing" in f.description  # methods now enriched into the description
    f.assert_consistent()


def test_reflection_finding_unchanged_when_methods_none():
    # methods=None must be byte-for-byte the original service-only finding.
    base = _reflection_finding(["pkg.A", "pkg.B"], "app", "http://h:50051")
    assert "/pkg." not in base.description  # no method lines
    assert len(base.evidence) == 1


# --------------------------------------------------------------------- confirmed unauth (oracle)
def test_active_unauth_confirmed_with_negative_control(monkeypatch):
    methods = [_m("pkg.UserService", "GetUser"), _m("pkg.AdminService", "GetAdminSettings")]
    monkeypatch.setattr(scan_mod, "_list_methods", lambda host, port, scheme, timeout=8.0: methods)

    def fake_invoke(host, port, scheme, full_method, metadata=None, request_bytes=b"", timeout=8.0):
        # unauthenticated: a read method is OPEN, the admin read method is properly GATED (control).
        if full_method == "/pkg.UserService/GetUser":
            return {"code": "OK", "ok": True, "response_len": 42, "details": ""}
        return {"code": "UNAUTHENTICATED", "ok": False, "response_len": 0, "details": "auth required"}

    monkeypatch.setattr(scan_mod, "_invoke_method", fake_invoke)
    findings = scan_grpc_methods("h", 50051, "grpc", "app", "http://h:50051", active=True)
    unauth = [f for f in findings if f.vuln_class == "GRPC_UNAUTH_METHOD"]
    assert len(unauth) == 1
    f = unauth[0]
    assert f.confidence == "confirmed"
    assert f.state == scan_mod.State.VALIDATED
    assert f.verification.validated is True
    assert f.verification.independent_reproduction is True
    assert f.verification.reproductions >= 2
    assert f.verification.method == "grpc-unauth-invoke"
    assert set(f.cwe) == {"CWE-306", "CWE-285"}
    assert "/pkg.UserService/GetUser" in f.description
    assert len(f.verification.false_positive_checks) >= 3  # control + 2 reproductions
    f.assert_consistent()


# --------------------------------------------------------------------- firm (no negative control)
def test_active_unauth_all_open_is_firm_not_confirmed(monkeypatch):
    methods = [_m("pkg.S", "GetUser"), _m("pkg.S", "ListThings")]
    monkeypatch.setattr(scan_mod, "_list_methods", lambda host, port, scheme, timeout=8.0: methods)
    monkeypatch.setattr(
        scan_mod,
        "_invoke_method",
        lambda *a, **k: {"code": "OK", "ok": True, "response_len": 10, "details": ""},
    )
    findings = scan_grpc_methods("h", 50051, "grpc", "app", "http://h:50051", active=True)
    unauth = [f for f in findings if f.vuln_class == "GRPC_UNAUTH_METHOD"]
    assert len(unauth) == 1
    f = unauth[0]
    assert f.confidence == "firm"
    assert f.verification.validated is False
    assert f.state == scan_mod.State.EVIDENCE_FOUND


# --------------------------------------------------------------------- all gated => no finding
def test_active_unauth_all_gated_produces_no_unauth_finding(monkeypatch):
    methods = [_m("pkg.S", "GetUser"), _m("pkg.S", "ListThings")]
    monkeypatch.setattr(scan_mod, "_list_methods", lambda host, port, scheme, timeout=8.0: methods)
    monkeypatch.setattr(
        scan_mod,
        "_invoke_method",
        lambda *a, **k: {"code": "UNAUTHENTICATED", "ok": False, "response_len": 0, "details": "nope"},
    )
    findings = scan_grpc_methods("h", 50051, "grpc", "app", "http://h:50051", active=True)
    assert [f for f in findings if f.vuln_class == "GRPC_UNAUTH_METHOD"] == []


# --------------------------------------------------------------------- NON-DESTRUCTIVE by default
def test_inactive_never_invokes_any_method(monkeypatch):
    monkeypatch.setattr(
        scan_mod, "_list_methods", lambda host, port, scheme, timeout=8.0: [_m("pkg.S", "GetUser")]
    )

    def boom(*a, **k):
        raise AssertionError("_invoke_method must NOT be called when active=False")

    monkeypatch.setattr(scan_mod, "_invoke_method", boom)
    findings = scan_grpc_methods("h", 50051, "grpc", "app", "http://h:50051", active=False)
    # no exception => invoke was never reached; and no unauth finding is produced.
    assert [f for f in findings if f.vuln_class == "GRPC_UNAUTH_METHOD"] == []


def test_active_never_invokes_mutating_methods(monkeypatch):
    methods = [_m("pkg.S", "GetUser"), _m("pkg.S", "DeleteUser"), _m("pkg.S", "CreateUser")]
    monkeypatch.setattr(scan_mod, "_list_methods", lambda host, port, scheme, timeout=8.0: methods)
    calls = []

    def recording_invoke(host, port, scheme, full_method, metadata=None, request_bytes=b"", timeout=8.0):
        calls.append(full_method)
        return {"code": "OK", "ok": True, "response_len": 5, "details": ""}

    monkeypatch.setattr(scan_mod, "_invoke_method", recording_invoke)
    scan_grpc_methods("h", 50051, "grpc", "app", "http://h:50051", active=True)
    assert "/pkg.S/DeleteUser" not in calls  # mutating never invoked
    assert "/pkg.S/CreateUser" not in calls
    assert "/pkg.S/GetUser" in calls  # read-ish IS invoked


# --------------------------------------------------------------------- plaintext transport
def test_plaintext_finding_for_insecure_scheme(monkeypatch):
    monkeypatch.setattr(
        scan_mod, "_list_methods", lambda host, port, scheme, timeout=8.0: [_m("pkg.S", "GetUser")]
    )
    findings = scan_grpc_methods("h", 50051, "grpc", "app", "http://h:50051", active=False)
    plain = [f for f in findings if f.vuln_class == "GRPC_PLAINTEXT"]
    assert len(plain) == 1
    assert "CWE-319" in plain[0].cwe
    assert plain[0].confidence == "firm"


def test_no_plaintext_finding_for_tls_scheme(monkeypatch):
    monkeypatch.setattr(
        scan_mod, "_list_methods", lambda host, port, scheme, timeout=8.0: [_m("pkg.S", "GetUser")]
    )
    findings = scan_grpc_methods("h", 50051, "grpcs", "app", "https://h:50051", active=False)
    assert [f for f in findings if f.vuln_class == "GRPC_PLAINTEXT"] == []


def test_scan_grpc_methods_empty_when_no_methods(monkeypatch):
    monkeypatch.setattr(scan_mod, "_list_methods", lambda *a, **k: [])
    assert scan_grpc_methods("h", 50051, "grpc", "app", "http://h:50051", active=True) == []


def test_scan_grpc_methods_graceful_when_list_methods_raises(monkeypatch):
    def _boom(*a, **k):
        raise RuntimeError("no grpcio / unreachable")

    monkeypatch.setattr(scan_mod, "_list_methods", _boom)
    assert scan_grpc_methods("h", 50051, "grpc", "app", "http://h:50051", active=True) == []


# --------------------------------------------------------------------- scan_grpc active wiring
def test_scan_grpc_active_extends_with_method_findings(monkeypatch):
    monkeypatch.setattr(
        scan_mod, "_list_services", lambda host, port, scheme, timeout=8.0: ["pkg.UserService"]
    )
    monkeypatch.setattr(
        scan_mod,
        "_list_methods",
        lambda host, port, scheme, timeout=8.0: [
            _m("pkg.UserService", "GetUser"),
            _m("pkg.UserService", "GetAdmin"),
        ],
    )

    def fake_invoke(host, port, scheme, full_method, metadata=None, request_bytes=b"", timeout=8.0):
        if full_method == "/pkg.UserService/GetUser":
            return {"code": "OK", "ok": True, "response_len": 7, "details": ""}
        return {"code": "PERMISSION_DENIED", "ok": False, "response_len": 0, "details": "denied"}

    monkeypatch.setattr(scan_mod, "_invoke_method", fake_invoke)
    findings = scan_grpc("h", 50051, "grpc", "app", "http://h:50051", active=True)
    classes = {f.vuln_class for f in findings}
    assert "information-disclosure" in classes  # reflection exposure
    assert "GRPC_PLAINTEXT" in classes  # plaintext transport
    assert "GRPC_UNAUTH_METHOD" in classes  # confirmed unauth (GetUser open, GetAdmin gated)
    for f in findings:
        f.assert_consistent()


# --------------------------------------------------------------------- C-7 read classifier
def test_read_classifier_rejects_mutating_words_anywhere():
    for name in (
        "Checkout",
        "CheckoutCart",
        "GetOrCreateUser",
        "get_or_create_user",
        "ReadAndDelete",
        "QueryAndPurge",
        "HealthReset",
        "ListAndDrop",
        "Getaway",  # first word must be EXACTLY a read verb
        "Lister",
        "CountAndIncrement",
        "FetchThenSend",
        "SearchAndTransfer",
        "StatusSet",
    ):
        assert _is_read_method(name) is False, name


def test_read_classifier_accepts_plain_reads():
    for name in (
        "GetUser",
        "ListOrders",
        "list_orders",
        "Check",
        "HealthCheck",
        "Ping",
        "Watch",
        "DescribeTable",
        "FindById",
        "LookupHTTPRoute",
        "ShowStatus",
        "ViewProfile",
        "Status",
    ):
        assert _is_read_method(name) is True, name


def test_active_never_invokes_compound_mutators(monkeypatch):
    methods = [_m("pkg.S", n) for n in ("GetOrCreateUser", "CheckoutCart", "HealthReset", "GetUser")]
    monkeypatch.setattr(scan_mod, "_list_methods", lambda host, port, scheme, timeout=8.0: methods)
    calls = []

    def rec(host, port, scheme, full_method, metadata=None, request_bytes=b"", timeout=8.0):
        calls.append(full_method)
        return {"code": "OK", "ok": True, "response_len": 1, "details": ""}

    monkeypatch.setattr(scan_mod, "_invoke_method", rec)
    scan_grpc_methods("h", 50051, "grpc", "app", "http://h:50051", active=True)
    assert set(calls) == {"/pkg.S/GetUser"}


# --------------------------------------------------------------------- C-12 engagement id / passive
def _fake_invoke_x_open(h, p, s, full, **k):
    is_x = full.endswith("GetX")
    return {"code": "OK" if is_x else "UNAUTHENTICATED", "ok": is_x, "response_len": 3, "details": ""}


def test_scan_grpc_stamps_engagement_id_and_plaintext_is_passive(monkeypatch):
    monkeypatch.setattr(scan_mod, "_list_services", lambda host, port, scheme, timeout=8.0: ["pkg.A"])
    monkeypatch.setattr(
        scan_mod, "_list_methods", lambda host, port, scheme, timeout=8.0: [_m("pkg.A", "GetX")]
    )

    def boom(*a, **k):
        raise AssertionError("passive scan must not invoke RPCs")

    monkeypatch.setattr(scan_mod, "_invoke_method", boom)
    findings = scan_grpc("h", 50051, "grpc", "app", "http://h:50051", engagement_id="ENG-42")
    assert {f.vuln_class for f in findings} == {"information-disclosure", "GRPC_PLAINTEXT"}
    assert all(f.engagement_id == "ENG-42" for f in findings)


def test_scan_grpc_active_engagement_id_on_method_findings(monkeypatch):
    monkeypatch.setattr(scan_mod, "_list_services", lambda host, port, scheme, timeout=8.0: ["pkg.A"])
    monkeypatch.setattr(
        scan_mod,
        "_list_methods",
        lambda host, port, scheme, timeout=8.0: [_m("pkg.A", "GetX"), _m("pkg.A", "GetY")],
    )
    monkeypatch.setattr(scan_mod, "_invoke_method", _fake_invoke_x_open)
    findings = scan_grpc("h", 50051, "grpc", "app", "http://h:50051", active=True, engagement_id="E1")
    assert "GRPC_UNAUTH_METHOD" in {f.vuln_class for f in findings}
    assert all(f.engagement_id == "E1" for f in findings)
    assert [f.vuln_class for f in findings].count("GRPC_PLAINTEXT") == 1  # no duplicate


# --------------------------------------------------------------------- C-13 structured skip
def test_scan_grpc_missing_dependency_has_skip_reason(monkeypatch):
    def _missing(*a, **k):
        raise ImportError("No module named 'grpc'")

    monkeypatch.setattr(scan_mod, "_list_services", _missing)
    out = scan_grpc("h", 50051, "grpc", "app", "http://h:50051")
    assert out == []
    assert out.skip_reason == "grpc: skipped — pip install rampart-appsec[grpc]"


# --------------------------------------------------------------------- scope + audit/budget (C-11)
def _gscope(ports):
    from rampart.schemas.scope import EngagementScope

    return EngagementScope.from_dict(
        {
            "kind": "EngagementScope",
            "scope": {
                "in_scope": [{"host": "127.0.0.1", "ports": list(ports)}],
                "resolved_ip_allowlist": ["127.0.0.1/32"],
            },
        }
    )


def _loop(_h):
    return ["127.0.0.1"]


def test_scan_grpc_refuses_port_not_in_scope(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("no channel may be opened for an out-of-scope port")

    monkeypatch.setattr(scan_mod, "_list_services", boom)
    out = scan_grpc("127.0.0.1", 50051, "grpc", "app", "", scope=_gscope([8080]), resolver=_loop)
    assert out == [] and "not authorized" in out.skip_reason


def test_scan_grpc_audits_each_rpc_and_honours_kill(monkeypatch, tmp_path):
    from rampart.audit import AuditLog
    from rampart.policy.budget import BudgetTracker
    from rampart.schemas.scope import Limits

    monkeypatch.setattr(scan_mod, "_list_services", lambda host, port, scheme, timeout=8.0: ["pkg.A"])
    monkeypatch.setattr(
        scan_mod,
        "_list_methods",
        lambda host, port, scheme, timeout=8.0: [_m("pkg.A", "GetX"), _m("pkg.A", "GetY")],
    )
    monkeypatch.setattr(scan_mod, "_invoke_method", _fake_invoke_x_open)
    audit = AuditLog(str(tmp_path / "a.jsonl"))
    budget = BudgetTracker(Limits())
    kw = {"scope": _gscope([50051]), "resolver": _loop, "active": True}
    scan_grpc("127.0.0.1", 50051, "grpc", "app", "", engagement_id="E", audit=audit, budget=budget, **kw)
    events = audit.read_all()
    # list_services + method enumeration + 2 invocations + 1 reproduction = 5 RPC admissions
    assert len(events) == 5
    assert budget.total_requests == 5
    assert all(e.action["kind"] == "grpc-rpc" and e.engagement_id == "E" for e in events)

    budget.kill("stop")
    out = scan_grpc("127.0.0.1", 50051, "grpc", "app", "", budget=budget, **kw)
    assert out == [] and "kill-switch" in out.skip_reason
