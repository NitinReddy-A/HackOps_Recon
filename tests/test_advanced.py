"""Advanced classes (Phase 3): host-header injection, and write-side (mass assignment / GraphQL)
behind the --active gate."""
from conftest import make_engagement, write_engagement
from rampart.engagement import Engagement, EngagementConfig
from rampart.schemas.finding import State


def _active_eng(tmp_path, port):
    scope = write_engagement(tmp_path, port)
    cfg = EngagementConfig(scope_file=scope, target=f"http://127.0.0.1:{port}",
                           work_dir=str(tmp_path / ".rampart"),
                           openapi=str(tmp_path / "openapi.json"), appmodel_seed=str(tmp_path / "seed.json"),
                           application="demo-shop-api", active=True)
    return Engagement(cfg)


def test_host_header_injection_confirmed(tmp_path, vuln_server):
    findings = make_engagement(tmp_path, vuln_server.port).run_scan().findings
    hhi = [f for f in findings if f.vuln_class == "HOST_HEADER_INJECTION" and f.verification.validated]
    assert hhi, "host-header injection should be confirmed on /api/reset"
    assert "/api/reset" in hhi[0].endpoint["url"]
    assert hhi[0].verification.reproductions >= 2
    hhi[0].assert_consistent()


def test_host_header_injection_clean_on_fixed(tmp_path, fixed_server):
    findings = make_engagement(tmp_path, fixed_server.port).run_scan().findings
    assert not [f for f in findings if f.vuln_class == "HOST_HEADER_INJECTION" and f.verification.validated]
    assert [f for f in findings if f.vuln_class == "HOST_HEADER_INJECTION" and f.state == State.DROPPED]


def test_write_classes_gated_off_without_active(tmp_path, vuln_server):
    result = make_engagement(tmp_path, vuln_server.port).run_scan()
    classes = {h["vuln_class"] for h in result.hypotheses}
    assert "MASS_ASSIGNMENT" not in classes and "GRAPHQL" not in classes   # safe by default


def test_active_confirms_mass_assignment_and_graphql(tmp_path, vuln_server):
    findings = _active_eng(tmp_path, vuln_server.port).run_scan().findings
    confirmed = {f.vuln_class for f in findings if f.verification.validated}
    assert "MASS_ASSIGNMENT" in confirmed, "mass assignment should be confirmed in --active mode"
    assert "GRAPHQL" in confirmed, "GraphQL introspection should be confirmed in --active mode"
    ma = next(f for f in findings if f.vuln_class == "MASS_ASSIGNMENT" and f.verification.validated)
    assert ma.endpoint["method"] == "POST"
    ma.assert_consistent()


def test_smuggling_indicator_detects_proxy_and_is_never_confirmed():
    from rampart.scanners.misconfig import proxy_indicators
    assert proxy_indicators({"via": "1.1 varnish", "server": "nginx"}) == ["via"]
    assert proxy_indicators({"x-cache": "HIT", "cf-ray": "abc"}) == ["cf-ray", "x-cache"]
    assert proxy_indicators({"server": "nginx", "content-type": "text/html"}) == []   # no false alarm


def test_no_smuggling_indicator_on_plain_demo(tmp_path, vuln_server):
    # the demo has no intermediary -> no smuggling indicator (fires only on real proxy stacks)
    findings = make_engagement(tmp_path, vuln_server.port).run_scan().findings
    assert not [f for f in findings if f.vuln_class == "request-smuggling-indicator"]


def test_active_writes_are_approved_and_audited(tmp_path, vuln_server):
    eng = _active_eng(tmp_path, vuln_server.port)
    eng.run_scan()
    ok, msg = eng.audit.verify_chain()
    assert ok, msg
    # the write probes were POSTs that passed the Tier-2 approval path
    assert any((e.action or {}).get("method") == "POST" for e in eng.audit.read_all())
