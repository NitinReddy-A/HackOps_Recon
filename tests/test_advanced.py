"""Advanced classes (Phase 3). Host-header injection (safe GET+header, deterministic)."""
from conftest import make_engagement
from rampart.schemas.finding import State


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
