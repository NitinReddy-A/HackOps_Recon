"""P0 coverage wave: JWT (alg=none), SSTI, sensitive-file exposure, clickjacking, insecure cookie."""

from conftest import make_engagement

from rampart.schemas.finding import State


def _confirmed(findings):
    return {f.vuln_class for f in findings if f.verification.validated}


def _titles(findings, vuln_class):
    return [f.title for f in findings if f.vuln_class == vuln_class and f.verification.validated]


def test_vuln_target_confirms_p0_classes(tmp_path, vuln_server):
    findings = make_engagement(tmp_path, vuln_server.port).run_scan().findings
    classes = _confirmed(findings)
    assert "JWT" in classes
    assert "SSTI" in classes
    assert "sensitive-file-exposure" in classes
    # misconfig family now includes clickjacking + insecure cookie
    misc = " ".join(_titles(findings, "security-misconfiguration"))
    assert "Clickjacking" in misc
    assert "cookie" in misc.lower()
    # JWT + SSTI are rated critical
    jwt = next(f for f in findings if f.vuln_class == "JWT" and f.verification.validated)
    ssti = next(f for f in findings if f.vuln_class == "SSTI" and f.verification.validated)
    assert jwt.severity == "critical" and ssti.severity == "critical"
    # several sensitive files found by content signature
    assert len(_titles(findings, "sensitive-file-exposure")) >= 3


def test_fixed_target_drops_p0_classes(tmp_path, fixed_server):
    findings = make_engagement(tmp_path, fixed_server.port).run_scan().findings
    assert not [f for f in findings if f.verification.validated]
    for cls in ("JWT", "SSTI"):
        assert any(f.vuln_class == cls and f.state == State.DROPPED for f in findings)
    # no sensitive files confirmed when they 404
    assert not [f for f in findings if f.vuln_class == "sensitive-file-exposure"]


def test_jwt_forgery_is_proven_not_guessed(tmp_path, vuln_server):
    findings = make_engagement(tmp_path, vuln_server.port).run_scan().findings
    jwt = next(f for f in findings if f.vuln_class == "JWT" and f.verification.validated)
    assert jwt.verification.reproductions >= 2
    # the proof must show auth was still enforced (so the defect is signature verification)
    proof = " ".join(jwt.verification.false_positive_checks)
    assert "unauthenticated" in proof.lower() or "rejected" in proof.lower()


def test_soc2_report_generates(tmp_path, vuln_server):
    eng = make_engagement(tmp_path, vuln_server.port)
    eng.run_scan()
    written, rb, _ = eng.report(["soc2"])
    assert "soc2" in written
    text = rb.to_soc2()
    assert "Trust Services Criteria" in text or "TSC" in text
    assert "attestation" in text and "licensed CPA firm" in text  # honest disclaimer present
    assert "CC6.1" in text  # control mapping present
