"""Acceptance tests for the gap-closure build: deep auth, business logic, compliance matrix,
and SCA exploit-intelligence enrichment. Auth/bizlogic run against the live demo target."""
import os

import pytest

from conftest import write_engagement
from rampart.engagement import Engagement, EngagementConfig
from rampart.schemas.finding import Finding, State, Verification


def _engagement(tmp_path, port, **flags):
    scope_file = write_engagement(tmp_path, port)
    cfg = EngagementConfig(
        scope_file=scope_file, target=f"http://127.0.0.1:{port}",
        work_dir=str(tmp_path / ".rampart"),
        openapi=str(tmp_path / "openapi.json"),
        appmodel_seed=str(tmp_path / "seed.json"),
        application="demo-shop-api", **flags)
    return Engagement(cfg)


# ------------------------------------------------------------------- deep auth (JWT weak secret)
def test_authz_confirms_weak_jwt_secret(tmp_path, vuln_server):
    eng = _engagement(tmp_path, vuln_server.port, authz=True)
    findings = eng.run_authz()
    weak = [f for f in findings if f.vuln_class == "WEAK_JWT_SECRET"]
    assert weak, "expected a confirmed weak-JWT-secret finding on /api/v2/me"
    f = weak[0]
    assert "/api/v2/me" in f.endpoint.get("url", "")
    assert f.confidence == "confirmed" and f.verification.validated
    assert f.verification.reproductions >= 2
    assert "jwt-expiry" in f.tags       # VULN /api/v2/me also ignores exp
    f.assert_consistent()


def test_authz_clean_on_fixed(tmp_path, fixed_server):
    eng = _engagement(tmp_path, fixed_server.port, authz=True)
    weak = [f for f in eng.run_authz() if f.vuln_class == "WEAK_JWT_SECRET"]
    assert not weak, "strong secret + exp enforcement must not be flagged"


# ------------------------------------------------------- business logic (economic tampering)
def test_bizlogic_confirms_economic_tampering(tmp_path, vuln_server):
    eng = _engagement(tmp_path, vuln_server.port, bizlogic=True)
    findings = eng.run_bizlogic()
    econ = [f for f in findings if f.vuln_class == "BUSINESS_LOGIC_ECONOMIC"]
    assert econ, "expected a confirmed economic-tampering finding on /api/checkout"
    f = econ[0]
    assert f.confidence == "confirmed" and f.verification.validated
    assert f.verification.reproductions >= 2
    f.assert_consistent()


def test_bizlogic_clean_on_fixed(tmp_path, fixed_server):
    eng = _engagement(tmp_path, fixed_server.port, bizlogic=True)
    econ = [f for f in eng.run_bizlogic() if f.vuln_class == "BUSINESS_LOGIC_ECONOMIC"]
    assert not econ, "fixed checkout (rejects qty<1) must not be flagged"


# ------------------------------------------------------------------ compliance matrix (8 frameworks)
def test_compliance_matrix_maps_all_frameworks():
    from rampart.compliance import ALL_FRAMEWORKS, compliance_matrix_report, map_finding
    assert set(ALL_FRAMEWORKS) >= {"SOC2", "ISO27001", "PCI-DSS", "NIST-800-53", "HIPAA", "GDPR",
                                   "OWASP-ASVS", "CIS"}
    f = Finding(engagement_id="e", title="IDOR", vuln_class="IDOR/BOLA", severity="high",
                confidence="confirmed", state=State.VALIDATED, cwe=["CWE-639"],
                verification=Verification(method="x", validated=True, reproductions=2))
    mapped = map_finding(f)
    # every framework yields at least one control for an access-control CWE
    for fw in ALL_FRAMEWORKS:
        assert mapped.get(fw), f"{fw} should map CWE-639"

    class _Scope:
        class authorization:
            ticket = "T"; authorized_by = "a@b"
    report = compliance_matrix_report([f], _Scope)
    assert "Compliance control-coverage matrix" in report
    assert "NIST SP 800-53" in report and "HIPAA" in report and "GDPR" in report


# ----------------------------------------------------- SCA enrichment (EPSS + KEV + reachability)
def test_sca_enrichment_adjusts_priority(tmp_path):
    from rampart.sca import scan_sca
    (tmp_path / "requirements.txt").write_text("Flask==0.12.2\nunused-pkg==1.0.0\n")
    app = tmp_path / "app"
    app.mkdir()
    (app / "main.py").write_text("from flask import Flask\napp = Flask(__name__)\n")

    def osv(url, payload, timeout=None):
        n = payload["package"]["name"]
        if n == "flask":
            return {"vulns": [{"id": "G1", "aliases": ["CVE-2099-0001"], "summary": "x",
                "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"}],
                "affected": [{"package": {"ecosystem": "PyPI", "name": "flask"},
                              "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "0.12.3"}]}]}]}]}
        if n == "unused-pkg":
            return {"vulns": [{"id": "G2", "aliases": ["CVE-2099-0002"], "summary": "y",
                "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
                "affected": [{"package": {"ecosystem": "PyPI", "name": "unused-pkg"},
                              "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.0.0"}]}]}]}]}
        return {"vulns": []}

    def epss(url, timeout=None):
        return {"data": [{"cve": "CVE-2099-0001", "epss": "0.9", "percentile": "0.99"},
                         {"cve": "CVE-2099-0002", "epss": "0.001", "percentile": "0.1"}]}

    def kev(url, timeout=None):
        return {"vulnerabilities": [{"cveID": "CVE-2099-0001"}]}

    findings = scan_sca(str(tmp_path), "e", online=True, fetch=osv, fetch_epss_fn=epss, fetch_kev_fn=kev)
    flask_f = next(f for f in findings if "flask" in f.title)
    unused_f = next(f for f in findings if "unused-pkg" in f.title)
    # reachable + KEV + high EPSS => bumped to critical, P0
    assert flask_f.exploit_intel["kev"] is True
    assert flask_f.exploit_intel["reachable"] is True
    assert flask_f.exploit_intel["adjusted_severity"] == "critical"
    assert flask_f.exploit_intel["priority"] == "P0"
    # declared-but-unimported dep => de-prioritised below the reachable one
    assert unused_f.exploit_intel["reachable"] is False
    assert findings.index(flask_f) < findings.index(unused_f)
