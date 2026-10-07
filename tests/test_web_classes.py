"""Coverage tests for the web/API classes added on top of BOLA — each proven both ways:
confirmed on the vulnerable target, dropped by the independent oracle on the fixed target.
"""
from conftest import make_engagement
from rampart.schemas.finding import State


def _confirmed(findings, vuln_class):
    return [f for f in findings if f.vuln_class == vuln_class and f.verification.validated]


def _dropped(findings, vuln_class):
    return [f for f in findings if f.vuln_class == vuln_class and f.state == State.DROPPED]


# ---- vulnerable target: every class is confirmed with reproducible proof ----
def test_vuln_target_confirms_all_classes(tmp_path, vuln_server):
    eng = make_engagement(tmp_path, vuln_server.port)
    findings = eng.run_scan().findings

    xss = _confirmed(findings, "XSS")
    assert any("q" in f.endpoint["url"] or "q" in str(f.endpoint.get("parameters")) for f in xss), "XSS on q"
    assert xss and all(f.verification.reproductions >= 2 for f in xss)

    sqli = _confirmed(findings, "SQLI")
    assert sqli and all(f.verification.validator == "validator" for f in sqli)
    assert all(f.confidence == "confirmed" and f.cvss.vector.startswith("CVSS:") for f in sqli)

    redirect = _confirmed(findings, "OPEN_REDIRECT")
    assert redirect, "open redirect must be confirmed"

    # misconfiguration (observation oracle)
    cors = [f for f in findings if "CWE-942" in f.cwe and f.verification.validated]
    assert cors, "CORS misconfiguration must be confirmed"


# ---- the independent oracle drops non-sinks on the vulnerable target (no false positives) ----
def test_oracle_drops_non_sinks(tmp_path, vuln_server):
    eng = make_engagement(tmp_path, vuln_server.port)
    findings = eng.run_scan().findings
    # SQLi was hypothesised on q/next too, but only the real sink (products/id) is confirmed
    assert _dropped(findings, "SQLI"), "non-SQL params must be dropped"
    # XSS hypothesised on JSON endpoints must be dropped (no HTML context)
    assert _dropped(findings, "XSS"), "non-HTML reflections must be dropped"
    for f in _confirmed(findings, "SQLI"):
        assert "products" in f.endpoint["url"]


# ---- fixed target: the FP gate confirms nothing across any class ----
def test_fixed_target_confirms_nothing(tmp_path, fixed_server):
    eng = make_engagement(tmp_path, fixed_server.port)
    findings = eng.run_scan().findings
    confirmed = [f for f in findings if f.verification.validated]
    assert not confirmed, f"fixed target must yield zero confirmed findings, got {[f.title for f in confirmed]}"
    for cls in ("XSS", "SQLI", "OPEN_REDIRECT", "IDOR/BOLA"):
        assert _dropped(findings, cls), f"{cls} candidate should be dropped on the fixed target"


# ---- the deep classes (SSRF / cmd injection / traversal / BFLA / data exposure) ----
def test_vuln_target_confirms_deep_classes(tmp_path, vuln_server):
    eng = make_engagement(tmp_path, vuln_server.port)
    findings = eng.run_scan().findings
    confirmed = {f.vuln_class for f in findings if f.verification.validated}
    for cls in ("SSRF", "CMDI", "PATH_TRAVERSAL", "BFLA", "EXCESSIVE_DATA"):
        assert cls in confirmed, f"{cls} must be confirmed on the vulnerable target"
    cmdi = next(f for f in findings if f.vuln_class == "CMDI" and f.verification.validated)
    assert cmdi.severity == "critical"


def test_fixed_target_drops_deep_classes(tmp_path, fixed_server):
    eng = make_engagement(tmp_path, fixed_server.port)
    findings = eng.run_scan().findings
    confirmed = [f for f in findings if f.verification.validated]
    assert not confirmed
    for cls in ("SSRF", "CMDI", "PATH_TRAVERSAL", "BFLA", "EXCESSIVE_DATA"):
        assert _dropped(findings, cls), f"{cls} should be dropped on the fixed target"


# ---- hypotheses span multiple classes (multi-vector planning) ----
def test_hypotheses_cover_multiple_classes(tmp_path, vuln_server):
    eng = make_engagement(tmp_path, vuln_server.port)
    result = eng.run_scan()
    classes = {h["vuln_class"] for h in result.hypotheses}
    assert {"IDOR/BOLA", "XSS", "SQLI", "OPEN_REDIRECT",
            "SSRF", "CMDI", "PATH_TRAVERSAL", "BFLA", "EXCESSIVE_DATA"} <= classes


# ---- confirmed findings never violate the trust invariant ----
def test_all_confirmed_are_consistent(tmp_path, vuln_server):
    eng = make_engagement(tmp_path, vuln_server.port)
    for f in eng.run_scan().findings:
        f.assert_consistent()
