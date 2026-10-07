"""White-box SAST / SCA + SAST<->DAST correlation + isolated scan modes."""
import os

from conftest import write_engagement
from rampart.engagement import Engagement, EngagementConfig
from rampart.sast import scan_secrets, scan_source

DEMO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "examples", "demo_target"))


def test_sast_finds_sink_patterns():
    findings = scan_source(DEMO, "x")
    cwes = {c for f in findings for c in f.cwe}
    for expected in ("CWE-78", "CWE-89", "CWE-918", "CWE-502", "CWE-95", "CWE-327", "CWE-22", "CWE-489"):
        assert expected in cwes, f"SAST should flag {expected}"
    # static tier: never runtime-validated, carries a source location
    for f in findings:
        assert f.verification.validated is False and "sast" in f.tags
        assert f.affected_code and f.affected_code.file and f.affected_code.start_line > 0
        f.assert_consistent()


def test_secret_scan_finds_hardcoded_key():
    secrets = scan_secrets(DEMO, "x")
    assert any(f.vuln_class == "sast-hardcoded-secret" for f in secrets)


def _eng(tmp_path, port, **over):
    scope = write_engagement(tmp_path, port)
    cfg = EngagementConfig(scope_file=scope, target=f"http://127.0.0.1:{port}",
                           work_dir=str(tmp_path / ".rampart"),
                           openapi=str(tmp_path / "openapi.json"), appmodel_seed=str(tmp_path / "seed.json"),
                           application="demo-shop-api", repo=DEMO, **over)
    return Engagement(cfg)


def test_sast_mode_runs_without_network(tmp_path, vuln_server):
    # sast-only: no DAST network findings, only static source findings
    eng = _eng(tmp_path, vuln_server.port, do_dast=False, do_sast=True, do_sca=True)
    findings = eng.run_scan().findings
    assert findings, "sast mode should produce source findings"
    assert all("sast" in f.tags for f in findings)
    assert not [f for f in findings if f.verification.validated]   # nothing runtime-confirmed


def test_sast_dast_correlation(tmp_path, vuln_server):
    eng = _eng(tmp_path, vuln_server.port, do_dast=True, do_sast=True, do_sca=True)
    findings = eng.run_scan().findings
    # a runtime-confirmed finding whose CWE also appears in source should be source-correlated
    correlated = [f for f in findings if "source-correlated" in f.tags]
    assert correlated, "expected at least one runtime finding correlated to a source location"
    for f in correlated:
        assert f.verification.validated and f.affected_code and f.affected_code.file
