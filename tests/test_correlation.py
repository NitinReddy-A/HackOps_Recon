"""Attack-chain correlation, risk scoring, and remediation roadmap."""
from conftest import make_engagement
from rampart.correlation import correlate


def test_chains_and_risk_on_vuln_target(tmp_path, vuln_server):
    result = make_engagement(tmp_path, vuln_server.port).run_scan()
    corr = result.correlation
    assert corr is not None
    chain_ids = {c["id"] for c in corr.chains}
    # the big ones must be inferred from the confirmed findings
    assert {"ssrf-cloud-takeover", "rce-full-compromise", "sqli-breach",
            "mass-data-exfil"} <= chain_ids
    assert corr.risk_score >= 80 and corr.risk_band == "Critical"
    # every chain references at least one real confirmed finding
    confirmed_ids = {f.id for f in result.findings if f.verification.validated}
    for c in corr.chains:
        assert c["finding_ids"] and set(c["finding_ids"]) <= confirmed_ids


def test_roadmap_prioritized_and_deduped(tmp_path, vuln_server):
    result = make_engagement(tmp_path, vuln_server.port).run_scan()
    roadmap = result.correlation.roadmap
    assert roadmap
    ranks = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sev_seq = [ranks[r["severity"]] for r in roadmap]
    assert sev_seq == sorted(sev_seq), "roadmap must be ordered worst-first"


def test_no_chains_without_findings():
    corr = correlate([])
    assert corr.chains == [] and corr.risk_score == 0 and corr.risk_band == "Informational"


def test_fixed_target_low_risk(tmp_path, fixed_server):
    result = make_engagement(tmp_path, fixed_server.port).run_scan()
    assert result.correlation.risk_score == 0
    assert result.correlation.chains == []
