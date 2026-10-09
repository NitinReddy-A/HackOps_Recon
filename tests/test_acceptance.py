"""End-to-end acceptance tests — the v0.1 "definition of done" (blueprint section 29, A1-A8).

Each test runs the real engagement against a throwaway, isolated demo target.
"""

import os

import pytest
from conftest import make_engagement, write_engagement

from rampart.engagement import Engagement, EngagementConfig
from rampart.schemas.finding import Finding, State
from rampart.schemas.scope import ScopeError


# A1 — refuses to run without a valid, in-scope authorization
def test_a1_refuses_out_of_scope_target(tmp_path, vuln_server):
    scope_file = write_engagement(tmp_path, vuln_server.port)
    cfg = EngagementConfig(
        scope_file=scope_file,
        target="http://192.0.2.1:8080",  # not in scope
        work_dir=str(tmp_path / ".rampart"),
        openapi=str(tmp_path / "openapi.json"),
        appmodel_seed=str(tmp_path / "seed.json"),
    )
    with pytest.raises(ScopeError):
        Engagement(cfg)


def test_a1_refuses_invalid_scope(tmp_path):
    bad = tmp_path / "rampart.scope.yaml"
    bad.write_text("kind: EngagementScope\nscope: {}\n", encoding="utf-8")
    (tmp_path / "secrets.json").write_text("{}", encoding="utf-8")
    cfg = EngagementConfig(
        scope_file=str(bad), target="http://127.0.0.1:8080", work_dir=str(tmp_path / ".rampart")
    )
    with pytest.raises(ScopeError):
        Engagement(cfg)


# A2 — builds an application model with endpoints, roles, principals
def test_a2_builds_app_model(tmp_path, vuln_server):
    eng = make_engagement(tmp_path, vuln_server.port)
    assert len(eng.appmodel.endpoints) >= 2
    assert len(eng.appmodel.principals) == 2
    assert len(eng.appmodel.ownable_endpoints()) == 1


# A3 — forms a BOLA hypothesis using seeded accounts only
def test_a3_hypothesis_uses_seeded_accounts(tmp_path, vuln_server):
    eng = make_engagement(tmp_path, vuln_server.port)
    result = eng.run_scan()
    hyp = next(h for h in result.hypotheses if h["vuln_class"] == "IDOR/BOLA")
    ids = {p.id for p in eng.appmodel.principals}
    assert hyp["attacker_principal"] in ids and hyp["victim_principal"] in ids
    assert hyp["attacker_principal"] != hyp["victim_principal"]


# A4 — independent validation before confirmed (2+ reproductions, separate component)
def test_a4_independent_validation(tmp_path, vuln_server):
    eng = make_engagement(tmp_path, vuln_server.port)
    result = eng.run_scan()
    idor = next(f for f in result.findings if f.vuln_class == "IDOR/BOLA")
    assert idor.verification.validated is True
    assert idor.verification.validator == "validator"  # separation of duties
    assert idor.verification.reproductions >= 2
    assert idor.confidence == "confirmed"
    assert idor.state == State.VALIDATED
    idor.assert_consistent()  # confirmed <=> validated


# A5 — emits a schema-valid finding with CWE/OWASP/CVSS + evidence
def test_a5_finding_schema_and_roundtrip(tmp_path, vuln_server):
    eng = make_engagement(tmp_path, vuln_server.port)
    result = eng.run_scan()
    idor = next(f for f in result.findings if f.vuln_class == "IDOR/BOLA")
    assert "CWE-639" in idor.cwe
    assert "API1:2023-BOLA" in idor.owasp.get("api_2023", [])
    assert idor.cvss.vector.startswith("CVSS:")
    assert len(idor.evidence) >= 2
    # SARIF + round-trip
    assert idor.to_sarif_result()["ruleId"] == "CWE-639"
    again = Finding.from_dict(idor.to_dict())
    assert again.id == idor.id and again.verification.validated


# A6 — white-box correlation + advisory patch, never auto-applied
def test_a6_advisory_patch_not_applied(tmp_path, vuln_server):
    repo = os.path.join(os.path.dirname(__file__), "..", "examples", "demo_target")
    src = os.path.join(repo, "src", "orders_service.py")
    before = open(src, encoding="utf-8").read()
    eng = make_engagement(tmp_path, vuln_server.port, repo=repo)
    eng.run_scan()
    touched = eng.remediate()
    assert touched, "expected a remediation proposal"
    f = touched[0]
    assert f.affected_code and f.affected_code.file.endswith("orders_service.py")
    assert "Forbidden" in f.remediation.proposed_diff
    assert f.remediation.fix_status == "proposed"  # not applied
    after = open(src, encoding="utf-8").read()
    assert before == after, "source must NOT be modified (advisory only)"


# A7 — retest flips a fixed finding to Fixed
def test_a7_retest_flips_to_fixed(tmp_path, vuln_server, fixed_server):
    eng = make_engagement(tmp_path, vuln_server.port)
    eng.run_scan()
    # replay stored findings/hypotheses against the PATCHED target, sharing the work dir
    fixed_cfg_dir = tmp_path / "fixedcfg"
    fixed_cfg_dir.mkdir()
    scope_file = write_engagement(fixed_cfg_dir, fixed_server.port)
    cfg = EngagementConfig(
        scope_file=scope_file,
        target=f"http://127.0.0.1:{fixed_server.port}",
        work_dir=eng.cfg.work_dir,
        openapi=str(fixed_cfg_dir / "openapi.json"),
        appmodel_seed=str(fixed_cfg_dir / "seed.json"),
        application="demo-shop-api",
    )
    eng_fixed = Engagement(cfg)
    results = eng_fixed.retest()
    outcomes = {f.vuln_class: o for f, o in results if f.vuln_class == "IDOR/BOLA"}
    assert outcomes.get("IDOR/BOLA") == "Fixed"
    # every oracle-replayable finding is Fixed on the patched build; the rest are reported
    # as "not retestable" (misconfig / sensitive-file / static) rather than silently skipped
    print(sorted({(f.vuln_class, o) for f, o in results}))
    assert {o for _f, o in results} <= {"Fixed", Engagement.NOT_RETESTABLE}


# A8 — false-positive gate: nothing confirmed against a secure target
def test_a8_fp_gate_drops_on_fixed(tmp_path, fixed_server):
    eng = make_engagement(tmp_path, fixed_server.port)
    result = eng.run_scan()
    confirmed_idor = [f for f in result.findings if f.vuln_class == "IDOR/BOLA" and f.verification.validated]
    dropped_idor = [f for f in result.findings if f.vuln_class == "IDOR/BOLA" and f.state == State.DROPPED]
    assert not confirmed_idor, "must not confirm IDOR on a patched target"
    assert dropped_idor, "IDOR candidate should be dropped by the FP gate"


# Bonus — the whole engagement audit chain stays intact
def test_audit_chain_intact_after_run(tmp_path, vuln_server):
    eng = make_engagement(tmp_path, vuln_server.port)
    eng.run_scan()
    ok, msg = eng.audit.verify_chain()
    assert ok, msg
