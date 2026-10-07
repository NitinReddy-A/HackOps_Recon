"""Multi-agent reasoning layer — orchestration tested deterministically with a scripted brain.

These prove the loop (plan -> explore -> adversarial critic), the safety gating (every agent
action goes through the audited pipeline), and the honest tiering (agent findings are
'agent-assessed', never oracle-'confirmed') — all with NO real LLM.
"""
from conftest import make_engagement
from rampart.agents import AgentBrain, MockBrain


_CONCLUDE = {
    "title": "Negative quantity yields a negative total (store-credit / refund abuse)",
    "vuln_class": "business-logic", "severity": "high", "endpoint_path": "/api/checkout",
    "description": "The /api/checkout quote accepts a negative quantity and returns a negative total.",
    "impact": "An attacker can obtain negative charges / store credit by ordering negative quantities.",
    "root_cause": "Quantity is not validated to be >= 1 before computing the total.",
    "steps": ["GET /api/checkout?item=1&qty=-5", "Observe a negative total"],
    "remediation_summary": "Validate quantity >= 1 server-side.",
    "remediation_guidance": "Reject non-positive quantities and clamp/validate monetary math.",
}


def _script(verdict="stands"):
    return {
        "plan": [{"objectives": ["probe /api/checkout for quantity/price tampering"]}],
        "explore": [
            {"thought": "baseline", "action": {"method": "GET", "path": "/api/checkout",
                                               "query": {"item": "1", "qty": "1"}}},
            {"thought": "try a negative quantity", "action": {"method": "GET", "path": "/api/checkout",
                                                             "query": {"item": "1", "qty": "-5"}}},
            {"thought": "negative total observed", "conclude": _CONCLUDE},
        ],
        "critique": [
            {"action": {"method": "GET", "path": "/api/checkout", "query": {"item": "1", "qty": "2"}},
             "reason": "control: a positive quantity should give a positive total"},
            {"verdict": verdict, "reason": "positive qty gives a positive total; the negative total is anomalous"},
        ],
    }


def test_agent_finds_business_logic_flaw(tmp_path, vuln_server):
    eng = make_engagement(tmp_path, vuln_server.port)
    res = eng.run_agents(brain=MockBrain(_script("stands")), confirmed_findings=[])
    assert len(res.findings) == 1
    f = res.findings[0]
    assert f.vuln_class == "business-logic"
    assert f.verification.validated is False          # reasoning, not proof
    assert f.confidence != "confirmed"                # NEVER confirmed
    assert "agent-assessed" in f.tags and "needs-human-review" in f.tags
    assert any("human confirmation recommended" in c.lower() for c in f.verification.false_positive_checks)
    f.assert_consistent()


def test_critic_refutes_drops_finding(tmp_path, vuln_server):
    eng = make_engagement(tmp_path, vuln_server.port)
    res = eng.run_agents(brain=MockBrain(_script("refuted")), confirmed_findings=[])
    assert res.findings == []                         # critic refuted -> nothing kept


def test_agent_actions_are_gated_and_audited(tmp_path, vuln_server):
    eng = make_engagement(tmp_path, vuln_server.port)
    eng.run_agents(brain=MockBrain(_script("stands")), confirmed_findings=[])
    ok, msg = eng.audit.verify_chain()
    assert ok, msg
    events = eng.audit.read_all()
    assert any((e.actor or {}).get("agent_role", "").startswith("agent") for e in events)


def test_deterministic_brain_produces_nothing(tmp_path, vuln_server):
    # honest: the deterministic provider cannot reason, so the agent layer yields nothing
    eng = make_engagement(tmp_path, vuln_server.port)
    res = eng.run_agents(brain=AgentBrain(eng.intel), confirmed_findings=[])
    assert res.findings == []


def test_agent_findings_flow_into_correlation_and_soc2(tmp_path, vuln_server):
    from rampart.correlation import correlate
    from rampart.reporting.soc2 import soc2_report
    eng = make_engagement(tmp_path, vuln_server.port)
    res = eng.run_agents(brain=MockBrain(_script("stands")), confirmed_findings=[])
    assert res.findings
    # correlation: agent finding becomes an agent-assessed chain and contributes (discounted) risk
    corr = correlate(res.findings)
    agent_chains = [c for c in corr.chains if c.get("agent_assessed")]
    assert agent_chains and corr.risk_score > 0
    # SOC 2: shown as an agent-assessed observation (not a confirmed exception)
    text = soc2_report(res.findings, {}, eng.scope)
    assert "Agent-assessed observations" in text
