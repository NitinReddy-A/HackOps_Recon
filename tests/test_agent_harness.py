"""Agent-harness reliability: schema validation, self-repair, loop detection, coverage, no-miss."""

from conftest import make_engagement

from rampart.agents import DecisionGuard, MockBrain, action_signature, validate_decision


# ---- pure validation ----
def test_validate_decision_accepts_well_formed():
    assert validate_decision({"action": {"method": "GET", "path": "/x", "query": {"a": "1"}}})[0]
    assert validate_decision({"conclude": {"title": "t"}})[0]
    assert validate_decision({"stop": True})[0]
    assert validate_decision({"verdict": "stands"})[0]


def test_validate_decision_rejects_malformed():
    assert not validate_decision("not a dict")[0]
    assert not validate_decision({})[0]  # does nothing
    assert not validate_decision({"action": {"method": "GET"}})[0]  # no path
    assert not validate_decision({"action": {"method": "DROP", "path": "/x"}})[0]
    assert not validate_decision({"action": {"path": "noslash"}})[0]
    assert not validate_decision({"verdict": "maybe"})[0]


def test_action_signature_dedup_key():
    a = {"method": "get", "path": "/p", "query": {"b": "2", "a": "1"}}
    assert action_signature(a) == "GET /p?a=1&b=2"


# ---- guard: self-repair then accept ----
class _Replay:
    def __init__(self, seq):
        self.seq = list(seq)
        self.name = "replay"

    def decide(self, ctx):
        return self.seq.pop(0) if self.seq else {"stop": True}

    def can_reason(self):
        return True


def test_guard_repairs_one_bad_decision():
    brain = _Replay([{"bogus": 1}, {"action": {"method": "GET", "path": "/ok"}}])
    guard = DecisionGuard(brain)
    d, status = guard.decide({"mode": "explore"})
    assert status == "ok" and d["action"]["path"] == "/ok"
    assert guard.stats["repairs"] == 1


def test_guard_stops_on_persistently_invalid():
    brain = _Replay([{"bogus": 1}, {"still": "bad"}])
    guard = DecisionGuard(brain)
    d, status = guard.decide({"mode": "explore"})
    assert status == "invalid" and d.get("stop") is True
    assert guard.stats["invalid"] == 1


def test_guard_detects_repeated_action_loop():
    act = {"action": {"method": "GET", "path": "/same", "query": {}}}
    guard = DecisionGuard(_Replay([act, dict(act)]))
    _, s1 = guard.decide({"mode": "explore"})
    _, s2 = guard.decide({"mode": "explore"})
    assert s1 == "ok" and s2 == "repeat"


# ---- end-to-end coverage: every objective gets an outcome (nothing silently missed) ----
def test_coverage_records_every_objective(tmp_path, vuln_server):
    script = {
        "plan": [{"objectives": ["obj-one", "obj-two"]}],
        # obj-one concludes a finding; obj-two emits an invalid decision (harness must still record it)
        "explore": [
            {
                "thought": "look",
                "action": {"method": "GET", "path": "/api/checkout", "query": {"item": "1", "qty": "-5"}},
            },
            {
                "conclude": {
                    "title": "neg total",
                    "vuln_class": "business-logic",
                    "severity": "high",
                    "endpoint_path": "/api/checkout",
                    "description": "d",
                    "impact": "i",
                    "root_cause": "r",
                    "steps": ["s"],
                    "remediation_summary": "fix",
                    "remediation_guidance": "g",
                }
            },
            {"garbage": True},
            {"garbage": True},  # obj-two: invalid x2 -> stopped-invalid
        ],
        "critique": [
            {
                "action": {"method": "GET", "path": "/api/checkout", "query": {"item": "1", "qty": "2"}},
                "reason": "control",
            },
            {"verdict": "stands", "reason": "neg total is anomalous"},
        ],
    }
    eng = make_engagement(tmp_path, vuln_server.port)
    res = eng.run_agents(brain=MockBrain(script), confirmed_findings=[])
    assert set(res.coverage) == {"obj-one", "obj-two"}  # BOTH objectives recorded — none missed
    assert res.coverage["obj-one"] == "agent-assessed"
    assert res.coverage["obj-two"] == "stopped-invalid"
    assert res.harness_stats["invalid"] >= 1
    assert len(res.findings) == 1
