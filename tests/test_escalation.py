"""Unit tests for the finding-driven escalation policy and its anti-runaway bounds.

These are pure (no network, no LLM): they pin the deterministic follow-up generation and that
every cap — depth, total, per-finding, dedup — actually bites and is tallied.
"""

from types import SimpleNamespace

from rampart.orchestration import (
    EscalationBudget,
    escalation_identity,
    follow_ups,
)
from rampart.orchestration.escalation import (
    ESCALATION_INJECTION_CLASSES,
    _injection_siblings,
    _object_type_neighbors,
)


def _finding(vuln_class):
    return SimpleNamespace(vuln_class=vuln_class)


def _appmodel(endpoints):
    eps = [
        SimpleNamespace(
            method=e.get("method", "GET"),
            path=e["path"],
            returns_object_type=e.get("returns_object_type"),
            object_selector=e.get("object_selector", {}),
        )
        for e in endpoints
    ]
    return SimpleNamespace(
        ownable_endpoints=lambda: [e for e in eps if e.returns_object_type and e.object_selector]
    )


# --------------------------------------------------------------- identity / dedup
def test_identity_is_class_method_path_param():
    h = {"vuln_class": "SQLI", "endpoint_method": "get", "endpoint_path": "/a", "selector_param": "q"}
    assert escalation_identity(h) == "SQLI|GET|/a|q"
    # method case-normalised; same fields -> same identity
    h2 = {**h, "endpoint_method": "GET"}
    assert escalation_identity(h) == escalation_identity(h2)


# --------------------------------------------------------------- injection siblings
def test_injection_confirmed_escalates_to_other_sound_injection_classes_on_same_param():
    hyp = {"vuln_class": "SQLI", "endpoint_method": "GET", "endpoint_path": "/api/x", "selector_param": "q"}
    outs = follow_ups(_finding("SQLI"), hyp, None)
    classes = {o["vuln_class"] for o in outs}
    assert "SQLI" not in classes  # never re-propose the class already confirmed
    assert classes == set(ESCALATION_INJECTION_CLASSES) - {"SQLI"}
    # every follow-up targets the SAME endpoint+param and is tagged as escalation
    assert all(o["endpoint_path"] == "/api/x" and o["selector_param"] == "q" for o in outs)
    assert all(o["_origin"] == "escalation:injection-sibling" for o in outs)


def test_cmdi_is_never_an_escalation_target_but_still_triggers_escalation():
    # CMDI's oracle confirms on plain reflection, so escalating INTO it would amplify that into
    # false positives on every reflection endpoint. It must never be a follow-up class...
    for trigger in ("SQLI", "XSS", "CMDI"):
        outs = follow_ups(
            _finding(trigger),
            {"vuln_class": trigger, "endpoint_method": "GET", "endpoint_path": "/x", "selector_param": "p"},
            None,
        )
        assert "CMDI" not in {o["vuln_class"] for o in outs}
    # ...yet a confirmed CMDI still TRIGGERS escalation into the sound classes.
    outs = follow_ups(
        _finding("CMDI"),
        {
            "vuln_class": "CMDI",
            "endpoint_method": "GET",
            "endpoint_path": "/api/ping",
            "selector_param": "host",
        },
        None,
    )
    assert {o["vuln_class"] for o in outs} == set(ESCALATION_INJECTION_CLASSES)


def test_injection_without_param_yields_nothing():
    assert _injection_siblings({"endpoint_path": "/x"}, "SQLI") == []
    assert _injection_siblings({"selector_param": "q"}, "SQLI") == []


# --------------------------------------------------------------- object-type neighbours
def test_bola_confirmed_sweeps_sibling_endpoints_of_the_same_object_type():
    hyp = {
        "vuln_class": "IDOR/BOLA",
        "endpoint_method": "GET",
        "endpoint_path": "/api/orders/{id}",
        "selector_param": "id",
        "object_type": "order",
        "attacker_principal": "user_a",
        "victim_principal": "user_b",
        "victim_object": {"id": "2"},
        "attacker_object": {"id": "1"},
    }
    appmodel = _appmodel(
        [
            {"path": "/api/orders/{id}", "returns_object_type": "order", "object_selector": {"param": "id"}},
            {
                "path": "/api/invoices/{iid}",
                "returns_object_type": "order",
                "object_selector": {"param": "iid"},
            },
            {"path": "/api/users/{uid}", "returns_object_type": "user", "object_selector": {"param": "uid"}},
        ]
    )
    outs = follow_ups(_finding("IDOR/BOLA"), hyp, appmodel)
    # only the sibling 'order' endpoint (not the origin, not the 'user' endpoint)
    assert [o["endpoint_path"] for o in outs] == ["/api/invoices/{iid}"]
    o = outs[0]
    assert o["selector_param"] == "iid"  # the sibling's own selector
    assert o["attacker_principal"] == "user_a" and o["victim_object"] == {"id": "2"}  # fixtures reused
    assert o["_origin"] == "escalation:object-type-neighbor"


def test_bola_without_seeded_fixtures_yields_nothing():
    hyp = {"vuln_class": "IDOR/BOLA", "object_type": "order", "endpoint_path": "/x"}
    assert _object_type_neighbors(hyp, _appmodel([])) == []


def test_non_escalatable_classes_yield_nothing():
    assert follow_ups(_finding("security-misconfiguration"), {"endpoint_path": "/x"}, None) == []
    assert follow_ups(_finding("sensitive-file-exposure"), {}, None) == []


# --------------------------------------------------------------- budget caps
def _cand(cls, param):
    return {"vuln_class": cls, "endpoint_method": "GET", "endpoint_path": "/x", "selector_param": param}


def test_disabled_budget_admits_nothing():
    b = EscalationBudget(enabled=False)
    assert b.admit_batch([_cand("SQLI", "q")], depth=0) == []


def test_depth_cap_blocks_beyond_max_depth():
    b = EscalationBudget(enabled=True, max_depth=1)
    assert len(b.admit_batch([_cand("SQLI", "q")], depth=0)) == 1  # depth 0 -> 1 allowed
    assert b.admit_batch([_cand("XSS", "q")], depth=1) == []  # depth 1 -> 2 blocked
    assert b.stats["dropped_depth"] == 1


def test_dedup_blocks_already_seen_and_seed_counts():
    b = EscalationBudget(enabled=True)
    b.seed([_cand("SQLI", "q")])  # already planned in the initial fan-out
    assert b.admit_batch([_cand("SQLI", "q")], depth=0) == []
    assert b.stats["dropped_duplicate"] == 1
    # a different param is still admitted
    assert len(b.admit_batch([_cand("SQLI", "other")], depth=0)) == 1


def test_per_finding_cap():
    b = EscalationBudget(enabled=True, max_per_finding=2)
    cands = [_cand("SQLI", "q"), _cand("XSS", "q"), _cand("SSTI", "q"), _cand("SSRF", "q")]
    admitted = b.admit_batch(cands, depth=0)
    assert len(admitted) == 2
    assert b.stats["dropped_per_finding"] == 2


def test_total_cap_across_findings():
    b = EscalationBudget(enabled=True, max_total=3, max_per_finding=10)
    a1 = b.admit_batch([_cand("SQLI", "p1"), _cand("XSS", "p1")], depth=0)
    a2 = b.admit_batch([_cand("SQLI", "p2"), _cand("XSS", "p2")], depth=0)
    assert len(a1) == 2 and len(a2) == 1  # 3 total, then the 4th is dropped
    assert b.stats["admitted"] == 3 and b.stats["dropped_total"] == 1


def test_admitted_followups_are_stamped_with_next_depth():
    b = EscalationBudget(enabled=True)
    admitted = b.admit_batch([_cand("SQLI", "q")], depth=1)
    assert admitted[0]["_depth"] == 2


def test_summary_reports_caps_and_drops():
    b = EscalationBudget(enabled=True, max_depth=2, max_total=24, max_per_finding=6)
    b.seed([_cand("SQLI", "q")])
    b.admit_batch([_cand("SQLI", "q"), _cand("XSS", "q")], depth=0)
    s = b.summary()
    assert s["enabled"] and s["max_depth"] == 2
    assert s["admitted"] == 1 and s["dropped"]["duplicate"] == 1
