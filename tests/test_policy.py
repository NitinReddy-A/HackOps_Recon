"""The safety choke-point: allowlist -> scope -> risk -> policy -> HITL -> budget -> audit."""

import pytest

from rampart.audit import AuditLog
from rampart.policy import PolicyPipeline
from rampart.policy.budget import BudgetTracker
from rampart.schemas.scope import EngagementScope
from rampart.schemas.toolcall import Decision, RiskTier, ToolAction, ToolCallRequest

SCOPE = """
apiVersion: security-agent/v1
kind: EngagementScope
authorization: {owner: o, authorized_by: c, ticket: T, attestation: ok, expires: "2099-01-01T00:00:00Z"}
scope:
  in_scope:
    - host: "127.0.0.1"
      ports: [8080]
      paths_include: ["/api/**"]
      methods: ["GET", "POST", "PUT", "DELETE"]
  out_of_scope: {paths_exclude: ["/api/admin/**"], hosts_exclude: []}
  resolved_ip_allowlist: ["127.0.0.1/32"]
limits: {max_requests_per_host_per_min: 5, max_total_requests: 100}
action_policy: {default_tier_ceiling: 1, tier2_requires_approval: true, tier3: deny}
test_accounts: [{id: user_b, role: customer, secret_ref: "v://b"}]
"""


class _Resp:
    status = 200
    headers = {"Server": "x"}
    body = "ok"
    body_sha256 = "h"
    size = 2
    duration_ms = 1.0


class _Exec:
    def __init__(self):
        self.calls = 0

    def execute(self, action, ip):
        self.calls += 1
        return _Resp()


@pytest.fixture
def pipe(tmp_path):
    scope = EngagementScope.from_text(SCOPE)
    audit = AuditLog(str(tmp_path / "audit.jsonl"))
    budget = BudgetTracker(scope.limits)
    ex = _Exec()
    p = PolicyPipeline(
        scope, audit, budget, ex, resolver=lambda h: ["127.0.0.1"] if h == "127.0.0.1" else [], approver=None
    )
    return p, ex, audit


def _req(
    method="GET", path="/api/orders/1", payload="benign-read", session="user_b", tier=0, host="127.0.0.1"
):
    return ToolCallRequest(
        engagement_id="T",
        declared_tier=tier,
        action=ToolAction(
            method=method,
            target_host=host,
            port=8080,
            scheme="http",
            path=path,
            use_session=session,
            payload_class=payload,
        ),
    )


def test_in_scope_read_allowed(pipe):
    p, ex, _ = pipe
    r = p.execute(_req())
    assert r.decision.allowed and r.executed and ex.calls == 1


def test_out_of_scope_path_denied(pipe):
    p, ex, _ = pipe
    r = p.execute(_req(path="/api/admin/secret"))
    assert r.decision.decision == Decision.DENY and not r.executed and ex.calls == 0


def test_out_of_scope_host_denied(pipe):
    p, _, _ = pipe
    r = p.execute(_req(host="evil.com"))
    assert r.decision.decision == Decision.DENY and not r.executed


def test_write_is_tier2_and_fails_closed_without_approver(pipe):
    p, _, _ = pipe
    r = p.execute(_req(method="POST", path="/api/orders", payload="state-change"))
    assert r.decision.effective_tier == RiskTier.HIGH_RISK
    assert r.decision.decision == Decision.DENY and not r.executed


def test_risk_downgrade_attempt_ignored(pipe):
    p, _, _ = pipe
    r = p.execute(_req(method="DELETE", path="/api/orders/1", payload="benign-read", tier=0))
    assert r.decision.effective_tier == RiskTier.HIGH_RISK
    assert r.decision.checks.get("downgrade_attempt") is True


def test_destructive_marker_is_tier3_denied(pipe):
    p, _, _ = pipe
    r = p.execute(_req(path="/api/orders?q=1;DROP TABLE users--"))
    assert r.decision.effective_tier == RiskTier.PROHIBITED
    assert r.decision.decision == Decision.DENY


def test_tier2_allowed_with_human_approval(pipe):
    p, ex, _ = pipe
    p.approver = lambda req, dec: {"granted": True, "approver_user_id": "h"}
    r = p.execute(_req(method="POST", path="/api/orders", payload="state-change"))
    assert r.decision.decision == Decision.ALLOW and r.executed


def test_rate_limit_trips(pipe):
    p, _, _ = pipe
    blocked = False
    for i in range(30):
        r = p.execute(_req(path=f"/api/orders/{i}"))
        if not r.decision.allowed and "budget" in r.decision.reason:
            blocked = True
            break
    assert blocked


def test_kill_switch(pipe):
    p, _, _ = pipe
    p.budget.kill("test")
    r = p.execute(_req())
    assert r.decision.decision == Decision.DENY and not r.executed
