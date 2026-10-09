"""Choke-point hardening: Tier-2 approval vs ceiling, destructive-marker evasion, Host header,
per-request expiry, fail-closed approver/budget errors, redacted audit params, throttling and
the kill switch / LLM budget (reviewer findings A6/A7/A10/A11/A13/A17/A18)."""

import json
import signal

import pytest

from rampart.audit import AuditLog
from rampart.policy import PolicyPipeline, engine
from rampart.policy.budget import (
    BudgetExceeded,
    BudgetTracker,
    install_kill_signal_handlers,
    restore_signal_handlers,
)
from rampart.policy.risk import classify
from rampart.schemas.scope import ActionPolicy, EngagementScope, Limits
from rampart.schemas.toolcall import Decision, RiskTier, ToolAction, ToolCallRequest

SCOPE = """
apiVersion: security-agent/v1
kind: EngagementScope
authorization: {{owner: o, authorized_by: c, ticket: T, attestation: ok, expires: "2099-01-01T00:00:00Z"}}
scope:
  in_scope:
    - host: "127.0.0.1"
      ports: [8080]
      paths_include: ["/**"]
      methods: ["GET", "POST"]
  out_of_scope: {{paths_exclude: ["/api/admin/**", "/logout"], hosts_exclude: []}}
  resolved_ip_allowlist: ["127.0.0.1/32"]
limits: {{max_requests_per_host_per_min: 500, max_total_requests: 1000}}
action_policy: {{default_tier_ceiling: {ceiling}, tier2_requires_approval: {approval}, tier3: deny}}
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
        self.calls = []

    def execute(self, action, ip):
        self.calls.append(action)
        return _Resp()


def _pipe(tmp_path, ceiling=1, approval="true", approver=None):
    scope = EngagementScope.from_text(SCOPE.format(ceiling=ceiling, approval=approval))
    assert scope.validate() == []
    ex = _Exec()
    audit = AuditLog(str(tmp_path / "audit.jsonl"))
    p = PolicyPipeline(
        scope, audit, BudgetTracker(scope.limits), ex, resolver=lambda h: ["127.0.0.1"], approver=approver
    )
    return p, ex, audit


def _req(**kw):
    a = {"method": "GET", "target_host": "127.0.0.1", "port": 8080, "scheme": "http", "path": "/api/x"}
    a.update(kw)
    return ToolCallRequest(engagement_id="T", action=ToolAction(**a))


# ------------------------------------------------------------------------- A7
def test_tier2_requires_approval_even_when_ceiling_is_2(tmp_path):
    p, ex, _ = _pipe(tmp_path, ceiling=2, approval="true")
    r = p.execute(_req(method="POST", payload_class="state-change", body="{}"))
    assert r.decision.decision == Decision.DENY and not r.executed and not ex.calls
    assert "approval" in r.decision.reason


def test_tier2_auto_allowed_only_when_approval_disabled_and_ceiling_2(tmp_path):
    p, ex, _ = _pipe(tmp_path, ceiling=2, approval="false")
    r = p.execute(_req(method="POST", payload_class="state-change", body="{}"))
    assert r.executed


def test_engine_order():
    assert engine.decide(2, ActionPolicy(2, True)).decision == Decision.ALLOW_WITH_INTERRUPT
    assert engine.decide(2, ActionPolicy(1, False)).decision == Decision.DENY
    assert engine.decide(1, ActionPolicy(1, True)).decision == Decision.ALLOW
    assert engine.decide(3, ActionPolicy(2, False)).decision == Decision.DENY


# ------------------------------------------------------------------------ A10
@pytest.mark.parametrize(
    "action",
    [
        ToolAction(query={"q": "1;DROP/**/TABLE users"}),
        ToolAction(query={"1;DROP TABLE users--": "x"}),
        ToolAction(headers={"X-Q": "1; DROP TABLE users"}),
        ToolAction(path="/api/q/1%3BDROP%20TABLE%20users"),
        ToolAction(path="/api/q/1%253BDROP%2520TABLE%2520users"),
        ToolAction(method="POST", body="q=1%3BDROP+TABLE+users", payload_class="canary"),
        ToolAction(method="POST", body='{"q":"1;DROP\\u0020TABLE users"}', payload_class="canary"),
        ToolAction(method="POST", body='{"q":"1;DELETE/**/FROM users"}', payload_class="canary"),
        ToolAction(query={"cmd": "rm -fr /"}),
        ToolAction(query={"cmd": "rm -r -f /"}),
        ToolAction(query={"cmd": "rm --recursive /"}),
        ToolAction(query={"q": ["1; DROP TABLE users"]}),
        ToolAction(query={"q": "1;\n\tDROP\n  TABLE users"}),
        ToolAction(query={"cmd": "mkfs.ext4 /dev/sda"}),
        ToolAction(query={"cmd": "dd if=/dev/zero of=/dev/sda"}),
        ToolAction(query={"cmd": ":(){ :|:& };:"}),
        ToolAction(query={"q": "1; ALTER TABLE users DROP COLUMN pw"}),
        ToolAction(query={"q": "1; UPDATE users SET role='admin'"}),
        ToolAction(query={"cmd": "FLUSHALL"}),
    ],
)
def test_destructive_payload_evasions_are_tier3(action):
    assert classify(action, 0).tier == RiskTier.PROHIBITED


@pytest.mark.parametrize(
    "action",
    [
        ToolAction(path="/api/orders/1"),
        ToolAction(query={"q": "' OR '1'='1"}),
        ToolAction(query={"q": "1 AND SLEEP(5)"}),
        ToolAction(query={"file": "../../../../etc/passwd"}),
        ToolAction(query={"q": "<script>alert(1)</script>"}),
        ToolAction(query={"update": "x", "set": "y"}),  # separate fields never join into a marker
        ToolAction(headers={"Authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.e30.x"}),
        ToolAction(path="/api/users/drop-shipping/format"),
    ],
)
def test_normal_probes_not_tier3(action):
    assert classify(action, 0).tier < RiskTier.PROHIBITED


# ------------------------------------------------------------------------- A6
@pytest.mark.parametrize(
    "path", ["/api/%61dmin/x", "//api/admin", "/api/./admin", "/x/../api/admin", "/api/admin%2fx",
             "/API/admin/users", "/logout/", "/logout;jsessionid=1", "/logout?x=1", "/api/admin"]
)  # fmt: skip
def test_pipeline_denies_noncanonical_excluded_paths(tmp_path, path):
    p, ex, _ = _pipe(tmp_path)
    r = p.execute(_req(path=path))
    assert not r.executed and not ex.calls and "out of scope" in r.decision.reason


def test_pipeline_denies_crlf_and_absolute_form(tmp_path):
    p, ex, _ = _pipe(tmp_path)
    for path in ("/ok HTTP/1.1\r\nHost: x\r\n\r\nGET /api/admin/users", "http://evil.example/x", "x"):
        assert not p.execute(_req(path=path)).executed
    assert not ex.calls


# ------------------------------------------------------------------- A18(b)
def test_foreign_host_header_denied_but_target_and_reserved_canary_allowed(tmp_path):
    p, ex, _ = _pipe(tmp_path)
    assert not p.execute(_req(headers={"Host": "other-tenant.com"})).executed
    assert not p.execute(_req(headers={"Host": "evil.example"})).executed
    assert not p.execute(_req(headers={"host": "internal.corp:8080"})).executed
    assert p.execute(_req(headers={"Host": "127.0.0.1:8080"})).executed
    assert p.execute(_req(headers={"Host": "rampart-hhi-canary.example"})).executed  # HHI oracle canary


def test_non_http_scheme_denied(tmp_path):
    p, ex, _ = _pipe(tmp_path)
    assert not p.execute(_req(scheme="gopher")).executed


# ------------------------------------------------------------------- A18(d)
def test_scope_expiry_checked_per_request(tmp_path):
    p, ex, _ = _pipe(tmp_path)
    assert p.execute(_req()).executed
    p.scope.authorization.expires = "2000-01-01T00:00:00Z"  # contract lapses mid-run
    r = p.execute(_req())
    assert not r.executed and "expired" in r.decision.reason


# ------------------------------------------------------------------- A18(e)
def test_audit_params_values_redacted_keys_kept_and_port_scheme_logged(tmp_path):
    p, _, audit = _pipe(tmp_path)
    p.execute(_req(query={"token": "s3cr3t-value", "ids": ["1", "2"]}))
    raw = open(audit.path, encoding="utf-8").read()
    assert "s3cr3t-value" not in raw
    ev = audit.read_all()[0]
    assert set(ev.action["params_redacted"]) == {"token", "ids"}
    assert ev.action["params_redacted"]["token"].startswith("<redacted:")
    assert ev.action["port"] == 8080 and ev.action["scheme"] == "http"


# ------------------------------------------------------------------------ A13
def test_approver_exception_denies_and_is_audited(tmp_path):
    def boom(req, dec):
        raise RuntimeError("approval service down")

    p, ex, audit = _pipe(tmp_path, approver=boom)
    r = p.execute(_req(method="POST", payload_class="state-change", body="{}"))
    assert not r.executed and not ex.calls and "approver error" in r.decision.reason
    assert audit.read_all()[-1].policy_decision["decision"] == Decision.DENY


def test_budget_exception_denies_and_is_audited(tmp_path):
    p, ex, audit = _pipe(tmp_path)
    p.budget.limits.max_total_requests = "5000"  # a type error inside the tracker
    r = p.execute(_req())
    assert not r.executed and not ex.calls and "budget" in r.decision.reason
    assert audit.read_all()[-1].execution["status"] == "blocked"


# ------------------------------------------------------------------------ A17
class _Clock:
    def __init__(self):
        self.t = 1000.0
        self.slept = []

    def __call__(self):
        return self.t

    def sleep(self, s):
        self.slept.append(s)
        self.t += s


def test_rate_limit_throttles_instead_of_denying():
    c = _Clock()
    b = BudgetTracker(Limits(max_requests_per_host_per_min=2, max_total_requests=100), sleep=c.sleep, clock=c)
    assert b.try_consume_request("h")[0] and b.try_consume_request("h")[0]
    ok, why = b.try_consume_request("h")
    assert ok and "throttled" in why and c.slept and 59 <= sum(c.slept) <= 60.1
    assert b.throttled_requests == 1 and b.denials["rate_limit"] == 0


def test_rate_limit_denies_past_max_wait_and_counts_it():
    c = _Clock()
    b = BudgetTracker(
        Limits(max_requests_per_host_per_min=1, max_total_requests=100),
        max_rate_wait_s=5,
        sleep=c.sleep,
        clock=c,
    )
    assert b.try_consume_request("h")[0]
    ok, why = b.try_consume_request("h")
    assert not ok and "rate limit" in why
    assert b.denials["rate_limit"] == 1 and b.snapshot()["denied"]["rate_limit"] == 1


def test_total_cap_denials_counted():
    b = BudgetTracker(Limits(max_total_requests=1))
    assert b.try_consume_request("h")[0]
    assert not b.try_consume_request("h")[0]
    assert b.denials["max_total_requests"] == 1 and b.denied_total() == 1


# ------------------------------------------------------------------------ A11
def test_kill_switch_denies_requests():
    b = BudgetTracker(Limits())
    b.kill("operator")
    ok, why = b.try_consume_request("h")
    assert not ok and "kill" in why and b.denials["kill_switch"] == 1


def test_kill_file_in_work_dir_trips_kill_switch(tmp_path):
    b = BudgetTracker.for_work_dir(Limits(), str(tmp_path))
    assert b.try_consume_request("h")[0]
    (tmp_path / "KILL").write_text("stop")
    assert not b.try_consume_request("h")[0] and b.killed
    assert not b.can_spend_llm()[0]


def test_llm_budget_usd_and_tokens_enforced():
    b = BudgetTracker(Limits(budget_usd=1.0, max_tokens=1000))
    assert b.can_spend_llm()[0]
    assert b.charge_llm(tokens=100, usd=0.4)[0]
    ok, why = b.charge_llm(tokens=100, usd=0.7)
    assert not ok and "budget_usd" in why
    assert not b.can_spend_llm()[0]
    with pytest.raises(BudgetExceeded):
        b.require_llm_budget()
    t = BudgetTracker(Limits(budget_usd=100.0, max_tokens=150))
    t.charge_llm(tokens=200)
    assert not t.can_spend_llm()[0] and "max_tokens" in t.can_spend_llm()[1]
    assert t.snapshot()["denied"]["llm_budget"] == 2


def test_sigint_engages_kill_switch():
    b = BudgetTracker(Limits())
    prev = install_kill_signal_handlers(b, signals=[signal.SIGINT])
    try:
        signal.raise_signal(signal.SIGINT)
        assert b.killed and "SIGINT" in b.kill_reason
        assert not b.try_consume_request("h")[0]
    finally:
        restore_signal_handlers(prev)


def test_pipeline_kill_file_denies_and_audits(tmp_path):
    p, ex, audit = _pipe(tmp_path)
    p.budget.kill_file = str(tmp_path / "KILL")
    (tmp_path / "KILL").write_text("")
    r = p.execute(_req())
    assert not r.executed and "kill" in r.decision.reason
    assert json.loads(open(audit.path, encoding="utf-8").readline())["budget"]["killed"] is True
