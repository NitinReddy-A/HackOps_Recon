"""Seeded-account logins go through the policy choke-point (reviewer finding A2) and the SQLite
store URL follows the SQLAlchemy convention (A18a)."""

import os
import socket

import pytest

from rampart.audit import AuditLog
from rampart.executor import session as session_mod
from rampart.executor.http_client import HttpExecutor
from rampart.executor.session import LoginConfig, SessionError, SessionManager
from rampart.policy import PolicyPipeline
from rampart.policy.budget import BudgetTracker
from rampart.schemas.scope import EngagementScope
from rampart.store.sql_store import SqlRunStore, sqlite_path_from_url

SCOPE = """
apiVersion: v1
kind: EngagementScope
authorization: {owner: o, authorized_by: c, ticket: T, attestation: ok, expires: "2099-01-01T00:00:00Z"}
scope:
  in_scope:
    - host: "127.0.0.1"
      ports: [18961]
      paths_include: ["/**"]
      methods: ["GET", "POST"]
  out_of_scope: {paths_exclude: ["/admin/**"], hosts_exclude: []}
  resolved_ip_allowlist: ["127.0.0.1/32"]
limits: {max_requests_per_host_per_min: 100, max_total_requests: 100}
test_accounts: [{id: user_a, role: customer, secret_ref: "v://a"}]
"""


class _Secrets:
    def resolve(self, ref):
        return {"username": "u", "password": "hunter2"}


class _Resp:
    status = 200
    body = '{"token": "tok"}'
    headers = {}
    body_sha256 = ""
    size = 0
    duration_ms = 0.0


@pytest.fixture
def sent(monkeypatch):
    calls = []

    def fake_raw_request(scheme, host, port, ip, method, path, headers=None, body=None, **kw):
        calls.append({"scheme": scheme, "host": host, "port": port, "ip": ip, "method": method, "path": path})
        return _Resp()

    monkeypatch.setattr(session_mod, "raw_request", fake_raw_request)
    return calls


def _mgr(tmp_path, with_pipeline=True, **login_kw):
    scope = EngagementScope.from_text(SCOPE)
    audit = AuditLog(str(tmp_path / "audit.jsonl"))
    login = LoginConfig(
        **{"scheme": "http", "host": "127.0.0.1", "port": 18961, "path": "/api/login", **login_kw}
    )
    sm = SessionManager(scope, _Secrets(), login, lambda h: ["127.0.0.1"], audit_log=audit)
    budget = BudgetTracker(scope.limits)
    if with_pipeline:
        PolicyPipeline(scope, audit, budget, HttpExecutor(sm), resolver=lambda h: ["127.0.0.1"])
    return sm, audit, budget


def test_pipeline_attaches_itself_to_the_session_manager(tmp_path):
    sm, _, _ = _mgr(tmp_path)
    assert sm.pipeline is not None


def test_in_scope_login_goes_through_pipeline_budget_and_audit(tmp_path, sent):
    sm, audit, budget = _mgr(tmp_path)
    assert sm.establish("user_a") == "tok"
    assert len(sent) == 1 and sent[0]["port"] == 18961 and sent[0]["ip"] == "127.0.0.1"
    assert budget.total_requests == 1
    evs = audit.read_all()
    assert (
        evs[0].action["tool"] == "login"
        and evs[0].action["port"] == 18961
        and evs[0].action["scheme"] == "http"
    )
    assert evs[0].action["payload_hash"] == "<redacted:credentials>"
    assert "hunter2" not in open(audit.path, encoding="utf-8").read()
    assert audit.verify_chain()[0]


@pytest.mark.parametrize(
    "login_kw",
    [
        {"port": 18962},  # port not in scope
        {"path": "/admin/login"},  # excluded path
        {"method": "PUT"},  # method not in scope
        {"scheme": "ftp"},
        {"host": "evil.example"},
        {"extra_headers": {"Host": "other-tenant.com"}},
    ],
)
def test_out_of_scope_login_refused_without_network(tmp_path, sent, login_kw):
    sm, audit, _ = _mgr(tmp_path, **login_kw)
    with pytest.raises(SessionError):
        sm.establish("user_a")
    assert sent == []
    assert audit.read_all()[0].policy_decision["decision"] == "DENY"


def test_login_refused_when_killed(tmp_path, sent):
    sm, _, budget = _mgr(tmp_path)
    budget.kill("stop")
    with pytest.raises(SessionError):
        sm.establish("user_a")
    assert sent == []


def test_standalone_manager_still_checks_scope(tmp_path, sent):
    sm, audit, _ = _mgr(tmp_path, with_pipeline=False, port=18962)
    with pytest.raises(SessionError):
        sm.establish("user_a")
    assert sent == []
    sm2, audit2, _ = _mgr(tmp_path / "b", with_pipeline=False)
    assert sm2.establish("user_a") == "tok"
    assert audit2.read_all()[0].action["port"] == 18961


def test_no_scope_refuses_login(tmp_path, sent):
    sm = SessionManager(None, _Secrets(), LoginConfig(), lambda h: ["127.0.0.1"])
    with pytest.raises(SessionError):
        sm.establish("user_a")
    assert sent == []


def test_connection_error_is_a_clean_session_error(tmp_path):
    # nothing listens on 18961 (reserved test range); a refused connect must surface as SessionError
    with socket.socket() as s:
        if s.connect_ex(("127.0.0.1", 18961)) == 0:
            pytest.skip("port 18961 unexpectedly in use")
    sm, _, _ = _mgr(tmp_path)
    with pytest.raises(SessionError):
        sm.fresh_session("user_a")
    sm2, _, _ = _mgr(tmp_path / "b", with_pipeline=False)
    with pytest.raises(SessionError):
        sm2.fresh_session("user_a")


# --------------------------------------------------------------------- A18(a)
@pytest.mark.parametrize(
    "url,path",
    [
        ("sqlite:///runs.db", "runs.db"),
        ("sqlite:///sub/runs.db", "sub/runs.db"),
        ("sqlite:////var/lib/rampart.db", "/var/lib/rampart.db"),
        ("sqlite:///C:/data/runs.db", "C:/data/runs.db"),
        ("sqlite:///:memory:", ":memory:"),
        ("sqlite://", ""),
        ("plain/path.db", "plain/path.db"),
    ],
)
def test_sqlite_url_convention(url, path):
    assert sqlite_path_from_url(url) == path


def test_sqlite_url_with_host_rejected():
    with pytest.raises(ValueError):
        sqlite_path_from_url("sqlite://host/runs.db")


def test_relative_sqlite_url_is_relative_to_cwd(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    store = SqlRunStore("sqlite:///runs.db", str(tmp_path / "w"), engagement="E")
    store.save_scan({"x": 1})
    store.close()
    assert os.path.exists(tmp_path / "runs.db")
