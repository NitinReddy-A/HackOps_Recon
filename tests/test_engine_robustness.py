"""Regression tests for analysis-engine robustness: the boolean SQLi oracle on time-varying pages,
retest control health (never "Fixed" on an outage), crawler resilience to malformed hrefs, OpenAPI
import shapes, and a truthful peak-concurrency metric."""

from __future__ import annotations

import itertools
import json
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from conftest import write_engagement

from rampart.appmodel.mapper import _endpoints_from_openapi
from rampart.executor.session import SessionError
from rampart.orchestration import Task, TaskGraph, run_graph
from rampart.recon.crawler import Crawler
from rampart.schemas.finding import Finding, State, Verification
from rampart.validation.oracle import run_bola_oracle
from rampart.validation.validator import Validator
from rampart.validation.web_oracles import _normalize_dynamic, run_sqli_oracle


# ------------------------------------------------------------------ fakes
class _Resp:
    def __init__(self, status, body, headers=None):
        self.status, self.body, self.headers = status, body, headers or {}

    @property
    def size(self):
        return len(self.body)


class _Outcome:
    def __init__(self, status, body, headers=None, executed=True):
        self.executed = executed
        self.response = _Resp(status, body, headers) if executed else None
        self.evidence = []

    @property
    def status(self):
        return getattr(self.response, "status", None)

    @property
    def body(self):
        return getattr(self.response, "body", "") or ""


class _FnRunner:
    def __init__(self, fn):
        self.fn = fn

    def get(self, path, session=None, query=None, **kw):
        return self.fn(path, session, dict(query or {}))


# ------------------------------------------------------------------ B-3: boolean SQLi oracle
_SQLI_HYP = {"endpoint_path": "/status", "selector_param": "page", "base_value": "1", "id": "h"}


def test_normalize_masks_dynamic_tokens():
    a = '{"t": "2026-10-09T11:22:33.123Z", "e": 1760000000.4, "m": 1760000000123, "id": "%s", "n": "%s"}'
    one = a % (uuid.uuid4(), "deadbeefcafebabe0123")
    two = a.replace("11:22:33.123", "11:22:34.999").replace("1760000000.4", "1760000001.9") % (
        uuid.uuid4(),
        "0123456789abcdef9999",
    )
    assert _normalize_dynamic(one) == _normalize_dynamic(two)
    assert _normalize_dynamic("Date: Fri, 09 Oct 2026 11:22:33 GMT") == "Date: <dyn>"
    assert _normalize_dynamic('{"price": 42, "id": 7}') == '{"price": 42, "id": 7}'  # small numbers kept


def test_boolean_sqli_not_confirmed_on_time_varying_benign_page():
    # A benign endpoint that ignores its params; its clock ticks every 4 requests. The old oracle
    # saw base==true (same tick) and false!=true (next tick) and "confirmed" this deterministically.
    calls = itertools.count()

    def fn(path, session, query):
        tick = next(calls) // 4
        body = json.dumps(
            {"status": "ok", "server_time": 1760000000 + tick, "at": f"2026-10-09T11:00:{tick % 60:02d}Z"}
        )
        return _Outcome(200, body, {"Content-Type": "application/json"})

    for _ in range(20):
        v = run_sqli_oracle(_FnRunner(fn), _SQLI_HYP)
        assert not v.validated, v.reasons


def test_boolean_sqli_still_confirmed_on_real_sink_with_timestamp():
    calls = itertools.count()

    def fn(path, session, query):
        val = query["page"]
        rows = [] if "'1'='2" in val else [{"id": 1, "name": "widget"}]
        body = json.dumps({"rows": rows, "generated_at": 1760000000 + next(calls)})
        return _Outcome(200, body, {"Content-Type": "application/json"})

    v = run_sqli_oracle(_FnRunner(fn), _SQLI_HYP)
    assert v.validated and v.controls["boolean_based"] and v.reproductions == 2


def test_boolean_sqli_requires_stable_false_condition():
    # The false condition flaps between two bodies — not a stable boolean oracle.
    false_calls = itertools.count()

    def fn(path, session, query):
        if "'1'='2" in query["page"]:
            return _Outcome(200, json.dumps({"rows": [], "flap": next(false_calls) % 2}))
        return _Outcome(200, json.dumps({"rows": [1]}))

    assert not run_sqli_oracle(_FnRunner(fn), _SQLI_HYP).validated


# ------------------------------------------------------------------ B-6: retest control health
_BOLA_HYP = {
    "id": "hyp1",
    "vuln_class": "IDOR/BOLA",
    "endpoint_path": "/api/orders/{id}",
    "selector_param": "id",
    "attacker_principal": "user_a",
    "victim_principal": "user_b",
    "attacker_object": {"id": "1", "signature": "SIG-A"},
    "victim_object": {"id": "2", "signature": "SIG-B"},
}


def _bola_target(mode):
    def fn(path, session, query):
        if mode == "down":
            return _Outcome(None, "", executed=False)
        if mode == "maint":
            return _Outcome(503, '{"error": "maintenance"}')
        oid = path.rsplit("/", 1)[-1]
        if session is None:
            return _Outcome(401, "{}")
        if oid not in ("1", "2"):
            return _Outcome(404, "{}")
        owner = "user_a" if oid == "1" else "user_b"
        if mode == "fixed" and owner != session:
            return _Outcome(403, '{"error": "forbidden"}')
        return _Outcome(200, json.dumps({"id": oid, "note": "SIG-A" if oid == "1" else "SIG-B"}))

    return fn


def _validated_finding():
    f = Finding(engagement_id="e", title="IDOR on orders", vuln_class="IDOR/BOLA")
    f.state = State.VALIDATED
    f.confidence = "confirmed"
    f.verification = Verification(validated=True, validator="validator")
    return f


def _validator(fn, sessions=None):
    v = Validator(pipeline=None, evidence_store=None, session_manager=sessions, host="127.0.0.1", port=1)
    v._runner = lambda phase, profile="validator": _FnRunner(fn)
    return v


def test_bola_verdict_reports_control_health():
    assert run_bola_oracle(_FnRunner(_bola_target("vuln")), None, _BOLA_HYP).validated
    fixed = run_bola_oracle(_FnRunner(_bola_target("fixed")), None, _BOLA_HYP)
    assert not fixed.validated and fixed.controls_ok and not fixed.inconclusive
    for mode in ("maint", "down"):
        v = run_bola_oracle(_FnRunner(_bola_target(mode)), None, _BOLA_HYP)
        assert not v.validated and not v.controls_ok and v.inconclusive


def test_retest_fixed_only_with_healthy_controls():
    f = _validated_finding()
    assert _validator(_bola_target("fixed")).retest(f, _BOLA_HYP) == "Fixed"
    assert f.state == State.FIXED


def test_retest_outage_is_inconclusive_not_fixed():
    for mode in ("maint", "down"):
        f = _validated_finding()
        assert _validator(_bola_target(mode)).retest(f, _BOLA_HYP) == "inconclusive"
        assert f.state == State.VALIDATED and f.status != "fixed"
        assert f.verification.last_retest["result"] == "inconclusive"


def test_retest_session_or_socket_error_is_inconclusive():
    class _Boom:
        def __init__(self, exc):
            self.exc = exc

        def fresh_session(self, account_id):
            raise self.exc

    for exc in (SessionError("login failed with HTTP 503"), ConnectionRefusedError("refused")):
        f = _validated_finding()
        assert _validator(_bola_target("fixed"), sessions=_Boom(exc)).retest(f, _BOLA_HYP) == "inconclusive"
        assert f.state == State.VALIDATED


class _MaintHandler(BaseHTTPRequestHandler):
    """Target in maintenance: login works, every other request returns 503."""

    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _s(self, st, obj):
        b = json.dumps(obj).encode()
        self.send_response(st)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length", 0)))
        if self.path == "/api/login":
            return self._s(200, {"token": "tok-maint", "user_id": "u1"})
        return self._s(503, {"error": "maintenance"})

    def do_GET(self):
        return self._s(503, {"error": "maintenance"})


def test_retest_against_maintenance_target_is_not_fixed(tmp_path, vuln_server):
    from conftest import make_engagement

    from rampart.engagement import Engagement, EngagementConfig

    eng = make_engagement(tmp_path, vuln_server.port)
    eng.run_scan()
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _MaintHandler)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        port = srv.server_address[1]
        cfg_dir = tmp_path / "maintcfg"
        cfg_dir.mkdir()
        scope_file = write_engagement(cfg_dir, port)
        cfg = EngagementConfig(
            scope_file=scope_file,
            target=f"http://127.0.0.1:{port}",
            work_dir=eng.cfg.work_dir,
            openapi=str(cfg_dir / "openapi.json"),
            appmodel_seed=str(cfg_dir / "seed.json"),
            application="demo-shop-api",
        )
        results = Engagement(cfg).retest()
    finally:
        srv.shutdown()
        srv.server_close()
    assert results
    assert all(outcome != "Fixed" for _, outcome in results), results
    assert all(f.state != State.FIXED for f, _ in results)


# ------------------------------------------------------------------ B-7: crawler malformed hrefs
class _Scope:
    def host_scope(self, host):
        class _HS:
            paths_include = ["/**"]

        return _HS()

    def path_excluded(self, path):
        return False


def test_crawler_skips_malformed_ipv6_href():
    pages = {
        "/": '<html><a href="http://[bad/x">bad</a><a href="//[x/y">bad2</a><a href="/after?z=1">ok</a>'
        '<form action="http://[bad/f"><input name="q"></form></html>',
        "/after": "<html>done</html>",
    }

    def fn(path, session, query):
        if path in pages:
            return _Outcome(200, pages[path], {"Content-Type": "text/html"})
        return _Outcome(404, "nf", {"Content-Type": "text/plain"})

    res = Crawler(_FnRunner(fn), _Scope(), "127.0.0.1", 8080, "http").crawl(["/"])
    paths = {e.path for e in res.endpoints}
    assert "/after" in paths  # links after the malformed one are still followed
    assert res.pages_visited == 2


def test_crawler_same_host_check_with_ipv6_target():
    c = Crawler(_FnRunner(lambda *a: None), _Scope(), "::1", 8080, "http")
    assert c._same_host("/a?b=1", "/") == "/a?b=1"
    assert c._same_host("http://[::1]:8080/c", "/") == "/c"
    assert c._same_host("http://other.example/c", "/") is None


# ------------------------------------------------------------------ B-12: OpenAPI shapes
def test_openapi_refs_path_level_params_and_server_base():
    spec = {
        "openapi": "3.0.0",
        "servers": [{"url": "/v1"}],
        "components": {
            "parameters": {
                "Q": {"name": "q", "in": "query", "schema": {"type": "string"}},
                "Loop": {"$ref": "#/components/parameters/Loop"},
            }
        },
        "paths": {
            "/search": {"get": {"parameters": [{"$ref": "#/components/parameters/Q"}]}},
            "/items/{id}": {
                "parameters": [
                    {"name": "id", "in": "path", "schema": {"type": "string"}},
                    {"name": "fmt", "in": "query"},
                ],
                "get": {"parameters": [{"name": "id", "in": "path", "schema": {"type": "integer"}}]},
                "delete": {"parameters": [{"$ref": "#/components/parameters/Loop"}]},
            },
        },
    }
    eps = {(e.method, e.path): e for e in _endpoints_from_openapi(spec)}
    assert set(eps) == {("GET", "/v1/search"), ("GET", "/v1/items/{id}"), ("DELETE", "/v1/items/{id}")}
    assert eps[("GET", "/v1/search")].parameters == [{"name": "q", "in": "query", "type": "string"}]
    get_item = {(p["name"], p["in"]): p["type"] for p in eps[("GET", "/v1/items/{id}")].parameters}
    assert get_item == {("id", "path"): "integer", ("fmt", "query"): "string"}  # op overrides path-level
    del_item = {(p["name"], p["in"]) for p in eps[("DELETE", "/v1/items/{id}")].parameters}
    assert del_item == {("id", "path"), ("fmt", "query")}  # cyclic $ref ignored, no crash


def test_openapi_absolute_server_url_base_path():
    spec = {"servers": [{"url": "https://api.example.test/api/v2/"}], "paths": {"/x": {"get": {}}}}
    assert [e.path for e in _endpoints_from_openapi(spec)] == ["/api/v2/x"]
    spec = {"servers": [{"url": "http://127.0.0.1:8080"}], "paths": {"/x": {"get": {}}}}
    assert [e.path for e in _endpoints_from_openapi(spec)] == ["/x"]


# ------------------------------------------------------------------ B-15: peak concurrency
def test_peak_concurrency_counts_running_tasks_not_queued_futures():
    g = TaskGraph()
    lock = threading.Lock()
    state = {"now": 0, "max": 0}

    def work(ctx):
        with lock:
            state["now"] += 1
            state["max"] = max(state["max"], state["now"])
        time.sleep(0.05)
        with lock:
            state["now"] -= 1
        return 1

    tasks = [Task(name=f"t{i}", run=work, kind="w") for i in range(12)]
    g.add_all(tasks)
    res = run_graph(g, max_workers=2)
    assert res.max_concurrency <= 2  # was 12: every queued future was counted
    assert res.max_concurrency == state["max"]
    # started is stamped when a worker actually begins, so later tasks start later
    starts = sorted(t.started for t in tasks)
    assert starts[-1] - starts[0] >= 0.1
