"""JS/SPA route discovery — the pure normaliser (no browser) + a gated live-browser integration.

The normaliser (:func:`rampart.browser.endpoints_from_discovery`) is Playwright-independent, so the
scope-filter / param-merge / dedup / provenance logic is unit-tested with no Chromium. The
integration test serves a tiny SPA whose routes are injected by JavaScript AFTER load (invisible to
a static HTML parse) and asserts the real browser discovers them — while a JS-injected out-of-scope
link is never discovered. It is skipped automatically when Playwright/Chromium are absent.
"""

import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from conftest import write_engagement

from rampart.browser import browser_discover, endpoints_from_discovery
from rampart.browser.engine import RenderResult, StubDriver
from rampart.engagement import Engagement, EngagementConfig

TARGET = "http://127.0.0.1:19200"


# --------------------------------------------------------------- pure normaliser (no browser)
def test_normaliser_keeps_only_in_scope():
    links = [
        "/api/hidden?x=1",  # in scope (relative)
        "http://127.0.0.1:19200/page",  # in scope (absolute, same origin)
        "http://example.invalid/evil",  # OUT of scope (other host)
        "http://127.0.0.1:19299/other",  # OUT of scope (other port)
        "javascript:alert(1)",  # not a route
        "#section",  # same-page fragment, not a route
        "mailto:x@y.z",  # not a route
    ]
    reqs = [
        {"method": "GET", "url": TARGET + "/api/data?id=2"},  # in scope fetch/XHR
        {"method": "GET", "url": "http://evil.test/collect?c=1"},  # OUT of scope
    ]
    eps = endpoints_from_discovery(TARGET, links=links, requests=reqs)
    paths = {(e.method, e.path) for e in eps}
    assert ("GET", "/api/hidden") in paths
    assert ("GET", "/page") in paths
    assert ("GET", "/api/data") in paths
    # nothing out-of-scope or non-navigable leaked in
    assert all(e.path not in ("/evil", "/other", "/collect") for e in eps)
    assert all("example.invalid" not in e.path and "evil.test" not in e.path for e in eps)


def test_normaliser_merges_params_and_dedups():
    # Same (method, path) seen from an anchor AND a fetch -> ONE endpoint, params merged.
    links = ["/api/x?a=1"]
    reqs = [{"method": "GET", "url": TARGET + "/api/x?b=2"}, {"method": "GET", "url": TARGET + "/api/x?a=9"}]
    eps = endpoints_from_discovery(TARGET, links=links, requests=reqs)
    xs = [e for e in eps if e.path == "/api/x"]
    assert len(xs) == 1, "dedup by (method, path)"
    names = {p["name"] for p in xs[0].parameters}
    assert names == {"a", "b"}
    assert all(p["in"] == "query" for p in xs[0].parameters)


def test_normaliser_forms_query_vs_body_and_provenance():
    forms = [
        {"action": TARGET + "/search", "method": "GET", "inputs": ["q"]},
        {"action": TARGET + "/submit", "method": "POST", "inputs": ["name", "email"]},
        {"action": "http://example.invalid/x", "method": "POST", "inputs": ["secret"]},  # out of scope
    ]
    eps = endpoints_from_discovery(TARGET, forms=forms)
    by = {(e.method, e.path): e for e in eps}
    assert by[("GET", "/search")].parameters == [{"name": "q", "in": "query", "type": "string"}]
    submit = by[("POST", "/submit")]
    assert {(p["name"], p["in"]) for p in submit.parameters} == {("name", "body"), ("email", "body")}
    assert all(e.provenance == "browser" for e in eps)  # distinguishable from crawl/spec
    assert not any("example.invalid" in e.path for e in eps)


def test_normaliser_post_request_has_no_query_params():
    # A non-GET network request contributes just (method, path) — body params are not observable.
    reqs = [{"method": "POST", "url": TARGET + "/api/write?ignored=1"}]
    eps = endpoints_from_discovery(TARGET, requests=reqs)
    assert len(eps) == 1 and eps[0].method == "POST" and eps[0].path == "/api/write"
    assert eps[0].parameters == []


def test_normaliser_custom_allow_predicate_is_authoritative():
    # A caller-supplied predicate (the policy pipeline's scope check) overrides same-origin default.
    def allow(url, method="GET"):
        return "/public/" in url

    links = ["/public/a?k=1", "/private/b"]
    eps = endpoints_from_discovery(TARGET, links=links, allow=allow)
    assert {e.path for e in eps} == {"/public/a"}


# --------------------------------------------------------------- browser_discover (StubDriver, no browser)
def test_browser_discover_with_stub_driver():
    rr = RenderResult(
        discovered_links=["/api/hidden?x=1", "http://example.invalid/evil"],
        discovered_requests=[{"method": "GET", "url": TARGET + "/api/data?id=2"}],
        discovered_forms=[{"action": TARGET + "/s", "method": "GET", "inputs": ["q"]}],
    )
    crawl = browser_discover(StubDriver(default=rr), TARGET)
    paths = {(e.method, e.path) for e in crawl.endpoints}
    assert paths == {("GET", "/api/hidden"), ("GET", "/api/data"), ("GET", "/s")}
    assert crawl.pages_visited == 1
    assert all(e.provenance == "browser" for e in crawl.endpoints)


def test_browser_discover_unavailable_driver_is_clean_noop():
    class _Down(StubDriver):
        def is_available(self):
            return False

    crawl = browser_discover(_Down(), TARGET)
    assert crawl.endpoints == [] and crawl.pages_visited == 0


# --------------------------------------------------------------- engagement skip (no browser)
def test_browser_discovery_visible_skip_when_extra_absent(tmp_path, monkeypatch):
    import rampart.browser as browser

    monkeypatch.setattr(browser, "browser_skip_reason", lambda: "browser: skipped — install it")
    scope = write_engagement(tmp_path, 19201)
    cfg = EngagementConfig(
        scope_file=scope,
        target="http://127.0.0.1:19201",
        work_dir=str(tmp_path / ".rampart"),
        openapi="",
        appmodel_seed="",
        application="demo-spa",
        browser=True,
    )
    eng = Engagement(cfg)
    eng._stage_log = []
    assert eng.browser_discovery() is None
    assert eng.browser_discovered == 0
    assert any("browser: skipped" in e["msg"] for e in eng._stage_log)


# --------------------------------------------------------------- gated live-browser integration
def _free_port(lo=19200, hi=19249):
    for p in range(lo, hi + 1):
        s = socket.socket()
        try:
            s.bind(("127.0.0.1", p))
            s.close()
            return p
        except OSError:
            s.close()
    raise RuntimeError("no free port in 19200-19249")


# A tiny SPA: the two real routes (/api/hidden, /api/data) + an out-of-scope link are injected by
# JavaScript AFTER load, so a static HTML parse of the served source would never see them.
_SPA_HTML = (
    b"<!doctype html><html><body><div id=app></div><script>"
    b"document.body.innerHTML += '<a href=\"/api/hidden?x=1\">hidden</a>';"
    b"document.body.innerHTML += '<a href=\"http://example.invalid/evil\">evil</a>';"
    b"fetch('/api/data?id=2');"
    b"</script></body></html>"
)


def _spa_server(port):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            if self.path.startswith("/api/data"):
                body = b"{}"
                ctype = "application/json"
            elif self.path == "/" or self.path.startswith("/?"):
                body = _SPA_HTML
                ctype = "text/html"
            else:
                self.send_response(404)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    srv = ThreadingHTTPServer(("127.0.0.1", port), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def test_browser_discovers_js_injected_spa_routes(tmp_path):
    pytest.importorskip("playwright.sync_api")
    from rampart.browser import available

    if not available():
        pytest.skip("chromium not installed")

    port = _free_port()
    srv = _spa_server(port)
    try:
        scope = write_engagement(tmp_path, port)
        cfg = EngagementConfig(
            scope_file=scope,
            target=f"http://127.0.0.1:{port}",
            work_dir=str(tmp_path / ".rampart"),
            openapi="",  # no spec/seed: the attack surface must come from browser discovery
            appmodel_seed="",
            application="demo-spa",
            browser=True,
        )
        eng = Engagement(cfg)
        assert eng.appmodel.endpoints == []  # nothing known before discovery
        eng.browser_discovery()
        by = {(e.method, e.path): e for e in eng.appmodel.endpoints}

        # the JS-injected anchor (DOM harvest) and the fetch (network harvest) are both found...
        assert ("GET", "/api/hidden") in by, by.keys()
        assert ("GET", "/api/data") in by, by.keys()
        # ...with their query params...
        assert any(p["name"] == "x" for p in by[("GET", "/api/hidden")].parameters)
        assert any(p["name"] == "id" for p in by[("GET", "/api/data")].parameters)
        # ...all provenance=browser...
        assert all(e.provenance == "browser" for e in eng.appmodel.endpoints)
        # ...and the JS-injected OUT-OF-SCOPE link is never discovered.
        assert ("GET", "/evil") not in by
        assert not any("example.invalid" in e.path for e in eng.appmodel.endpoints)
    finally:
        srv.shutdown()
