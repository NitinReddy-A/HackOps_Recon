"""Tests for the OPTIONAL headless-browser engine (rampart/browser).

No real browser is used: the oracle logic is driven entirely through StubDriver, and the
"Playwright absent" degradation path is exercised deterministically by simulating the lazy
import failing. These pass whether or not Playwright happens to be installed on the host.
"""

import rampart.browser.engine as engine
from rampart.browser.engine import (
    DOMXSS_TOKEN,
    PlaywrightDriver,
    RenderResult,
    StubDriver,
    available,
    run_dom_xss_oracle,
    run_stored_xss_oracle,
)

BASE = "http://127.0.0.1:65500"  # arbitrary; StubDriver matches on URL substrings, not the host


# --------------------------------------------------------------------- DOM XSS oracle
def test_dom_xss_confirmed_when_canary_executes():
    # The malicious URL carries the "__rampart_xss" binding call; the benign control value does
    # not, so the benign render falls through to the default (empty) RenderResult -> no execution.
    stub = StubDriver({"__rampart_xss": RenderResult(html="<x>", executed_markers=[DOMXSS_TOKEN])})
    v = run_dom_xss_oracle(stub, BASE, "/page", "q")
    assert v.validated is True
    assert v.vuln_class == "DOM_XSS"
    assert v.reproductions >= 2
    assert v.controls["payload_executes"] is True
    assert v.controls["control_executed"] is False
    assert any("EXECUTED" in r for r in v.reasons)


def test_dom_xss_not_confirmed_when_payload_never_executes():
    # Payload is reflected but never executes (empty executed_markers everywhere).
    stub = StubDriver({"__rampart_xss": RenderResult(html="<x>", executed_markers=[])})
    v = run_dom_xss_oracle(stub, BASE, "/page", "q")
    assert v.validated is False
    assert v.reproductions == 0


def test_dom_xss_not_confirmed_when_control_also_executes():
    # Even if the payload executes, a benign control that ALSO "executes" the token means the
    # signal is environment noise, not our injection -> the FP gate must refuse to confirm.
    stub = StubDriver({}, default=RenderResult(executed_markers=[DOMXSS_TOKEN]))
    v = run_dom_xss_oracle(stub, BASE, "/page", "q")
    assert v.controls["control_executed"] is True
    assert v.validated is False


def test_dom_xss_console_message_counts_as_execution():
    # Execution proven via a console message carrying the token (secondary signal).
    stub = StubDriver({"__rampart_xss": RenderResult(console=[f"hello {DOMXSS_TOKEN}"])})
    v = run_dom_xss_oracle(stub, BASE, "/page", "q")
    assert v.validated is True


# --------------------------------------------------------------------- stored XSS oracle
def test_stored_xss_confirmed_when_token_executes_on_reads():
    token = "RAMPART_DOMXSS_stored_demo"
    stub = StubDriver({"/read": RenderResult(executed_markers=[token])})
    v = run_stored_xss_oracle(stub, True, f"{BASE}/read", token)
    assert v.validated is True
    assert v.vuln_class == "STORED_XSS"
    assert v.reproductions >= 2


def test_stored_xss_not_confirmed_when_token_never_executes():
    token = "RAMPART_DOMXSS_stored_demo"
    stub = StubDriver({"/read": RenderResult(executed_markers=[])})
    v = run_stored_xss_oracle(stub, True, f"{BASE}/read", token)
    assert v.validated is False
    assert v.reproductions == 0


def test_stored_xss_requires_write_precondition():
    # The payload executes on read, but the write is reported as failed -> cannot confirm.
    token = "RAMPART_DOMXSS_stored_demo"
    stub = StubDriver({"/read": RenderResult(executed_markers=[token])})
    v = run_stored_xss_oracle(stub, False, f"{BASE}/read", token)
    assert v.validated is False
    assert v.controls["write_ok"] is False


# --------------------------------------------------------------------- graceful degradation
def test_module_imports_cleanly_without_playwright():
    # Importing the engine must never require Playwright (all imports are lazy, inside methods).
    assert engine is not None
    assert hasattr(engine, "PlaywrightDriver")


def test_playwright_is_available_returns_bool_without_raising():
    # Honours the real environment: returns a bool and never raises, Playwright present or not.
    val = PlaywrightDriver().is_available()
    assert isinstance(val, bool)
    assert isinstance(available(), bool)


def test_playwright_driver_unavailable_when_playwright_absent(monkeypatch):
    # Simulate "Playwright not installed": is_available() is False and render() degrades to an
    # empty RenderResult, both without raising.
    def _boom(*a, **k):
        raise ImportError("No module named 'playwright'")

    monkeypatch.setattr(engine, "_load_playwright", _boom)
    d = PlaywrightDriver()
    assert d.is_available() is False
    assert "playwright install" in d.install_hint
    r = d.render(f"{BASE}/anything")
    assert isinstance(r, RenderResult)
    assert r.executed_markers == []
    assert r.ok is False


def test_dom_xss_oracle_degrades_when_engine_unavailable(monkeypatch):
    # An unavailable driver yields a non-validated verdict instead of an exception.
    monkeypatch.setattr(engine, "_load_playwright", lambda *a, **k: (_ for _ in ()).throw(ImportError()))
    v = run_dom_xss_oracle(PlaywrightDriver(), BASE, "/page", "q")
    assert v.validated is False
    assert v.controls["engine_available"] is False


# --------------------------------------------------------------------- C-4 reflected/DOM dedupe
def test_dom_xss_deduped_when_server_reflects_payload():
    """If the raw payload appears in the server HTTP body, it is reflected XSS -> DOM oracle skips."""
    from rampart.browser.engine import _canary_payloads

    first = _canary_payloads(DOMXSS_TOKEN)[0]

    # Simulate a server that REFLECTS the first canary into its HTML AND executes it.
    stub = StubDriver(
        {"__rampart_xss": RenderResult(executed_markers=[DOMXSS_TOKEN], response_body=f"<p>{first}</p>")}
    )
    v = run_dom_xss_oracle(stub, BASE, "/api/search", "q")
    assert v.validated is False  # reflected, not DOM-based
    assert v.controls["server_reflected"] is True
    assert any("deduped" in r for r in v.reasons)


def test_dom_xss_confirmed_when_payload_absent_from_body():
    # Executes but the raw payload is NOT in the server body -> client-side DOM sink (innerHTML).
    stub = StubDriver(
        {"__rampart_xss": RenderResult(executed_markers=[DOMXSS_TOKEN], response_body="<div id=out></div>")}
    )
    v = run_dom_xss_oracle(stub, BASE, "/dom", "x")
    assert v.validated is True
    assert v.controls["is_dom_sink"] is True


def test_canary_payloads_use_innerhtml_capable_markup():
    from rampart.browser.engine import _canary_payload, _canary_payloads

    assert "onerror" in _canary_payload("TOK")  # primary is img/onerror, not a bare <script>
    kinds = _canary_payloads("TOK")
    assert any("onerror" in p for p in kinds) and any("onload" in p for p in kinds)


# --------------------------------------------------------------------- C-13 skip reason
def test_browser_skip_reason(monkeypatch):
    monkeypatch.setattr("rampart.browser.engine.available", lambda: False)
    assert engine.browser_skip_reason().startswith("browser: skipped —")
    monkeypatch.setattr("rampart.browser.engine.available", lambda: True)
    assert engine.browser_skip_reason() == ""


# --------------------------------------------------------------------- C-11 on_request auditing
def test_oracle_forwards_allow_and_on_request_to_driver():
    seen = {}

    class _Spy(StubDriver):
        def render(self, url, headers=None, timeout=10.0, allow=None, on_request=None):
            seen["allow"] = allow
            seen["on_request"] = on_request
            return super().render(url, headers, timeout, allow, on_request)

    spy = _Spy({"__rampart_xss": RenderResult(executed_markers=[DOMXSS_TOKEN])})

    def sentinel_allow(u, m="GET"):
        return True

    def sentinel_audit(u, m, ok):
        return None

    run_dom_xss_oracle(spy, BASE, "/dom", "x", allow=sentinel_allow, on_request=sentinel_audit)
    assert seen["allow"] is sentinel_allow
    assert seen["on_request"] is sentinel_audit


# --------------------------------------------------------------------- same-origin default predicate
def test_same_origin_allow_default():
    from rampart.browser.engine import same_origin_allow

    allow = same_origin_allow("http://127.0.0.1:18850/page")
    assert allow("http://127.0.0.1:18850/img", "GET") is True
    assert allow("http://127.0.0.1:18851/img", "GET") is False  # different port
    assert allow("http://evil.example.com/x", "GET") is False  # different host
    assert allow("about:blank", "GET") is True  # non-network
    assert allow("data:text/html,x", "GET") is True


# --------------------------------------------------------------------- C-3 route guard (real browser)
def test_route_guard_blocks_out_of_scope_subrequests(tmp_path):
    import pytest

    pytest.importorskip("playwright.sync_api")
    if not available():
        pytest.skip("chromium not installed")
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    hits = {"a": [], "b": []}

    def server(port, role, other=0):
        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                hits[role].append(self.path)
                if role == "a" and self.path.startswith("/redir"):
                    self.send_response(302)
                    self.send_header("Location", f"http://127.0.0.1:{other}/redirected")
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                body = (
                    (
                        f'<img src="http://127.0.0.1:{other}/img">'
                        f'<iframe src="http://127.0.0.1:{other}/frame"></iframe>'
                        "<p>hi</p>"
                    ).encode()
                    if role == "a"
                    else b"out-of-scope"
                )
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        s = ThreadingHTTPServer(("127.0.0.1", port), H)
        threading.Thread(target=s.serve_forever, daemon=True).start()
        return s

    import socket

    def _free():
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        p = s.getsockname()[1]
        s.close()
        return p

    pa, pb = _free(), _free()
    a = server(pa, "a", pb)
    b = server(pb, "b")
    audited = []
    try:
        drv = PlaywrightDriver()
        r = drv.render(
            f"http://127.0.0.1:{pa}/page",
            on_request=lambda u, m, ok: audited.append((u, ok)),
        )
    finally:
        a.shutdown()
        b.shutdown()
    # the out-of-scope origin (port pb) must never have been hit by the browser
    assert hits["b"] == [], hits["b"]
    assert any(f":{pb}" in u and ok is False for u, ok in audited)
    assert any(f":{pb}" in u for u, m in r.blocked_requests)


def test_route_guard_blocks_redirect_to_other_origin(tmp_path):
    import pytest

    pytest.importorskip("playwright.sync_api")
    if not available():
        pytest.skip("chromium not installed")
    import socket
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    hits = {"a": [], "b": []}

    def _free():
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        p = s.getsockname()[1]
        s.close()
        return p

    pa, pb = _free(), _free()

    def server(port, role, other=0):
        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                hits[role].append(self.path)
                if role == "a":
                    self.send_response(302)
                    self.send_header("Location", f"http://127.0.0.1:{other}/redirected")
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                body = b"out-of-scope"
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        s = ThreadingHTTPServer(("127.0.0.1", port), H)
        threading.Thread(target=s.serve_forever, daemon=True).start()
        return s

    a = server(pa, "a", pb)
    b = server(pb, "b")
    try:
        PlaywrightDriver().render(f"http://127.0.0.1:{pa}/redir")
    finally:
        a.shutdown()
        b.shutdown()
    assert hits["b"] == [], "a redirect to another origin must be blocked by the route guard"
