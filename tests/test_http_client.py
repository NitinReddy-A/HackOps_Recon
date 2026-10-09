"""The deterministic HTTP client: TLS to a pinned IP with hostname SNI/verification, a bounded
Host header, a wall-clock deadline, a body-size cap, and lossless repeated headers."""

from __future__ import annotations

import http.client
import os
import socket
import ssl
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from rampart.evidence.store import MAX_EVIDENCE_BODY_CHARS, EvidenceStore
from rampart.executor import http_client
from rampart.executor.http_client import HttpResponse, raw_request

TLS_DIR = os.path.join(os.path.dirname(__file__), "fixtures", "tls")
CA = os.path.join(TLS_DIR, "ca.pem")


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    seen_hosts: list = []

    def log_message(self, *a):
        pass

    def _send(self, status, body: bytes, extra=()):
        self.send_response(status)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        for k, v in extra:
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        _Handler.seen_hosts.append(self.headers.get("Host"))
        if self.path == "/trickle":
            self.send_response(200)
            self.send_header("Content-Length", "20")
            self.end_headers()
            try:
                for _ in range(20):
                    self.wfile.write(b"x")
                    self.wfile.flush()
                    time.sleep(0.3)
            except OSError:
                pass
            return
        if self.path == "/big":
            n = 2 * 1024 * 1024
            self.send_response(200)
            self.send_header("Content-Length", str(n))
            self.end_headers()
            try:
                chunk = b"A" * 65536
                for _ in range(n // len(chunk)):
                    self.wfile.write(chunk)
            except OSError:
                pass
            return
        if self.path == "/cookies":
            return self._send(
                200, b"ok", [("Set-Cookie", "session=abc; Path=/"), ("Set-Cookie", "pref=1; HttpOnly")]
            )
        if self.path == "/incomplete":
            self.send_response(200)
            self.send_header("Content-Length", "1000")
            self.end_headers()
            self.wfile.write(b"short")
            self.close_connection = True
            return
        return self._send(200, b"ok")


class _QuietServer(ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, request, client_address):
        pass  # rejected TLS handshakes are expected in these tests


@pytest.fixture
def http_server():
    srv = _QuietServer(("127.0.0.1", 0), _Handler)
    srv.daemon_threads = True
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield srv.server_address[1]
    srv.shutdown()
    srv.server_close()


@pytest.fixture
def tls_server():
    srv = _QuietServer(("127.0.0.1", 0), _Handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(os.path.join(TLS_DIR, "leaf.pem"), os.path.join(TLS_DIR, "leaf.key"))
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield srv.server_address[1]
    srv.shutdown()
    srv.server_close()


# ------------------------------------------------------------------ A5: TLS SNI to pinned IP
def test_https_verifies_hostname_while_connecting_to_vetted_ip(tls_server, monkeypatch):
    ctx = ssl.create_default_context(cafile=CA)
    # The fixture cert names only DNS:localhost — verifying against the IP must fail...
    raw = http.client.HTTPSConnection("127.0.0.1", tls_server, timeout=5, context=ctx)
    with pytest.raises(ssl.SSLCertVerificationError):
        raw.request("GET", "/")
    raw.close()

    # ...while Rampart connects the socket to the vetted IP and verifies the hostname.
    dialed = []
    real_create = socket.create_connection

    def spy(addr, *a, **kw):
        dialed.append(addr)
        return real_create(addr, *a, **kw)

    monkeypatch.setattr(http_client.socket, "create_connection", spy)
    r = raw_request("https", "localhost", tls_server, "127.0.0.1", "GET", "/", ssl_context=ctx)
    assert r.status == 200 and r.body == "ok"
    assert dialed == [("127.0.0.1", tls_server)]  # DNS-rebinding defense: the pinned IP, not a lookup


def test_https_still_rejects_untrusted_certificate(tls_server):
    with pytest.raises(ssl.SSLError):
        raw_request(
            "https",
            "localhost",
            tls_server,
            "127.0.0.1",
            "GET",
            "/",
            ssl_context=ssl.create_default_context(),
        )


# ------------------------------------------------------------------ A18b/A18c: Host header
def test_host_header_brackets_ipv6():
    assert http_client._host_header("::1", 8080) == "[::1]:8080"
    assert http_client._host_header("::1", 443) == "[::1]"
    assert http_client._host_header("example.test", 8080) == "example.test:8080"
    assert http_client._host_header("example.test", 80) == "example.test"


def test_caller_supplied_host_header_is_dropped(http_server):
    _Handler.seen_hosts.clear()
    raw_request(
        "http",
        "127.0.0.1",
        http_server,
        "127.0.0.1",
        "GET",
        "/",
        headers={"host": "evil.example", "X-A": "1"},
    )
    assert _Handler.seen_hosts == [f"127.0.0.1:{http_server}"]


def test_executor_drops_routable_host_but_allows_reserved_canary(http_server):
    from rampart.executor.http_client import HttpExecutor, is_reserved_canary_host
    from rampart.schemas.toolcall import ToolAction

    assert is_reserved_canary_host("rampart-hhi-canary.example")
    assert is_reserved_canary_host("x.test:8080")
    for bad in ("evil.com", "internal.corp", "localhost", "127.0.0.1", "a.example/x", ""):
        assert not is_reserved_canary_host(bad), bad
    with pytest.raises(ValueError):
        raw_request(
            "http", "127.0.0.1", http_server, "127.0.0.1", "GET", "/", host_header_override="evil.com"
        )

    ex = HttpExecutor()
    _Handler.seen_hosts.clear()
    for host in ("admin.internal.corp", "rampart-hhi-canary.example"):
        act = ToolAction(
            method="GET",
            target_host="127.0.0.1",
            port=http_server,
            scheme="http",
            path="/",
            headers={"Host": host},
        )
        assert ex.execute(act, "127.0.0.1").status == 200
    assert _Handler.seen_hosts == [f"127.0.0.1:{http_server}", "rampart-hhi-canary.example"]


# ------------------------------------------------------------------ B-10: deadline + caps
def test_wall_clock_deadline_on_slow_drip(http_server):
    start = time.monotonic()
    with pytest.raises(TimeoutError):
        raw_request("http", "127.0.0.1", http_server, "127.0.0.1", "GET", "/trickle", timeout=1.0)
    # Each byte arrives well inside the per-read timeout; only a wall-clock deadline stops it.
    assert time.monotonic() - start < 3.0


def test_body_is_capped_and_marked_truncated(http_server):
    cap = 256 * 1024
    r = raw_request("http", "127.0.0.1", http_server, "127.0.0.1", "GET", "/big", max_body_bytes=cap)
    assert r.truncated is True
    assert len(r.body) == cap


def test_small_body_not_truncated_and_incomplete_still_raises(http_server):
    r = raw_request("http", "127.0.0.1", http_server, "127.0.0.1", "GET", "/")
    assert r.status == 200 and r.body == "ok" and r.truncated is False
    with pytest.raises(http.client.IncompleteRead):
        raw_request("http", "127.0.0.1", http_server, "127.0.0.1", "GET", "/incomplete")


def test_evidence_store_caps_stored_body(tmp_path):
    store = EvidenceStore(str(tmp_path))
    resp = HttpResponse(status=200, headers={}, body="B" * (MAX_EVIDENCE_BODY_CHARS * 3), truncated=True)
    ev = store.put_response(resp)
    text = store.read(ev.storage_uri)
    assert len(text) < MAX_EVIDENCE_BODY_CHARS + 1024
    assert "evidence body truncated" in text
    assert "truncated by the HTTP client" in text


# ------------------------------------------------------------------ B-11: repeated headers
def test_repeated_set_cookie_headers_preserved(http_server):
    r = raw_request("http", "127.0.0.1", http_server, "127.0.0.1", "GET", "/cookies")
    assert r.set_cookies == ["session=abc; Path=/", "pref=1; HttpOnly"]
    assert r.headers["Set-Cookie"] == "pref=1; HttpOnly"  # dict view unchanged (last wins)
    assert [k for k, _ in r.header_list].count("Set-Cookie") == 2
