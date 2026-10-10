"""Detection-accuracy regression tests for the content-proof oracles.

These prove the oracles confirm on *real* vulnerable response content, not on a marker the
bundled demo happens to emit, and — crucially — that a benign server which merely **reflects**
its query parameters is NOT confirmed for CMDI / SSRF / PATH_TRAVERSAL (no false positives).

Everything runs in-process against throwaway stdlib ``http.server`` decoys on ephemeral loopback
ports; the oracles are driven through a tiny live runner that issues real GETs and returns the
same ``.executed/.status/.body`` surface the real :class:`ProbeRunner` exposes.
"""

from __future__ import annotations

import json
import threading
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from rampart.validation.more_oracles import (
    run_cmdi_oracle,
    run_ssrf_oracle,
    run_traversal_oracle,
)


# --------------------------------------------------------------------------- live runner
class _Resp:
    def __init__(self, status, body, headers):
        self.status = status
        self.body = body
        self.headers = headers


class _Outcome:
    def __init__(self, executed, response):
        self.executed = executed
        self.response = response
        self.evidence = []

    @property
    def status(self):
        return getattr(self.response, "status", None)

    @property
    def body(self):
        return getattr(self.response, "body", "") or ""


class _LiveRunner:
    """Minimal runner that issues real GETs to a loopback decoy and mirrors ProbeOutcome."""

    engagement_id = "eng-oracle-accuracy"

    def __init__(self, port, host="127.0.0.1"):
        self.host, self.port = host, port

    def get(self, path, session=None, query=None, headers=None, **kw):
        url = f"http://{self.host}:{self.port}{path}"
        if query:
            url += "?" + urllib.parse.urlencode(query)
        req = urllib.request.Request(url, headers=dict(headers or {}))
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                body = r.read().decode("utf-8", "replace")
                return _Outcome(True, _Resp(r.status, body, dict(r.headers.items())))
        except urllib.error.HTTPError as e:  # a 4xx/5xx is still an executed request
            body = e.read().decode("utf-8", "replace")
            return _Outcome(True, _Resp(e.code, body, dict(e.headers.items())))
        except Exception:  # noqa: BLE001 - connection refused / timeout -> not executed
            return _Outcome(False, None)


# --------------------------------------------------------------------------- decoy servers
def _serve(handler_cls):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv


def _make_handler(render):
    class _H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *a):  # keep tests quiet
            pass

        def do_GET(self):  # noqa: N802
            parsed = urllib.parse.urlparse(self.path)
            q = {k: v[0] for k, v in urllib.parse.parse_qs(parsed.query).items()}
            status, ctype, body = render(parsed.path, q)
            raw = body.encode()
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

    return _H


def _reflecting(path, q):
    """A benign server: echoes every query value into BOTH a JSON body and HTML, 200 for any path."""
    val = next(iter(q.values()), "")
    body = (
        "<!doctype html><html><body>"
        f"<p>You sent: {val}</p>"
        f"<pre>{json.dumps({'echo': q, 'path': path})}</pre>"
        "</body></html>"
    )
    return 200, "text/html; charset=utf-8", body


def _traversal_vuln(path, q):
    """Serves a real /etc/passwd line when the name escapes the sandbox; benign otherwise."""
    name = next(iter(q.values()), "")
    if ".." in name or name.startswith("/"):
        return (
            200,
            "text/plain",
            "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n",
        )
    return 200, "text/plain", "benign readme contents"


def _ssrf_vuln(path, q):
    """Returns IMDS-like credential JSON when fetching an internal host; benign for external URLs."""
    url = next(iter(q.values()), "")
    host = urllib.parse.urlparse(url).hostname or ""
    if host.startswith("169.254.") or host in ("127.0.0.1", "localhost", "metadata.google.internal"):
        return (
            200,
            "application/json",
            json.dumps(
                {
                    "Code": "Success",
                    "AccessKeyId": "ASIA-DECOY-EXAMPLE",
                    "SecretAccessKey": "decoy-secret-not-real",
                    "iam-role": "decoy-admin",
                }
            ),
        )
    return 200, "application/json", json.dumps({"fetched": url, "content": "external resource ok"})


@pytest.fixture
def reflecting_decoy():
    srv = _serve(_make_handler(_reflecting))
    yield srv.server_address[1]
    srv.shutdown()


@pytest.fixture
def traversal_decoy():
    srv = _serve(_make_handler(_traversal_vuln))
    yield srv.server_address[1]
    srv.shutdown()


@pytest.fixture
def ssrf_decoy():
    srv = _serve(_make_handler(_ssrf_vuln))
    yield srv.server_address[1]
    srv.shutdown()


_HYP = {"endpoint_path": "/echo", "selector_param": "q", "id": "h-accuracy"}


# --------------------------------------------------------------------------- negatives (no FP)
def test_reflecting_server_is_not_confirmed_cmdi(reflecting_decoy):
    runner = _LiveRunner(reflecting_decoy)
    v = run_cmdi_oracle(runner, _HYP)
    assert not v.validated, "a pure reflection must not confirm command injection"


def test_reflecting_server_is_not_confirmed_ssrf(reflecting_decoy):
    runner = _LiveRunner(reflecting_decoy)
    v = run_ssrf_oracle(runner, _HYP)
    assert not v.validated, "echoing a metadata URL back is not SSRF"


def test_reflecting_server_is_not_confirmed_traversal(reflecting_decoy):
    runner = _LiveRunner(reflecting_decoy)
    v = run_traversal_oracle(runner, _HYP)
    assert not v.validated, "echoing '../../etc/passwd' back is not a traversal read"


# --------------------------------------------------------------------------- positives (real content)
def test_real_passwd_line_confirms_traversal(traversal_decoy):
    runner = _LiveRunner(traversal_decoy)
    v = run_traversal_oracle(runner, _HYP)
    assert v.validated and v.reproductions >= 2, "a genuine /etc/passwd leak must confirm"


def test_imds_json_confirms_ssrf(ssrf_decoy):
    runner = _LiveRunner(ssrf_decoy)
    v = run_ssrf_oracle(runner, _HYP)
    assert v.validated and v.reproductions >= 2, "IMDS credential content must confirm SSRF"


def test_demo_computed_echo_confirms_cmdi(vuln_server):
    runner = _LiveRunner(vuln_server.port)
    hyp = {"endpoint_path": "/api/ping", "selector_param": "host", "id": "h-cmdi"}
    v = run_cmdi_oracle(runner, hyp)
    assert v.validated and v.reproductions >= 2, "the demo's computed echo must confirm CMDI"
    assert v.controls.get("not_in_payload") and v.controls.get("control_clean")
