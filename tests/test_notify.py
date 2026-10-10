"""The outbound findings-notification layer (generic signed webhook + Slack), offline.

A throwaway loopback HTTP server (ephemeral port in 19250-19299) captures POSTed bodies and
headers so we can assert the summary shape, the HMAC signature, Slack's ``text`` body,
idempotency across re-runs, off-by-default behaviour, failure-safety, and that the webhook
secret never leaks into a persisted file or a returned structure.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from rampart.integrations import notify as notify_mod

_PORT_RANGE = range(19250, 19300)
SECRET = "s3cr3t-webhook-signing-key"


class _CaptureHandler(BaseHTTPRequestHandler):
    def do_POST(self):  # noqa: N802 - BaseHTTPRequestHandler API
        length = int(self.headers.get("Content-Length", "0") or "0")
        body = self.rfile.read(length) if length else b""
        self.server.requests.append(  # type: ignore[attr-defined]
            {"path": self.path, "headers": dict(self.headers), "body": body}
        )
        code = self.server.status_code  # type: ignore[attr-defined]
        self.send_response(code)
        self.end_headers()
        self.wfile.write(b"ok" if code < 400 else b"boom")

    def log_message(self, *a):  # silence the test server
        pass


class FakeSink:
    """A captured-POST HTTP server bound to an ephemeral port in the allowed range."""

    def __init__(self, status_code: int = 200):
        self.httpd = None
        for port in _PORT_RANGE:
            try:
                self.httpd = ThreadingHTTPServer(("127.0.0.1", port), _CaptureHandler)
                self.port = port
                break
            except OSError:
                continue
        if self.httpd is None:
            raise RuntimeError("no free port in 19250-19299 for the fake sink")
        self.httpd.requests = []
        self.httpd.status_code = status_code
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    @property
    def requests(self):
        return self.httpd.requests

    @property
    def url(self):
        return f"http://127.0.0.1:{self.port}/hook"

    def stop(self):
        self.httpd.shutdown()
        self.httpd.server_close()


@pytest.fixture
def sink():
    s = FakeSink()
    yield s
    s.stop()


def _finding(title, *, sev="high", key=None, vuln="XSS", url="http://t/api/x"):
    return {
        "title": title,
        "severity": sev,
        "vuln_class": vuln,
        "endpoint": {"method": "GET", "url": url},
        "dedupe_key": key or title,
        "verification": {"validated": True},
        "state": "Validated",
        "id": "fnd_" + (key or title),
    }


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


# ------------------------------------------------------------------ webhook body + signature
def test_webhook_body_shape_and_signature(sink, tmp_path):
    findings = [
        _finding("IDOR on /api/orders", sev="high", key="k-idor"),
        _finding("Reflected XSS", sev="medium", key="k-xss"),
        {  # an unconfirmed candidate must never be sent
            "title": "dropped",
            "severity": "low",
            "verification": {"validated": False},
            "state": "Dropped",
            "dedupe_key": "k-drop",
        },
    ]
    res = notify_mod.notify(
        findings,
        work_dir=str(tmp_path),
        webhook_url=sink.url,
        webhook_secret=SECRET,
        application="demo",
        target="http://t:8080",
        engagement_id="eng-1",
    )
    assert res["enabled"] and res["sent"] == 2
    assert len(sink.requests) == 1
    req = sink.requests[0]

    payload = json.loads(req["body"])  # valid JSON
    assert set(payload) == {"counts", "findings", "run"}
    assert payload["counts"] == {"high": 1, "medium": 1}
    titles = {f["title"] for f in payload["findings"]}
    assert titles == {"IDOR on /api/orders", "Reflected XSS"}
    for f in payload["findings"]:
        assert set(f) >= {"title", "severity", "vuln_class", "endpoint", "dedupe_key"}
    assert payload["run"]["application"] == "demo" and payload["run"]["target"] == "http://t:8080"
    assert payload["run"]["tool"] == "rampart" and payload["run"]["engagement_id"] == "eng-1"

    # X-Rampart-Signature is HMAC-SHA256 of the EXACT raw body for the configured secret.
    expected = "sha256=" + hmac.new(SECRET.encode(), req["body"], hashlib.sha256).hexdigest()
    assert req["headers"].get("X-Rampart-Signature") == expected
    assert req["headers"].get("Content-Type") == "application/json"


def test_webhook_unsigned_without_secret(sink, tmp_path):
    res = notify_mod.notify(
        [_finding("A", key="a")], work_dir=str(tmp_path), webhook_url=sink.url, webhook_secret=""
    )
    assert res["sinks"][0]["posted"] and res["sinks"][0]["signed"] is False
    assert "note" in res["sinks"][0]
    assert "X-Rampart-Signature" not in sink.requests[0]["headers"]


# ------------------------------------------------------------------ slack
def test_slack_posts_text(sink, tmp_path):
    res = notify_mod.notify(
        [_finding("Reflected XSS", sev="high", key="x")],
        work_dir=str(tmp_path),
        slack_url=sink.url,
        application="demo",
    )
    assert res["enabled"] and res["sent"] == 1
    payload = json.loads(sink.requests[0]["body"])
    assert "text" in payload and isinstance(payload["text"], str)
    assert "Reflected XSS" in payload["text"] and "demo" in payload["text"]


# ------------------------------------------------------------------ idempotency
def test_idempotent_across_runs(sink, tmp_path):
    batch = [_finding("A", key="a"), _finding("B", key="b")]
    r1 = notify_mod.notify(batch, work_dir=str(tmp_path), webhook_url=sink.url, webhook_secret=SECRET)
    assert r1["sent"] == 2 and len(sink.requests) == 1
    assert len(json.loads(sink.requests[0]["body"])["findings"]) == 2

    # Second run over the SAME findings sends nothing and makes no HTTP call.
    r2 = notify_mod.notify(batch, work_dir=str(tmp_path), webhook_url=sink.url, webhook_secret=SECRET)
    assert r2["sent"] == 0 and len(sink.requests) == 1

    # A third run with one NEW finding sends only the new one.
    r3 = notify_mod.notify(
        [*batch, _finding("C", key="c")],
        work_dir=str(tmp_path),
        webhook_url=sink.url,
        webhook_secret=SECRET,
    )
    assert r3["sent"] == 1 and len(sink.requests) == 2
    new_body = json.loads(sink.requests[1]["body"])
    assert [f["dedupe_key"] for f in new_body["findings"]] == ["c"]


def test_manifest_robust_to_corruption(sink, tmp_path):
    (tmp_path / "notified.json").write_text("{ this is not json", encoding="utf-8")
    res = notify_mod.notify([_finding("A", key="a")], work_dir=str(tmp_path), webhook_url=sink.url)
    assert res["sent"] == 1  # corrupt manifest treated as empty, finding still sent


# ------------------------------------------------------------------ off by default
def test_off_by_default_makes_no_http_call(sink, tmp_path):
    # A sink server is running, but no sink URL is configured -> nothing is posted.
    res = notify_mod.notify([_finding("A", key="a")], work_dir=str(tmp_path))
    assert res == {"enabled": False, "sinks": [], "sent": 0}
    assert sink.requests == []
    assert not os.path.exists(tmp_path / "notified.json")


# ------------------------------------------------------------------ failure-safe
def test_failure_safe_on_closed_port(tmp_path):
    dead = f"http://127.0.0.1:{_free_port()}/hook"  # nothing is listening
    res = notify_mod.notify(
        [_finding("A", key="a")],
        work_dir=str(tmp_path),
        webhook_url=dead,
        webhook_secret=SECRET,
        timeout=2.0,
    )
    assert res["enabled"] and res["sent"] == 0
    assert res["sinks"][0]["posted"] is False and "reason" in res["sinks"][0]
    # a failed send is NOT recorded, so a later run retries it
    assert not os.path.exists(tmp_path / "notified.json")


def test_failure_safe_on_http_500(tmp_path):
    s = FakeSink(status_code=500)
    try:
        res = notify_mod.notify(
            [_finding("A", key="a")], work_dir=str(tmp_path), webhook_url=s.url, webhook_secret=SECRET
        )
    finally:
        s.stop()
    assert res["enabled"] and res["sent"] == 0
    assert res["sinks"][0]["posted"] is False and res["sinks"][0]["reason"] == "HTTP 500"
    assert not os.path.exists(tmp_path / "notified.json")


# ------------------------------------------------------------------ no secret leak
def test_secret_never_leaks(sink, tmp_path):
    res = notify_mod.notify(
        [_finding("A", key="a")],
        work_dir=str(tmp_path),
        webhook_url=sink.url + "?token=supersecrettoken",
        webhook_secret=SECRET,
    )
    blob = json.dumps(res)
    assert SECRET not in blob and "supersecrettoken" not in blob
    manifest = (tmp_path / "notified.json").read_text(encoding="utf-8")
    assert SECRET not in manifest and "supersecrettoken" not in manifest
    assert "a" in manifest  # the identity IS recorded


# ------------------------------------------------------------------ scrubbing
def test_finding_text_is_scrubbed(sink, tmp_path):
    leaky = _finding("leak Bearer abcdefghijklmnopqrstuvwxyz0123456789", key="leak")
    notify_mod.notify([leaky], work_dir=str(tmp_path), webhook_url=sink.url)
    body = sink.requests[0]["body"].decode()
    assert "abcdefghijklmnopqrstuvwxyz0123456789" not in body
    assert "<redacted>" in body


# ------------------------------------------------------------------ engagement wiring
def test_engagement_notify_off_by_default(tmp_path, monkeypatch):
    from conftest import make_engagement

    for var in ("RAMPART_WEBHOOK_URL", "RAMPART_SLACK_WEBHOOK_URL", "RAMPART_WEBHOOK_SECRET"):
        monkeypatch.delenv(var, raising=False)
    eng = make_engagement(tmp_path, 18123)
    assert eng.notify() == {"enabled": False, "sinks": [], "sent": 0}


def test_engagement_notify_sends_confirmed(tmp_path, sink, monkeypatch):
    from conftest import make_engagement

    from rampart.schemas.finding import Finding, State, Verification

    monkeypatch.setenv("RAMPART_WEBHOOK_SECRET", SECRET)
    eng = make_engagement(tmp_path, 18123)
    f = Finding(
        engagement_id="T",
        title="IDOR on /api/orders",
        vuln_class="IDOR/BOLA",
        severity="high",
        confidence="confirmed",
        state=State.VALIDATED,
        endpoint={"method": "GET", "url": "http://t/api/orders/1"},
        dedupe_key="k-eng",
        verification=Verification(validated=True),
    )
    eng.store.save_findings([f])
    eng.cfg.notify_webhook_url = sink.url
    res = eng.notify()
    assert res["enabled"] and res["sent"] == 1
    body = json.loads(sink.requests[0]["body"])
    assert body["findings"][0]["dedupe_key"] == "k-eng"
    expected = "sha256=" + hmac.new(SECRET.encode(), sink.requests[0]["body"], hashlib.sha256).hexdigest()
    assert sink.requests[0]["headers"]["X-Rampart-Signature"] == expected
