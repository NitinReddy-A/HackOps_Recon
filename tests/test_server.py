"""Local dashboard server: renders a run and can launch a scope-gated scan over HTTP."""

import http.client
import json
import re
import threading
import urllib.error
import urllib.parse
import urllib.request

import pytest
from conftest import write_engagement

from rampart.server.dashboard import build_server


def _server(work_dir):
    httpd = build_server("127.0.0.1", 0, str(work_dir))
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    return httpd, httpd.server_address[1]


def _token_from_page(base):
    home = urllib.request.urlopen(base + "/").read().decode()
    m = re.search(r'<meta name="rampart-token" content="([^"]+)">', home)
    assert m, "dashboard page must embed the launch token"
    return m.group(1)


def _run(base, payload, token, extra_headers=None):
    """POST /api/run like the dashboard page does; returns (status, json)."""
    headers = {"Content-Type": "application/json", "X-Rampart-Token": token}
    headers.update(extra_headers or {})
    req = urllib.request.Request(base + "/api/run", data=json.dumps(payload).encode(), headers=headers)
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode() or "{}")


def _raw(port, method, path, headers, body=b""):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    conn.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
    for k, v in headers.items():
        conn.putheader(k, v)
    conn.endheaders()
    if body:
        conn.send(body)
    resp = conn.getresponse()
    data = resp.read()
    conn.close()
    return resp.status, data, resp


def test_dashboard_serves_and_runs_a_scan(tmp_path, vuln_server):
    scope_file = write_engagement(tmp_path, vuln_server.port)  # writes scope + secrets next to it
    work_dir = tmp_path / "run"
    httpd, port = _server(work_dir)
    base = f"http://127.0.0.1:{port}"
    try:
        # dashboard renders before any run
        home = urllib.request.urlopen(base + "/").read().decode()
        assert "Rampart" in home and "Run a scan" in home
        token = _token_from_page(base)
        assert token == httpd.rampart_token

        # launch a scan through the dashboard (scope gate still applies server-side)
        status, out = _run(
            base,
            {
                "scope_file": scope_file,
                "target": f"http://127.0.0.1:{vuln_server.port}",
                "crawl": True,
                "application": "demo-shop-api",
            },
            token,
            {"Origin": base},
        )
        assert status == 200 and out.get("ok") is True, out
        assert out["confirmed"] >= 5 and out["risk_score"] >= 55
        assert out["chains"] >= 1

        # the run is now queryable + the HTML report is served
        scan = json.loads(urllib.request.urlopen(base + "/api/scan").read().decode())
        assert scan["correlation"]["risk_score"] == out["risk_score"]
        assert "Rampart" in urllib.request.urlopen(base + "/report").read().decode()
    finally:
        httpd.shutdown()


def test_dashboard_rejects_out_of_scope_target(tmp_path, vuln_server):
    scope_file = write_engagement(tmp_path, vuln_server.port)
    httpd, port = _server(tmp_path / "run2")
    base = f"http://127.0.0.1:{port}"
    try:
        status, out = _run(
            base, {"scope_file": scope_file, "target": "http://192.0.2.1:8080"}, httpd.rampart_token
        )
        assert status == 400 and "error" in out and out.get("ok") is not True
        assert "not in the rampart.scope.yaml scope" in out["error"]
    finally:
        httpd.shutdown()


def test_cross_site_form_post_cannot_launch_a_scan(tmp_path, vuln_server):
    """The classic CSRF: an attacker page auto-submits a urlencoded form to /api/run."""
    scope_file = write_engagement(tmp_path, vuln_server.port)
    work_dir = tmp_path / "csrf"
    httpd, port = _server(work_dir)
    body = urllib.parse.urlencode(
        {"scope_file": scope_file, "target": f"http://127.0.0.1:{vuln_server.port}", "crawl": "on"}
    ).encode()
    host = f"127.0.0.1:{port}"
    try:
        form = {
            "Host": host,
            "Content-Type": "application/x-www-form-urlencoded",
            "Content-Length": str(len(body)),
        }
        status, _, _ = _raw(port, "POST", "/api/run", {**form, "Origin": "http://localhost:18643"}, body)
        assert status == 403
        status, _, _ = _raw(port, "POST", "/api/run", form, body)  # no Origin, no token, form type
        assert status == 415
        # JSON without the token is refused too
        jbody = json.dumps(
            {"scope_file": scope_file, "target": f"http://127.0.0.1:{vuln_server.port}"}
        ).encode()
        jh = {"Host": host, "Content-Type": "application/json", "Content-Length": str(len(jbody))}
        assert _raw(port, "POST", "/api/run", jh, jbody)[0] == 403
        assert _raw(port, "POST", "/api/run", {**jh, "X-Rampart-Token": "guess"}, jbody)[0] == 403
        # a cross-site Referer is refused even with a token
        assert (
            _raw(
                port,
                "POST",
                "/api/run",
                {**jh, "X-Rampart-Token": httpd.rampart_token, "Referer": "http://evil.example/x"},
                jbody,
            )[0]
            == 403
        )
        assert not (work_dir / "findings.json").exists()  # nothing ran
    finally:
        httpd.shutdown()


def test_foreign_host_header_is_refused(tmp_path):
    """DNS rebinding: a request for evil.example resolving to 127.0.0.1 must not read findings."""
    work_dir = tmp_path / "rebind"
    work_dir.mkdir()
    (work_dir / "findings.json").write_text('[{"title": "secret finding"}]', encoding="utf-8")
    httpd, port = _server(work_dir)
    try:
        for path in ("/", "/api/findings", "/api/scan", "/report"):
            status, data, _ = _raw(port, "GET", path, {"Host": "evil.example"})
            assert status == 403 and b"secret" not in data
            status, _, _ = _raw(port, "GET", path, {"Host": f"evil.example:{port}"})
            assert status == 403
        assert _raw(port, "GET", "/api/findings", {"Host": "127.0.0.1:1"})[0] == 403  # wrong port
        assert _raw(port, "GET", "/api/findings", {})[0] == 403  # no Host at all
        for ok in (f"127.0.0.1:{port}", f"localhost:{port}", f"LOCALHOST:{port}"):
            status, data, _ = _raw(port, "GET", "/api/findings", {"Host": ok})
            assert status == 200 and b"secret finding" in data
    finally:
        httpd.shutdown()


def test_security_headers_and_csp(tmp_path):
    httpd, port = _server(tmp_path / "hdr")
    try:
        status, data, resp = _raw(port, "GET", "/", {"Host": f"127.0.0.1:{port}"})
        assert status == 200
        assert resp.getheader("X-Content-Type-Options") == "nosniff"
        assert resp.getheader("Referrer-Policy") == "no-referrer"
        assert resp.getheader("X-Frame-Options") == "DENY"
        csp = resp.getheader("Content-Security-Policy")
        assert (
            "frame-ancestors 'none'" in csp
            and "'unsafe-inline'" not in csp.split("script-src")[1].split(";")[0]
        )
        nonce = re.search(r"'nonce-([^']+)'", csp).group(1)
        assert f'<script nonce="{nonce}">' in data.decode()
        assert "onsubmit=" not in data.decode()  # no inline handlers (blocked by the CSP)
    finally:
        httpd.shutdown()


def test_bad_requests_get_clean_errors(tmp_path):
    httpd, port = _server(tmp_path / "bad")
    host = f"127.0.0.1:{port}"
    tok = httpd.rampart_token
    try:
        h = {"Host": host, "Content-Type": "application/json", "X-Rampart-Token": tok}
        assert _raw(port, "POST", "/api/run", {**h, "Content-Length": "abc"})[0] == 400
        assert _raw(port, "POST", "/api/run", {**h, "Content-Length": "-5"})[0] == 400
        assert _raw(port, "POST", "/api/run", {**h, "Content-Length": str(10**9)})[0] == 413
        assert _raw(port, "POST", "/api/run", {**h, "Content-Length": "3"}, b"{x}")[0] == 400

        # scope_file errors never reveal whether an arbitrary path exists
        errors = []
        for path in (str(tmp_path / "does-not-exist.yaml"), __file__):
            body = json.dumps({"scope_file": path, "target": "http://127.0.0.1:1"}).encode()
            status, data, _ = _raw(port, "POST", "/api/run", {**h, "Content-Length": str(len(body))}, body)
            assert status == 400
            errors.append(json.loads(data)["error"])
        assert errors[0] == errors[1]
        assert "does-not-exist" not in errors[0] and "No such file" not in errors[0]
    finally:
        httpd.shutdown()


def test_second_dashboard_on_same_port_fails_clearly(tmp_path):
    httpd, port = _server(tmp_path / "one")
    try:
        with pytest.raises(OSError, match="already in use"):
            build_server("127.0.0.1", port, str(tmp_path / "two"))
    finally:
        httpd.shutdown()
