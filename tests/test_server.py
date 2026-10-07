"""Local dashboard server: renders a run and can launch a scope-gated scan over HTTP."""
import json
import threading
import urllib.parse
import urllib.request

from conftest import write_engagement
from rampart.server.dashboard import build_server


def _server(work_dir):
    httpd = build_server("127.0.0.1", 0, str(work_dir))
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    return httpd, httpd.server_address[1]


def test_dashboard_serves_and_runs_a_scan(tmp_path, vuln_server):
    scope_file = write_engagement(tmp_path, vuln_server.port)   # writes scope + secrets next to it
    work_dir = tmp_path / "run"
    httpd, port = _server(work_dir)
    base = f"http://127.0.0.1:{port}"
    try:
        # dashboard renders before any run
        home = urllib.request.urlopen(base + "/").read().decode()
        assert "Rampart" in home and "Run a scan" in home

        # launch a scan through the dashboard (scope gate still applies server-side)
        body = urllib.parse.urlencode({"scope_file": scope_file,
                                       "target": f"http://127.0.0.1:{vuln_server.port}",
                                       "crawl": "on", "application": "demo-shop-api"}).encode()
        out = json.loads(urllib.request.urlopen(base + "/api/run", data=body).read().decode())
        assert out.get("ok") is True
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
    try:
        body = urllib.parse.urlencode({"scope_file": scope_file,
                                       "target": "http://192.0.2.1:8080"}).encode()  # not in scope
        out = json.loads(urllib.request.urlopen(f"http://127.0.0.1:{port}/api/run",
                                                data=body).read().decode())
        assert "error" in out and out.get("ok") is not True
    finally:
        httpd.shutdown()
