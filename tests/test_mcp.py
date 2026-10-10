"""The Rampart MCP stdio server — driven over in-memory JSON-RPC streams.

Every assessment tool goes through Engagement, so these tests also prove the
rampart.scope.yaml scope gate is enforced from the MCP surface (an out-of-scope target is
refused with a clean error result, not an exception). Deterministic: intel defaults
to the deterministic provider; only rampart_scan touches the throwaway demo target.
"""

from __future__ import annotations

import io
import json

from conftest import write_engagement  # noqa: E402  (vuln_server fixture auto-discovered)

from rampart.mcp.server import serve_stdio


# --------------------------------------------------------------------------- helpers
def _run(requests):
    """Feed a list of JSON-RPC request dicts through serve_stdio; return response dicts."""
    stdin = io.StringIO("".join(json.dumps(r) + "\n" for r in requests))
    stdout = io.StringIO()
    serve_stdio(stdin, stdout)
    return [json.loads(ln) for ln in stdout.getvalue().splitlines() if ln.strip()]


def _call(name, arguments, rid=1):
    return {
        "jsonrpc": "2.0",
        "id": rid,
        "method": "tools/call",
        "params": {"name": name, "arguments": arguments},
    }


def _payload(resp):
    """Parse the JSON text carried in a tools/call result."""
    return json.loads(resp["result"]["content"][0]["text"])


# ------------------------------------------------------------------- protocol basics
def test_initialize_reports_server_name():
    resps = _run([{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}])
    info = resps[0]["result"]
    assert info["serverInfo"]["name"] == "rampart"
    assert info["serverInfo"]["version"]
    assert "tools" in info["capabilities"]


def test_notification_initialized_has_no_response():
    resps = _run(
        [
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        ]
    )
    # only the tools/list request produced a response
    assert len(resps) == 1 and resps[0]["id"] == 2


def test_tools_list_contains_the_four_tools():
    resps = _run([{"jsonrpc": "2.0", "id": 3, "method": "tools/list", "params": {}}])
    names = {t["name"] for t in resps[0]["result"]["tools"]}
    assert {"rampart_scope_check", "rampart_scan", "rampart_llm_test", "rampart_report"} <= names
    # every tool advertises a JSON-Schema inputSchema
    for t in resps[0]["result"]["tools"]:
        assert t["inputSchema"]["type"] == "object"
        assert "scope_file" in t["inputSchema"]["properties"]


def test_unknown_method_is_jsonrpc_error():
    resps = _run([{"jsonrpc": "2.0", "id": 9, "method": "no/such/method"}])
    assert resps[0]["error"]["code"] == -32601


def test_bad_line_does_not_crash_and_is_parse_error():
    stdin = io.StringIO("this is not json\n{still bad\n")
    stdout = io.StringIO()
    serve_stdio(stdin, stdout)  # must not raise
    lines = [json.loads(ln) for ln in stdout.getvalue().splitlines() if ln.strip()]
    assert len(lines) == 2
    assert all(r["error"]["code"] == -32700 for r in lines)


# -------------------------------------------------------------------- scope_check
def test_scope_check_valid(tmp_path, vuln_server):
    scope_file = write_engagement(tmp_path, vuln_server.port)
    resp = _run([_call("rampart_scope_check", {"scope_file": scope_file})])[0]
    assert resp["result"]["isError"] is False
    body = _payload(resp)
    assert body["valid"] is True and body["errors"] == []


def test_scope_check_missing_arg_is_error():
    resp = _run([_call("rampart_scope_check", {})])[0]
    assert resp["result"]["isError"] is True


# -------------------------------------------------------------------------- scan
def test_scan_confirms_findings_on_vuln_target(tmp_path, vuln_server):
    scope_file = write_engagement(tmp_path, vuln_server.port)
    resp = _run(
        [
            _call(
                "rampart_scan",
                {
                    "scope_file": scope_file,
                    "target": f"http://127.0.0.1:{vuln_server.port}",
                    "openapi": str(tmp_path / "openapi.json"),
                    "appmodel_seed": str(tmp_path / "seed.json"),
                    "work_dir": str(tmp_path / ".rampart"),
                    "application": "demo-shop-api",
                },
            )
        ]
    )[0]
    assert resp["result"]["isError"] is False
    body = _payload(resp)
    assert body["counts"]["confirmed"] >= 5
    assert body["risk_score"] >= 55
    assert body["attack_chains"]
    # confirmed findings expose the required fields
    f0 = body["confirmed_findings"][0]
    assert {"title", "severity", "vuln_class", "cwe", "endpoint"} <= set(f0)


def test_scan_out_of_scope_target_is_error_not_exception(tmp_path, vuln_server):
    scope_file = write_engagement(tmp_path, vuln_server.port)
    resp = _run(
        [
            _call(
                "rampart_scan",
                {
                    "scope_file": scope_file,
                    "target": "http://192.0.2.1:8080",  # host is NOT in scope.in_scope
                    "work_dir": str(tmp_path / ".rampart"),
                },
            )
        ]
    )[0]
    # the scope gate refuses it — a clean tool error, never a crash
    assert resp["result"]["isError"] is True
    body = _payload(resp)
    assert "error" in body


def test_scan_missing_target_is_error(tmp_path, vuln_server):
    scope_file = write_engagement(tmp_path, vuln_server.port)
    resp = _run([_call("rampart_scan", {"scope_file": scope_file})])[0]
    assert resp["result"]["isError"] is True


# ----------------------------------------------------------- CLI-parity surface (deep stages)
def test_scan_schema_exposes_deep_stage_parity():
    """rampart_scan's inputSchema reaches the deeper read-only stages the CLI offers."""
    resps = _run([{"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}])
    scan = next(t for t in resps[0]["result"]["tools"] if t["name"] == "rampart_scan")
    props = scan["inputSchema"]["properties"]
    for field in ("deep", "active", "authz", "bizlogic", "api_scan", "exploit", "oob"):
        assert props[field]["type"] == "boolean", field
    # grey-box / auth'd inputs are reachable too
    assert props["appmodel_seed"]["type"] == "string"
    assert props["secrets"]["type"] == "string"
    # the active flag documents that writes still pass the policy gate
    assert "policy approval" in props["active"]["description"]


class _FakeResult:
    complete = True
    incomplete_reason = ""
    endpoints_tested = 0
    classes_tested: list = []
    findings: list = []
    correlation = None


def test_scan_new_args_reach_engagement_config(tmp_path, monkeypatch):
    """Every new optional arg is mapped onto the matching EngagementConfig field.

    Engagement is stubbed so the mapping is asserted without running a real scan (fast,
    no live target) — the real EngagementConfig is still constructed by the handler."""
    import rampart.engagement as eng_mod

    captured = {}

    class _CapturingEngagement:
        def __init__(self, cfg):
            captured["cfg"] = cfg
            self.cfg = cfg
            self.target_url = cfg.target

        def run_scan(self):
            return _FakeResult()

        def intel_status(self):
            return {"effective": "deterministic", "requested": "deterministic"}

        def budget_status(self):
            return {}

    monkeypatch.setattr(eng_mod, "Engagement", _CapturingEngagement)
    scope_file = write_engagement(tmp_path, 9)  # no live server needed — Engagement is stubbed
    resp = _run(
        [
            _call(
                "rampart_scan",
                {
                    "scope_file": scope_file,
                    "target": "http://127.0.0.1:9",
                    "work_dir": str(tmp_path / ".rampart"),
                    "appmodel_seed": str(tmp_path / "seed.json"),
                    "secrets": str(tmp_path / "secrets.json"),
                    "deep": True,
                    "active": True,
                    "authz": True,
                    "bizlogic": True,
                    "api_scan": True,
                    "exploit": True,
                    "oob": True,
                },
            )
        ]
    )[0]
    assert resp["result"]["isError"] is False
    cfg = captured["cfg"]
    assert (cfg.deep, cfg.active, cfg.authz, cfg.bizlogic) == (True, True, True, True)
    assert (cfg.api_scan, cfg.exploit, cfg.oob) == (True, True, True)
    assert cfg.appmodel_seed.endswith("seed.json")
    assert cfg.secrets_file.endswith("secrets.json")


def test_scan_deep_authz_runs_against_demo_target(tmp_path, vuln_server):
    """The deeper read-only stages (deep escalation + authz) run end-to-end from MCP."""
    scope_file = write_engagement(tmp_path, vuln_server.port)
    resp = _run(
        [
            _call(
                "rampart_scan",
                {
                    "scope_file": scope_file,
                    "target": f"http://127.0.0.1:{vuln_server.port}",
                    "openapi": str(tmp_path / "openapi.json"),
                    "appmodel_seed": str(tmp_path / "seed.json"),
                    "work_dir": str(tmp_path / ".rampart"),
                    "application": "demo-shop-api",
                    "deep": True,
                    "authz": True,
                },
            )
        ]
    )[0]
    assert resp["result"]["isError"] is False
    body = _payload(resp)
    assert body["complete"] is True
    assert body["counts"]["confirmed"] >= 1


def test_scan_active_does_not_bypass_scope_gate(tmp_path, vuln_server):
    """Exposing `active`/`deep` must not let a client escape scope — an out-of-scope
    target is still refused (policy parity unchanged)."""
    scope_file = write_engagement(tmp_path, vuln_server.port)
    resp = _run(
        [
            _call(
                "rampart_scan",
                {
                    "scope_file": scope_file,
                    "target": "http://192.0.2.1:8080",  # NOT in scope.in_scope
                    "work_dir": str(tmp_path / ".rampart"),
                    "active": True,
                    "deep": True,
                    "exploit": True,
                },
            )
        ]
    )[0]
    assert resp["result"]["isError"] is True
    assert "error" in _payload(resp)
