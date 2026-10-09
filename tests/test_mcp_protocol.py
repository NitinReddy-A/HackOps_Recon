"""MCP JSON-RPC protocol hardening — notifications, params validation, argument types, ping,
version negotiation, report-without-run, and UTF-8/LF stdio framing. No target needed."""

from __future__ import annotations

import io
import json
import os
import subprocess
import sys

from rampart.mcp.server import SUPPORTED_PROTOCOL_VERSIONS, serve_stdio

PLATFORM = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def _run_raw(lines):
    stdin = io.StringIO("".join(line + "\n" for line in lines))
    stdout = io.StringIO()
    serve_stdio(stdin, stdout)
    return [json.loads(ln) for ln in stdout.getvalue().splitlines() if ln.strip()]


def _run(reqs):
    return _run_raw([json.dumps(r) for r in reqs])


def _call(name, arguments, rid=1):
    return {
        "jsonrpc": "2.0",
        "id": rid,
        "method": "tools/call",
        "params": {"name": name, "arguments": arguments},
    }


def _text(resp):
    return json.loads(resp["result"]["content"][0]["text"])


# ------------------------------------------------------------------ ping / version
def test_ping_returns_empty_result():
    assert _run([{"jsonrpc": "2.0", "id": 7, "method": "ping"}]) == [
        {"jsonrpc": "2.0", "id": 7, "result": {}}
    ]


def test_initialize_negotiates_protocol_version():
    for v in SUPPORTED_PROTOCOL_VERSIONS:
        r = _run([{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": v}}])[0]
        assert r["result"]["protocolVersion"] == v
    r = _run(
        [{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "1999-01-01"}}]
    )[0]
    assert r["result"]["protocolVersion"] == SUPPORTED_PROTOCOL_VERSIONS[0]
    assert "2025-06-18" in SUPPORTED_PROTOCOL_VERSIONS and "2024-11-05" in SUPPORTED_PROTOCOL_VERSIONS


# ------------------------------------------------------------------ notifications (E2-1)
def test_notifications_never_respond_or_execute(tmp_path):
    marker_dir = tmp_path / "should_not_exist"
    resps = _run(
        [
            {"jsonrpc": "2.0", "method": "tools/list"},
            {"jsonrpc": "2.0", "method": "initialize", "params": {}},
            {
                "jsonrpc": "2.0",
                "method": "tools/call",
                "params": {
                    "name": "rampart_report",
                    "arguments": {
                        "scope_file": "x",
                        "target": "http://127.0.0.1:1",
                        "work_dir": str(marker_dir),
                    },
                },
            },
            {"jsonrpc": "2.0", "method": "notifications/foo"},
            {"jsonrpc": "2.0", "id": 5, "method": "ping"},
        ]
    )
    assert resps == [{"jsonrpc": "2.0", "id": 5, "result": {}}]
    assert not marker_dir.exists()


# ------------------------------------------------------------------ invalid requests / params (E2-5)
def test_params_not_object_is_invalid_params():
    r = _run([{"jsonrpc": "2.0", "id": 58, "method": "tools/call", "params": "x"}])[0]
    assert r["error"]["code"] == -32602 and r["id"] == 58


def test_arguments_not_object_is_invalid_params():
    r = _run(
        [
            {
                "jsonrpc": "2.0",
                "id": 56,
                "method": "tools/call",
                "params": {"name": "rampart_scan", "arguments": ["x"]},
            }
        ]
    )[0]
    assert r["error"]["code"] == -32602


def test_tools_call_without_name_is_invalid_params():
    r = _run([{"jsonrpc": "2.0", "id": 59, "method": "tools/call", "params": {}}])[0]
    assert r["error"]["code"] == -32602


def test_malformed_requests_are_invalid_request():
    resps = _run(
        [
            {"id": 62, "method": "tools/list"},  # no jsonrpc
            {"jsonrpc": "2.0", "id": 63, "method": 5},  # method not a string
            {"jsonrpc": "2.0", "id": None, "method": "tools/list"},  # null id
        ]
    )
    assert [r["error"]["code"] for r in resps] == [-32600, -32600, -32600]
    batch = _run_raw([json.dumps([{"jsonrpc": "2.0", "id": 61, "method": "tools/list"}])])
    assert batch[0]["error"]["code"] == -32600


# ------------------------------------------------------------------ argument types (E2-4)
def test_wrong_argument_types_are_tool_errors():
    cases = [
        ("rampart_scan", {"scope_file": "s.yaml", "target": 12345}),
        ("rampart_scope_check", {"scope_file": ["a", "b"]}),
        ("rampart_scan", {"scope_file": "s.yaml", "target": "http://127.0.0.2:1", "crawl": "false"}),
        ("rampart_scan", {"scope_file": "s.yaml", "target": "http://127.0.0.2:1", "wrok_dir": "typo"}),
    ]
    for name, args in cases:
        r = _run([_call(name, args)])[0]
        assert r["result"]["isError"] is True, (name, args)
        assert "invalid arguments" in _text(r)["error"], _text(r)


def test_missing_required_argument_is_tool_error():
    r = _run([_call("rampart_scan", {})])[0]
    assert r["result"]["isError"] is True
    assert "scope_file" in _text(r)["error"] and "target" in _text(r)["error"]


# ------------------------------------------------------------------ report without a run (E2-3)
def test_report_on_empty_work_dir_is_error_and_creates_nothing(tmp_path):
    wd = tmp_path / "never_ran_here"
    r = _run(
        [
            _call(
                "rampart_report",
                {"scope_file": str(tmp_path / "s.yaml"), "target": "http://127.0.0.1:1", "work_dir": str(wd)},
            )
        ]
    )[0]
    assert r["result"]["isError"] is True
    assert "no stored run" in _text(r)["error"]
    assert not wd.exists()


# ------------------------------------------------------------------ stdio framing (E2-6)
def test_real_stdio_is_utf8_and_lf_only():
    reqs = [
        {"jsonrpc": "2.0", "id": 1, "method": "ping"},
        _call("rampart_scope_check", {"scope_file": "nope-→-日本.yaml"}, rid=2),
    ]
    data = ("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in reqs)).encode("utf-8")
    data = data.replace(b"\n", b"\n\xff\xfe garbage\n", 1)  # an undecodable line must not kill the loop
    env = dict(os.environ, PYTHONPATH=PLATFORM, PYTHONIOENCODING="")
    env.pop("PYTHONUTF8", None)
    proc = subprocess.run(
        [sys.executable, "-m", "rampart.mcp"],
        input=data,
        capture_output=True,
        timeout=60,
        env=env,
        cwd=PLATFORM,
    )
    out = proc.stdout
    assert b"\r\n" not in out
    frames = [json.loads(line) for line in out.decode("utf-8").split("\n") if line.strip()]
    by_id = {f.get("id"): f for f in frames}
    assert by_id[1]["result"] == {}
    err = json.loads(by_id[2]["result"]["content"][0]["text"])
    assert "→" in json.dumps(err, ensure_ascii=False) or "\\u2192" in json.dumps(err)
    assert any(f.get("error", {}).get("code") == -32700 for f in frames)  # the garbage line
