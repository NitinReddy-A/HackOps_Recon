"""Integration wiring: the module-level safety APIs are actually used by the shared facade.

Scope gate (scheme / host / port), KILL file, audit-corruption-at-startup, secrets-less black-box
scopes, side-channel engines (infra / gRPC / browser / OOB) receiving audit + budget + scope,
external adapters, LLM budget enforcement, the shared "confirmed" rule, retest outcomes,
completeness (unreachable target), SARIF locations and MCP refusals.
"""

from __future__ import annotations

import io
import json
import os
import socket
from types import SimpleNamespace

import pytest
from conftest import PLATFORM, make_engagement, write_engagement

from rampart.audit.log import AuditLog, AuditLogCorrupt
from rampart.engagement import Engagement, EngagementConfig, normalize_formats, parse_target
from rampart.executor.credentials import DictSecretsProvider
from rampart.schemas.finding import AffectedCode, Finding, State, Verification
from rampart.schemas.scope import ScopeError

DEMO_SRC = os.path.join(PLATFORM, "examples", "demo_target", "src")


def _free_port() -> int:
    """A loopback port with (almost certainly) nothing listening on it."""
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _cfg(tmp_path, port, **kw):
    scope_file = write_engagement(tmp_path, port)
    base = {
        "scope_file": scope_file,
        "target": f"http://127.0.0.1:{port}",
        "work_dir": str(tmp_path / ".rampart"),
        "application": "demo-shop-api",
    }
    base.update(kw)
    return EngagementConfig(**base)


# ------------------------------------------------------------------ 1. scope gate
@pytest.mark.parametrize(
    "target",
    ["127.0.0.1:8080", "not a url", "http://127.0.0.1:99999", "http://:8080", "ftp://127.0.0.1:8080", ""],
)
def test_parse_target_refuses_bad_targets(target):
    with pytest.raises(ScopeError):
        parse_target(target)


def test_parse_target_defaults_and_grpc():
    assert parse_target("http://Example.test") == ("http", "example.test", 80)
    assert parse_target("https://example.test") == ("https", "example.test", 443)
    with pytest.raises(ScopeError):
        parse_target("grpc://127.0.0.1:50051")  # gRPC only for the gRPC probe
    assert parse_target("grpc://127.0.0.1:50051", allow_grpc=True) == ("grpc", "127.0.0.1", 50051)
    with pytest.raises(ScopeError):
        parse_target("grpc://127.0.0.1", allow_grpc=True)  # explicit port required


def test_engagement_refuses_out_of_scope_port_and_creates_nothing(tmp_path):
    cfg = _cfg(tmp_path, 18123, target="http://127.0.0.1:18124")
    with pytest.raises(ScopeError, match="port 18124 is not authorized"):
        Engagement(cfg)
    assert not os.path.exists(cfg.work_dir)


def test_engagement_refuses_schemeless_target(tmp_path):
    with pytest.raises(ScopeError, match="scheme"):
        Engagement(_cfg(tmp_path, 18123, target="127.0.0.1:18123"))


def test_grpc_scheme_only_for_grpc_mode(tmp_path):
    with pytest.raises(ScopeError):
        Engagement(_cfg(tmp_path, 18123, target="grpc://127.0.0.1:18123"))
    eng = Engagement(_cfg(tmp_path, 18123, target="grpc://127.0.0.1:18123", grpc=True, do_dast=False))
    assert (eng.scheme, eng.port) == ("grpc", 18123)


def test_repo_must_be_a_directory(tmp_path):
    with pytest.raises(ScopeError, match="--repo"):
        Engagement(_cfg(tmp_path, 18123, repo=str(tmp_path / "nope")))


# ------------------------------------------------------------------ 2/3. budget, audit, secrets
def test_kill_file_budget_and_session_pipeline(tmp_path):
    eng = Engagement(_cfg(tmp_path, 18123))
    assert eng.budget.kill_file == os.path.join(eng.cfg.work_dir, "KILL")
    assert eng.sessions.pipeline is eng.pipeline
    open(eng.budget.kill_file, "w").close()
    assert eng.budget.is_killed()


def test_corrupt_audit_log_fails_at_startup(tmp_path):
    cfg = _cfg(tmp_path, 18123)
    os.makedirs(cfg.work_dir)
    with open(os.path.join(cfg.work_dir, "audit.jsonl"), "w", encoding="utf-8") as fh:
        fh.write("{garbage\n")
    with pytest.raises(AuditLogCorrupt):
        Engagement(cfg)


def test_blackbox_scope_needs_no_secrets_file(tmp_path):
    scope_file = write_engagement(tmp_path, 18123)
    txt = open(scope_file, encoding="utf-8").read().split("test_accounts:")[0]
    open(scope_file, "w", encoding="utf-8").write(txt)
    os.remove(tmp_path / "secrets.json")
    eng = Engagement(
        EngagementConfig(scope_file=scope_file, target="http://127.0.0.1:18123", work_dir=str(tmp_path / "w"))
    )
    assert isinstance(eng.secrets, DictSecretsProvider)


def test_scope_with_accounts_still_requires_secrets(tmp_path):
    cfg = _cfg(tmp_path, 18123)
    os.remove(tmp_path / "secrets.json")
    with pytest.raises(FileNotFoundError):
        Engagement(cfg)


def test_malformed_openapi_is_a_readable_value_error(tmp_path):
    (tmp_path / "bad.json").write_text("{not json", encoding="utf-8")
    with pytest.raises(ValueError, match="malformed JSON"):
        Engagement(_cfg(tmp_path, 18123, openapi=str(tmp_path / "bad.json")))


def test_unknown_intel_is_a_value_error(tmp_path):
    with pytest.raises(ValueError, match="unknown intelligence provider"):
        Engagement(_cfg(tmp_path, 18123, intel="gpt-banana"))


# ------------------------------------------------------------------ 4. side-channel engines
def test_infra_and_grpc_receive_scope_audit_budget(tmp_path, monkeypatch):
    from rampart import grpc_scan, infra
    from rampart.infra.sidechannel import ScanOutcome

    seen = {}

    def fake_infra(host, ports, **kw):
        seen["infra"] = (host, ports, kw)
        return ScanOutcome(skip_reason="infra: test skip", notes=["infra: note"])

    def fake_grpc(*a, **kw):
        seen["grpc"] = kw
        return ScanOutcome(skip_reason="grpc: refused — test")

    monkeypatch.setattr(infra, "scan_infra", fake_infra)
    monkeypatch.setattr(grpc_scan, "scan_grpc", fake_grpc)
    monkeypatch.setattr(grpc_scan, "available", lambda: True)
    eng = Engagement(_cfg(tmp_path, 18123))
    eng._stage_log = []
    assert eng.run_infra() == []
    host, ports, kw = seen["infra"]
    assert host == "127.0.0.1" and ports is None
    assert kw["audit"] is eng.audit and kw["budget"] is eng.budget and kw["scope"] is eng.scope
    assert kw["resolver"] is eng.resolver
    assert eng.run_grpc() == []
    g = seen["grpc"]
    assert g["engagement_id"] == eng.pipeline.engagement_id and g["scope"] is eng.scope
    assert g["audit"] is eng.audit and g["budget"] is eng.budget
    msgs = [e["msg"] for e in eng._stage_log]
    assert "infra: test skip" in msgs and "infra: note" in msgs and "grpc: refused — test" in msgs


def test_grpc_missing_extra_is_a_visible_skip(tmp_path, monkeypatch):
    from rampart import grpc_scan

    monkeypatch.setattr(grpc_scan, "available", lambda: False)
    eng = Engagement(_cfg(tmp_path, 18123))
    eng._stage_log = []
    assert eng.run_grpc() == []
    assert any("grpc: skipped" in e["msg"] for e in eng._stage_log)


def test_browser_gets_scope_predicate_and_audited_requests(tmp_path, monkeypatch):
    import rampart.browser as browser
    from rampart.validation.oracle import OracleVerdict

    calls = []

    def fake_oracle(driver, base, path, param, allow=None, on_request=None, **kw):
        calls.append((path, allow, on_request))
        return OracleVerdict(validated=False, vuln_class="DOM_XSS")

    monkeypatch.setattr(browser, "browser_skip_reason", lambda: "")
    monkeypatch.setattr(browser, "run_dom_xss_oracle", fake_oracle)
    monkeypatch.setattr(browser, "PlaywrightDriver", lambda: object())
    port = 18123
    eng = Engagement(
        _cfg(
            tmp_path, port, openapi=str(tmp_path / "openapi.json"), appmodel_seed=str(tmp_path / "seed.json")
        )
    )
    eng._stage_log = []
    eng.run_browser()
    assert calls, "the DOM oracle must be invoked"
    _path, allow, on_request = calls[0]
    assert allow is not None and on_request is not None
    assert allow(f"http://127.0.0.1:{port}/api/search?q=1")
    assert not allow(f"http://127.0.0.1:{port + 1}/")  # other port
    assert not allow("http://169.254.169.254/latest/meta-data/")  # other host
    assert not allow(f"http://127.0.0.1:{port}/api/admin/users")  # excluded path
    assert not allow(f"http://127.0.0.1:{port}/api/search", "DELETE")  # method not in scope
    assert allow("data:text/html,hi")
    before = len(eng.audit.read_all())
    on_request(f"http://127.0.0.1:{port}/x", "GET", False)
    ev = eng.audit.read_all()[before:]
    assert len(ev) == 1 and ev[0].policy_decision["decision"] == "deny"
    assert all(not p.startswith("/api/admin") for p, _a, _o in calls)


def test_browser_missing_extra_is_a_visible_skip(tmp_path, monkeypatch):
    import rampart.browser as browser

    monkeypatch.setattr(browser, "browser_skip_reason", lambda: "browser: skipped — install it")
    eng = Engagement(_cfg(tmp_path, 18123))
    eng._stage_log = []
    assert eng.run_browser() == []
    assert any("browser: skipped" in e["msg"] for e in eng._stage_log)


def test_oob_remote_target_without_collaborator_is_skipped(tmp_path, monkeypatch):
    eng = Engagement(_cfg(tmp_path, 18123))
    eng.target_url = "http://app.example.test:18123"  # pretend: a remote target
    eng._stage_log = []
    assert eng.run_oob(timeout=0.1) == []
    assert any(e["msg"].startswith("oob: skipped") for e in eng._stage_log)


def test_apiscan_receives_active(tmp_path, monkeypatch):
    import rampart.apiscan as apiscan

    seen = {}
    monkeypatch.setattr(apiscan, "api_scan", lambda *a, **kw: seen.update(kw) or [])
    eng = Engagement(_cfg(tmp_path, 18123, active=True))
    eng.run_apiscan()
    assert seen.get("active") is True


class _FakeAdapter:
    name = "fake"
    network = False
    install_hint = "pip install fake"

    def __init__(self, skip="", network=False, avail=True):
        self._skip, self.network, self._avail = skip, network, avail
        self.ran = False

    def is_available(self):
        return self._avail

    def skip_reason(self):
        return self._skip

    def uses_network(self):
        return True  # e.g. fetches a rule registry

    def run(self, appmodel, target_url, application):
        self.ran = True
        return []


def test_supervisor_adapters_skip_reason_and_network(tmp_path):
    from rampart.workers.supervisor import ScanResult

    eng = Engagement(_cfg(tmp_path, 18123))
    ok, skipped, netty = _FakeAdapter(), _FakeAdapter(skip="no config"), _FakeAdapter(network=True)
    eng.supervisor.scanners = [ok, skipped, netty]
    res = ScanResult()
    eng.supervisor.run_adapters(res, allow_target_network=False)
    assert ok.ran and not skipped.ran and not netty.ran
    runs = {id(a): r for a, r in zip([ok, skipped, netty], res.scanner_runs)}
    assert runs[id(ok)]["uses_network"] is True
    assert "no config" in runs[id(skipped)]["note"]
    assert any("skipped (no config)" in e["msg"] for e in res.phase_log)


# ------------------------------------------------------------------ 6. LLM budget
def test_llm_provider_refuses_when_budget_exhausted():
    from rampart.intelligence.llm_base import LLMProvider
    from rampart.policy.budget import BudgetTracker
    from rampart.schemas.scope import Limits

    class P(LLMProvider):
        name = "fake-llm"
        called = 0

        def _complete(self, prompt):
            P.called += 1
            self._charge(tokens=10, usd=0.01)
            return '{"ok": true}'

    b = BudgetTracker(Limits(budget_usd=0.015, max_tokens=1000))
    p = P(budget=b)
    assert p._json("x") == {"ok": True}
    assert p._json("x") == {"ok": True}  # 0.01 < 0.015 still allowed
    assert p._json("x") is None  # now 0.02 >= 0.015
    assert P.called == 2 and p.degraded
    assert any("LLM budget" in r for r in p.degraded_reasons)
    assert b.tokens_used == 20 and b.llm_calls == 2 and b.denials["llm_budget"] == 1


# ------------------------------------------------------------------ 7. completeness
def test_unreachable_target_marks_scan_incomplete(tmp_path):
    port = _free_port()
    eng = make_engagement(tmp_path, port)
    res = eng.run_scan()
    assert not res.complete and res.incomplete_reason.startswith("target unreachable")
    scan = json.load(open(os.path.join(eng.cfg.work_dir, "scan.json"), encoding="utf-8"))
    assert scan["status"] == "incomplete" and scan["incomplete_reason"].startswith("target unreachable")
    assert scan["target"] == f"http://127.0.0.1:{port}"
    assert "denied" in scan["budget"] and "denied_total" in scan["budget"]
    assert scan["intel"]["provider"] == "deterministic"


def test_sdk_incomplete_result_fails_gate(tmp_path):
    from rampart import Rampart

    port = _free_port()
    write_engagement(tmp_path, port)
    r = Rampart(
        scope=str(tmp_path / "rampart.scope.yaml"),
        target=f"http://127.0.0.1:{port}",
        work_dir=str(tmp_path / ".rampart"),
    )
    res = r.scan()
    assert res.complete is False and "unreachable" in res.incomplete_reason
    assert res.failed(on="critical") is True
    assert "INCOMPLETE" in res.summary()


# ------------------------------------------------------------------ 9/10. results semantics
def _finding(sev="high", validated=True, state=State.VALIDATED, tags=None, **kw):
    f = Finding(
        engagement_id="T",
        title="t",
        vuln_class=kw.pop("vuln_class", "SQLI"),
        severity=sev,
        confidence="confirmed" if validated else "firm",
        state=state,
        tags=list(tags or []),
        verification=Verification(validated=validated),
        **kw,
    )
    return f


def test_sdk_confirmed_excludes_fixed_and_validates_severity():
    from rampart.sdk import ScanResult

    res = ScanResult(
        [_finding("high"), _finding("critical", state=State.FIXED), _finding("HIGH")], engagement=None
    )
    assert len(res.confirmed) == 2  # the Fixed one is not confirmed
    assert res.failed(on="HIGH") and res.failed(on="high")
    assert not res.failed(on="critical")
    assert len(res.by_severity()["high"]) == 2
    with pytest.raises(ValueError):
        res.failed(on="severe")
    with pytest.raises(ValueError):
        res.at_or_above("bogus")


def test_correlation_ignores_fixed_findings():
    from rampart.correlation import correlate

    corr = correlate([_finding("critical", state=State.FIXED), _finding("weird-sev", vuln_class="XSS")])
    assert corr.risk_score == 1  # only the open finding; an unknown severity counts as info
    assert not any(c["id"] == "sqli-breach" for c in corr.chains)


def test_normalize_formats():
    assert normalize_formats("HTML, json,html") == ["html", "json"]
    assert normalize_formats(["SARIF"]) == ["sarif"]
    with pytest.raises(ValueError, match="valid:"):
        normalize_formats("html,pdf")


# ------------------------------------------------------------------ 11. retest
def test_retest_network_error_is_inconclusive(tmp_path, monkeypatch):
    eng = Engagement(_cfg(tmp_path, 18123))
    f = _finding("high", vuln_class="SQLI")
    misc = _finding("medium", vuln_class="security-misconfiguration")
    eng.store.save_findings([f, misc])
    eng.store.save_hypotheses([{"id": "h1", "vuln_class": "SQLI", "finding_id": f.id}])

    def boom(*a, **k):
        raise ConnectionRefusedError("down")

    monkeypatch.setattr(eng.validator, "retest", boom)
    out = {fd.vuln_class: o for fd, o in eng.retest()}
    assert out == {"SQLI": "inconclusive", "security-misconfiguration": Engagement.NOT_RETESTABLE}


# ------------------------------------------------------------------ 14. white-box notes / offline
def test_offline_whitebox_run_never_sends_requests_and_logs_notes(tmp_path):
    scope_file = write_engagement(tmp_path, 18123)
    cfg = EngagementConfig(
        scope_file=scope_file,
        target="",
        work_dir=str(tmp_path / "w"),
        repo=DEMO_SRC,
        do_dast=False,
        do_sast=True,
        do_sca=True,
        do_iac=True,
        crawl=True,  # requested network stages are skipped, not run
        infra=True,
        sast_since="no-such-ref-rampart-xyz",
        offline=True,
    )
    eng = Engagement(cfg)
    res = eng.run_scan()
    assert res.complete
    assert eng.probe_stats.snapshot()["executed"] == 0 and eng.budget.total_requests == 0
    msgs = [e["msg"] for e in res.phase_log]
    assert any("since: ref" in m and "full scan" in m for m in msgs), msgs
    assert any("skipped network stage" in m for m in msgs)
    assert any(f.tags and "sast" in f.tags for f in res.findings)
    scan = json.load(open(os.path.join(cfg.work_dir, "scan.json"), encoding="utf-8"))
    assert scan["offline"] is True and scan["repo"] == os.path.abspath(DEMO_SRC)
    with pytest.raises(RuntimeError):
        eng.executor.execute(None, "127.0.0.1")


# ------------------------------------------------------------------ 18. audit rule
def test_empty_audit_log_is_not_intact(tmp_path):
    log = AuditLog(str(tmp_path / "audit.jsonl"))
    ok, msg = log.verify_chain()
    assert not ok and "no events" in msg
    log.ensure_appendable()  # still appendable


# ------------------------------------------------------------------ 25. SARIF
def _check_sarif(doc):
    """Minimal SARIF 2.1.0 structural check (what GitHub code scanning needs)."""
    assert doc["version"] == "2.1.0"
    for run in doc["runs"]:
        assert run["tool"]["driver"]["name"]
        for r in run["results"]:
            assert r["level"] in ("error", "warning", "note", "none")
            assert isinstance(r["message"]["text"], str)
            for loc in r.get("locations", []):
                pl = loc.get("physicalLocation")
                if not pl:
                    continue
                uri = pl["artifactLocation"]["uri"]
                assert uri and not os.path.isabs(uri) and ":\\" not in uri and not uri.startswith("/")
                if "region" in pl:
                    assert pl["region"]["startLine"] >= 1


def test_sarif_source_location_is_repo_relative(tmp_path):
    repo = str(tmp_path / "repo")
    f = _finding("HIGH", validated=False, state=State.EVIDENCE_FOUND, tags=["sast"])
    f.endpoint = {"url": "http://127.0.0.1:1/x"}
    f.affected_code = AffectedCode(file=os.path.join(repo, "app", "views.py"), start_line=12, end_line=0)
    r = f.to_sarif_result(repo_root=repo)
    assert r["level"] == "error"
    assert len(r["locations"]) == 1
    pl = r["locations"][0]["physicalLocation"]
    assert pl["artifactLocation"] == {"uri": "app/views.py", "uriBaseId": "%SRCROOT%"}
    assert pl["region"] == {"startLine": 12, "endLine": 12}
    # no repo root: an absolute path is never emitted
    f.affected_code = AffectedCode(file="C:\\work\\repo\\a.py", start_line=0)
    r2 = f.to_sarif_result()
    assert r2["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "work/repo/a.py"
    assert "region" not in r2["locations"][0]["physicalLocation"]
    # URL-only finding keeps its URL
    g = _finding("medium")
    g.endpoint = {"url": "http://127.0.0.1:1/y"}
    assert g.to_sarif_result()["locations"][0]["physicalLocation"]["artifactLocation"]["uri"].startswith(
        "http"
    )


def test_report_sarif_is_structurally_valid(tmp_path):
    from rampart.reporting import ReportBuilder
    from rampart.schemas.scope import EngagementScope

    scope = EngagementScope.from_file(write_engagement(tmp_path, 18123))
    f = _finding("high", validated=False, state=State.EVIDENCE_FOUND, tags=["sast"])
    f.affected_code = AffectedCode(file=str(tmp_path / "repo" / "m.py"), start_line=3)
    g = _finding("medium")
    g.endpoint = {"url": "http://127.0.0.1:18123/a"}
    rb = ReportBuilder([f, g], scope, None, {"repo": str(tmp_path / "repo")}, {})
    doc = json.loads(rb.to_sarif())
    _check_sarif(doc)
    uris = [
        loc["physicalLocation"]["artifactLocation"]["uri"]
        for r in doc["runs"][0]["results"]
        for loc in r["locations"]
    ]
    assert "m.py" in uris


# ------------------------------------------------------------------ 24. MCP
def _mcp(name, arguments):
    from rampart.mcp.server import serve_stdio

    req = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": name, "arguments": arguments},
    }
    out = io.StringIO()
    serve_stdio(io.StringIO(json.dumps(req) + "\n"), out)
    return json.loads(out.getvalue().splitlines()[0])["result"]


def test_mcp_scan_and_llm_refuse_out_of_scope_port(tmp_path):
    scope_file = write_engagement(tmp_path, 18123)
    for tool in ("rampart_scan", "rampart_llm_test"):
        res = _mcp(
            tool,
            {"scope_file": scope_file, "target": "http://127.0.0.1:18124", "work_dir": str(tmp_path / tool)},
        )
        assert res["isError"] is True
        body = json.loads(res["content"][0]["text"])
        assert body["refused"] and "18124" in body["error"]
        assert not os.path.exists(tmp_path / tool)


def test_mcp_scope_check_clips_echoed_path(tmp_path):
    huge = str(tmp_path / ("x" * 5000)) + ".yaml"
    res = _mcp("rampart_scope_check", {"scope_file": huge})
    assert res["isError"] is True
    err = json.loads(res["content"][0]["text"])["errors"][0]
    assert len(err) < 1000 and "x" * 300 not in err


def test_mcp_report_reads_target_from_stored_run_and_empty_audit_is_not_intact(tmp_path):
    scope_file = write_engagement(tmp_path, 18123)
    work = tmp_path / "run"
    work.mkdir()
    (work / "scan.json").write_text(json.dumps({"target": "http://127.0.0.1:18123"}), encoding="utf-8")
    (work / "findings.json").write_text("[]", encoding="utf-8")
    res = _mcp("rampart_report", {"scope_file": scope_file, "work_dir": str(work), "format": "JSON"})
    body = json.loads(res["content"][0]["text"])
    assert res["isError"] is False, body
    assert body["formats"] == ["json"] and body["audit_chain_intact"] is False
    bad = _mcp("rampart_report", {"scope_file": scope_file, "work_dir": str(work), "format": "pdf"})
    assert bad["isError"] is True


def test_intel_status_reports_degraded_fallback(tmp_path):
    eng = Engagement(_cfg(tmp_path, 18123))
    eng.intel = SimpleNamespace(
        name="claude-code", degraded=True, degraded_reasons=["claude CLI not found"], notes=[], calls=0
    )
    st = eng.intel_status()
    assert st["degraded"] and st["effective"] == "claude-code (degraded: deterministic fallback)"
    assert st["degraded_reasons"] == ["claude CLI not found"]
