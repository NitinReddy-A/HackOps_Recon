"""The public SDK surface: Rampart(...).scan() wraps the Engagement facade and produces the same
findings as the CLI, with convenient result views and a severity gate."""

import json

from conftest import write_engagement

from rampart import EngagementConfig, Rampart, ScanResult


def _rampart(tmp_path, port, **kw):
    scope = write_engagement(tmp_path, port)
    return Rampart(
        scope=scope,
        target=f"http://127.0.0.1:{port}",
        work_dir=str(tmp_path / ".rampart"),
        openapi=str(tmp_path / "openapi.json"),
        seed=str(tmp_path / "seed.json"),
        application="demo-shop-api",
        **kw,
    )


def test_scan_returns_confirmed_findings(tmp_path, vuln_server):
    result = _rampart(tmp_path, vuln_server.port).scan()
    assert isinstance(result, ScanResult)
    assert result.confirmed, "expected confirmed findings on the vulnerable target"
    # every confirmed finding is validated and not dropped
    assert all(f.verification.validated for f in result.confirmed)
    classes = {f.vuln_class for f in result.confirmed}
    assert "IDOR/BOLA" in classes


def test_severity_gate_and_summary(tmp_path, vuln_server):
    result = _rampart(tmp_path, vuln_server.port).scan()
    assert result.failed(on="high") is True  # the demo has high-severity confirmed bugs
    assert result.failed(on="critical") in (True, False)
    assert len(result.at_or_above("high")) >= 1
    assert "confirmed" in result.summary()
    assert len(result) == len(result.findings)
    assert list(iter(result)) == result.findings


def test_clean_target_passes_gate(tmp_path, fixed_server):
    result = _rampart(tmp_path, fixed_server.port).scan()
    assert not result.confirmed, "fixed target must confirm nothing"
    assert result.failed(on="low") is False


def test_result_renders_reports(tmp_path, vuln_server):
    result = _rampart(tmp_path, vuln_server.port).scan()
    sarif = json.loads(result.to_sarif())
    assert sarif["runs"][0]["tool"]["driver"]["name"].lower().startswith("rampart")
    report = json.loads(result.to_json())
    assert "findings" in report
    assert result.to_markdown().startswith("#")


def test_matches_engagement_facade(tmp_path, vuln_server):
    # The SDK must route through the same Engagement — same confirmed set as the raw facade.
    from rampart.engagement import Engagement

    r = _rampart(tmp_path, vuln_server.port)
    sdk_result = r.scan()
    sdk_confirmed = sorted(f"{f.vuln_class}@{f.endpoint.get('url', '')}" for f in sdk_result.confirmed)

    cfg2 = EngagementConfig(
        scope_file=r.config.scope_file,
        target=r.config.target,
        work_dir=str(tmp_path / ".rampart2"),
        openapi=r.config.openapi,
        appmodel_seed=r.config.appmodel_seed,
        application="demo-shop-api",
    )
    raw = Engagement(cfg2).run_scan()
    raw_confirmed = sorted(
        f"{f.vuln_class}@{f.endpoint.get('url', '')}" for f in raw.findings if f.verification.validated
    )
    assert sdk_confirmed == raw_confirmed


def test_from_config(tmp_path, vuln_server):
    scope = write_engagement(tmp_path, vuln_server.port)
    cfg = EngagementConfig(
        scope_file=scope,
        target=f"http://127.0.0.1:{vuln_server.port}",
        work_dir=str(tmp_path / ".rampart"),
        openapi=str(tmp_path / "openapi.json"),
        appmodel_seed=str(tmp_path / "seed.json"),
        application="demo-shop-api",
    )
    result = Rampart.from_config(cfg).scan()
    assert result.confirmed
