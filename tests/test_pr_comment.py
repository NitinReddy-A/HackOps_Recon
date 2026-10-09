"""The PR-comment renderer and the (graceful, offline) GitHub poster."""

from rampart.integrations import github
from rampart.reporting.pr_comment import MARKER, render_from_report, render_pr_comment

_REPORT = {
    "engagement": {"application": "demo"},
    "findings": [
        {
            "severity": "high",
            "title": "IDOR on /api/orders",
            "vuln_class": "IDOR/BOLA",
            "cwe": ["CWE-639"],
            "endpoint": {"method": "GET", "url": "http://t/api/orders/1"},
            "verification": {"validated": True},
            "state": "Validated",
            "tags": [],
        },
        {
            "severity": "medium",
            "title": "Reflected XSS",
            "vuln_class": "XSS",
            "cwe": ["CWE-79"],
            "endpoint": {"url": "http://t/api/search"},
            "verification": {"validated": True},
            "state": "Validated",
            "tags": [],
        },
        {
            "severity": "low",
            "title": "dropped candidate",
            "vuln_class": "XSS",
            "cwe": [],
            "verification": {"validated": False},
            "state": "Dropped",
            "tags": [],
        },
        {
            "severity": "medium",
            "title": "logic guess",
            "vuln_class": "BL",
            "cwe": [],
            "verification": {"validated": False},
            "state": "EvidenceFound",
            "tags": ["agent-assessed"],
        },
    ],
}


def test_render_from_report_has_marker_and_counts():
    body = render_from_report(_REPORT, fail_on="high")
    assert MARKER in body  # sticky-update marker
    assert "2 confirmed" in body
    assert "IDOR on /api/orders" in body and "CWE-639" in body
    assert "Gate failed" in body  # a high finding exists
    assert "1 agent-assessed" in body and "1 dropped" in body


def test_render_gate_passes_when_below_threshold():
    body = render_from_report(_REPORT, fail_on="critical")
    assert "Gate passed" in body


def test_render_no_confirmed():
    body = render_pr_comment(
        [
            {
                "severity": "low",
                "title": "x",
                "verification": {"validated": False},
                "state": "Dropped",
                "tags": [],
            }
        ]
    )
    assert "No confirmed vulnerabilities" in body


def test_render_from_finding_objects(tmp_path, vuln_server):
    # The same renderer must also accept live Finding objects (the SDK path).
    from conftest import write_engagement

    from rampart import Rampart

    scope = write_engagement(tmp_path, vuln_server.port)
    result = Rampart(
        scope=scope,
        target=f"http://127.0.0.1:{vuln_server.port}",
        work_dir=str(tmp_path / ".rampart"),
        openapi=str(tmp_path / "openapi.json"),
        seed=str(tmp_path / "seed.json"),
        application="demo-shop-api",
    ).scan()
    body = render_pr_comment(result.confirmed, application="demo-shop-api", fail_on="high")
    assert MARKER in body and "confirmed" in body


def test_poster_graceful_without_token(monkeypatch):
    for var in ("GITHUB_TOKEN", "GITHUB_REPOSITORY", "GITHUB_EVENT_PATH", "GITHUB_REF"):
        monkeypatch.delenv(var, raising=False)
    res = github.post_or_update_comment("body", repo="o/r", pr=1)
    assert res["posted"] is False and "GITHUB_TOKEN" in res["reason"]


def test_poster_graceful_without_pr(monkeypatch):
    monkeypatch.delenv("GITHUB_EVENT_PATH", raising=False)
    monkeypatch.delenv("GITHUB_REF", raising=False)
    res = github.post_or_update_comment("body", repo="o/r", token="x", pr=None)
    assert res["posted"] is False and "pull-request" in res["reason"]


def test_resolve_context_from_env(monkeypatch, tmp_path):
    event = tmp_path / "event.json"
    event.write_text('{"pull_request": {"number": 42}}', encoding="utf-8")
    monkeypatch.setenv("GITHUB_REPOSITORY", "owner/name")
    monkeypatch.setenv("GITHUB_TOKEN", "tok")
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(event))
    ctx = github.resolve_context()
    assert ctx["repo"] == "owner/name" and ctx["pr"] == 42 and ctx["token"] == "tok"
