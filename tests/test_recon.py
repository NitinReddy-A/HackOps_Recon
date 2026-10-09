"""Recon crawler: discover the attack surface with NO OpenAPI spec, then confirm findings."""

from conftest import write_engagement

from rampart.engagement import Engagement, EngagementConfig


def _crawl_engagement(tmp_path, port):
    scope_file = write_engagement(tmp_path, port)  # writes scope + secrets (+ openapi/seed we ignore)
    cfg = EngagementConfig(
        scope_file=scope_file,
        target=f"http://127.0.0.1:{port}",
        work_dir=str(tmp_path / ".rampart"),
        openapi="",
        appmodel_seed="",  # <- no spec: discovery must come from crawling
        application="demo-shop-api",
        crawl=True,
    )
    return Engagement(cfg)


def test_crawl_discovers_endpoints_without_spec(tmp_path, vuln_server):
    eng = _crawl_engagement(tmp_path, vuln_server.port)
    assert eng.appmodel.endpoints == []  # nothing known before recon
    eng.recon()
    paths = {e.path for e in eng.appmodel.endpoints}
    assert "/api/search" in paths and "/api/products" in paths and "/api/go" in paths
    # the search form/link exposed the 'q' parameter
    search = next(e for e in eng.appmodel.endpoints if e.path == "/api/search")
    assert any(p["name"] == "q" for p in search.parameters)


def test_crawl_then_confirms_web_classes(tmp_path, vuln_server):
    eng = _crawl_engagement(tmp_path, vuln_server.port)
    findings = eng.run_scan().findings
    confirmed = {f.vuln_class for f in findings if f.verification.validated}
    assert {"XSS", "SQLI", "OPEN_REDIRECT"} <= confirmed, f"got {confirmed}"


def test_crawl_fingerprints_tech(tmp_path, vuln_server):
    eng = _crawl_engagement(tmp_path, vuln_server.port)
    eng.recon()
    # the demo server leaks a Server header; the crawler should fingerprint something
    assert isinstance(eng.recon_tech, list)
    assert any("demo-shop-api" in t or "server" in t.lower() for t in eng.recon_tech)
