"""Headless-browser DOM-XSS integration — skipped automatically when Playwright/Chromium absent."""

import os

import pytest
from conftest import make_engagement, write_engagement

from rampart.browser import available
from rampart.engagement import Engagement, EngagementConfig

# Launches a real browser (slow) — opt-in so the default suite stays fast and CI-portable.
pytestmark = pytest.mark.skipif(
    not (available() and os.environ.get("RAMPART_BROWSER_TESTS")),
    reason="set RAMPART_BROWSER_TESTS=1 with Playwright+Chromium installed to run browser integration",
)


def test_dom_xss_confirmed_via_browser(tmp_path, vuln_server):
    eng = make_engagement(tmp_path, vuln_server.port)
    findings = eng.run_browser()
    dom = [f for f in findings if "dom" in f.tags]
    assert dom, "DOM XSS on /dom should be confirmed by the browser engine"
    f = dom[0]
    assert f.verification.validated and f.confidence == "confirmed"
    assert f.verification.method == "headless-browser-execution"
    f.assert_consistent()


def test_dom_xss_clean_on_fixed(tmp_path, fixed_server):
    eng = make_engagement(tmp_path, fixed_server.port)
    findings = eng.run_browser()
    assert not [f for f in findings if "dom" in f.tags], "fixed /dom uses textContent -> no execution"


def _active_eng(tmp_path, port):
    scope = write_engagement(tmp_path, port)
    cfg = EngagementConfig(
        scope_file=scope,
        target=f"http://127.0.0.1:{port}",
        work_dir=str(tmp_path / ".rampart"),
        openapi=str(tmp_path / "openapi.json"),
        appmodel_seed=str(tmp_path / "seed.json"),
        application="demo-shop-api",
        active=True,
    )
    return Engagement(cfg)


def test_stored_xss_confirmed_via_browser(tmp_path, vuln_server):
    findings = _active_eng(tmp_path, vuln_server.port).run_browser()
    stored = [f for f in findings if "stored" in f.tags]
    assert stored, "stored XSS on /api/comments should be confirmed by the browser"
    assert stored[0].verification.validated and stored[0].verification.method == "headless-browser-execution"
    stored[0].assert_consistent()
