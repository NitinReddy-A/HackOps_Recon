"""Tests for the OPTIONAL headless-browser engine (rampart/browser).

No real browser is used: the oracle logic is driven entirely through StubDriver, and the
"Playwright absent" degradation path is exercised deterministically by simulating the lazy
import failing. These pass whether or not Playwright happens to be installed on the host.
"""

import rampart.browser.engine as engine
from rampart.browser.engine import (
    DOMXSS_TOKEN,
    PlaywrightDriver,
    RenderResult,
    StubDriver,
    available,
    run_dom_xss_oracle,
    run_stored_xss_oracle,
)

BASE = "http://127.0.0.1:65500"  # arbitrary; StubDriver matches on URL substrings, not the host


# --------------------------------------------------------------------- DOM XSS oracle
def test_dom_xss_confirmed_when_canary_executes():
    # The malicious URL carries the "__rampart_xss" binding call; the benign control value does
    # not, so the benign render falls through to the default (empty) RenderResult -> no execution.
    stub = StubDriver({"__rampart_xss": RenderResult(html="<x>", executed_markers=[DOMXSS_TOKEN])})
    v = run_dom_xss_oracle(stub, BASE, "/page", "q")
    assert v.validated is True
    assert v.vuln_class == "DOM_XSS"
    assert v.reproductions >= 2
    assert v.controls["payload_executes"] is True
    assert v.controls["control_executed"] is False
    assert any("EXECUTED" in r for r in v.reasons)


def test_dom_xss_not_confirmed_when_payload_never_executes():
    # Payload is reflected but never executes (empty executed_markers everywhere).
    stub = StubDriver({"__rampart_xss": RenderResult(html="<x>", executed_markers=[])})
    v = run_dom_xss_oracle(stub, BASE, "/page", "q")
    assert v.validated is False
    assert v.reproductions == 0


def test_dom_xss_not_confirmed_when_control_also_executes():
    # Even if the payload executes, a benign control that ALSO "executes" the token means the
    # signal is environment noise, not our injection -> the FP gate must refuse to confirm.
    stub = StubDriver({}, default=RenderResult(executed_markers=[DOMXSS_TOKEN]))
    v = run_dom_xss_oracle(stub, BASE, "/page", "q")
    assert v.controls["control_executed"] is True
    assert v.validated is False


def test_dom_xss_console_message_counts_as_execution():
    # Execution proven via a console message carrying the token (secondary signal).
    stub = StubDriver({"__rampart_xss": RenderResult(console=[f"hello {DOMXSS_TOKEN}"])})
    v = run_dom_xss_oracle(stub, BASE, "/page", "q")
    assert v.validated is True


# --------------------------------------------------------------------- stored XSS oracle
def test_stored_xss_confirmed_when_token_executes_on_reads():
    token = "RAMPART_DOMXSS_stored_demo"
    stub = StubDriver({"/read": RenderResult(executed_markers=[token])})
    v = run_stored_xss_oracle(stub, True, f"{BASE}/read", token)
    assert v.validated is True
    assert v.vuln_class == "STORED_XSS"
    assert v.reproductions >= 2


def test_stored_xss_not_confirmed_when_token_never_executes():
    token = "RAMPART_DOMXSS_stored_demo"
    stub = StubDriver({"/read": RenderResult(executed_markers=[])})
    v = run_stored_xss_oracle(stub, True, f"{BASE}/read", token)
    assert v.validated is False
    assert v.reproductions == 0


def test_stored_xss_requires_write_precondition():
    # The payload executes on read, but the write is reported as failed -> cannot confirm.
    token = "RAMPART_DOMXSS_stored_demo"
    stub = StubDriver({"/read": RenderResult(executed_markers=[token])})
    v = run_stored_xss_oracle(stub, False, f"{BASE}/read", token)
    assert v.validated is False
    assert v.controls["write_ok"] is False


# --------------------------------------------------------------------- graceful degradation
def test_module_imports_cleanly_without_playwright():
    # Importing the engine must never require Playwright (all imports are lazy, inside methods).
    assert engine is not None
    assert hasattr(engine, "PlaywrightDriver")


def test_playwright_is_available_returns_bool_without_raising():
    # Honours the real environment: returns a bool and never raises, Playwright present or not.
    val = PlaywrightDriver().is_available()
    assert isinstance(val, bool)
    assert isinstance(available(), bool)


def test_playwright_driver_unavailable_when_playwright_absent(monkeypatch):
    # Simulate "Playwright not installed": is_available() is False and render() degrades to an
    # empty RenderResult, both without raising.
    def _boom(*a, **k):
        raise ImportError("No module named 'playwright'")

    monkeypatch.setattr(engine, "_load_playwright", _boom)
    d = PlaywrightDriver()
    assert d.is_available() is False
    assert "playwright install" in d.install_hint
    r = d.render(f"{BASE}/anything")
    assert isinstance(r, RenderResult)
    assert r.executed_markers == []
    assert r.ok is False


def test_dom_xss_oracle_degrades_when_engine_unavailable(monkeypatch):
    # An unavailable driver yields a non-validated verdict instead of an exception.
    monkeypatch.setattr(engine, "_load_playwright", lambda *a, **k: (_ for _ in ()).throw(ImportError()))
    v = run_dom_xss_oracle(PlaywrightDriver(), BASE, "/page", "q")
    assert v.validated is False
    assert v.controls["engine_available"] is False
