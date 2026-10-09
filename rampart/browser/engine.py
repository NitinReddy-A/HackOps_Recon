"""Optional headless-browser engine for execution-proven XSS (blueprint section 31).

Pure-HTTP oracles (``rampart/validation/web_oracles.py``) can only prove that injected
markup is *reflected without encoding*. They cannot prove the browser actually **executed**
it — which is exactly what stored-XSS and DOM-XSS require. This module drives a real headless
browser so a finding can carry proof of JavaScript execution in the live DOM, not an inference
from the HTML source.

Trust boundary (read before wiring this in)
--------------------------------------------
A headless browser makes its **own** network requests: it will fetch the given URL, plus any
sub-resources that page references (scripts, images, XHR/fetch). Those requests do **not** pass
through Rampart's policy choke-point (``ProbeRunner`` / the scope pipeline). Therefore:

* The caller MUST only ever point a driver at a URL that is already **in-scope and authorized**
  for the engagement. The driver trusts the caller on scope; it enforces none of it itself.
* Treat a browser-execution finding as high-value *proof*: the canary token landing in
  ``executed_markers`` means attacker-controlled JavaScript ran in the page's DOM.

Graceful degradation
---------------------
Playwright is an **optional** extra. This module imports cleanly with Playwright absent — every
Playwright import is done lazily *inside* methods. ``PlaywrightDriver.is_available()`` returns
True only when the ``playwright`` package imports AND a browser binary is installed; otherwise
the engine degrades to a no-op (``render`` returns an empty :class:`RenderResult`, never raises)
and the oracles simply fail to confirm. The zero-dependency core is unaffected.
"""

from __future__ import annotations

import importlib
import os
import secrets
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from ..validation.oracle import OracleVerdict

# A module-level, per-process unique canary. If attacker-controlled markup carrying this token
# executes in the DOM, the token lands in RenderResult.executed_markers — our proof of execution.
DOMXSS_TOKEN = f"RAMPART_DOMXSS_{secrets.token_hex(8)}"

# The JS binding/convention name the injected canary calls when it runs.
_BINDING = "__rampart_xss"

# A benign, markup-free control value. A non-executing value must NOT trigger the canary; if it
# does, the "execution" is environment noise, not our injection — so we refuse to confirm.
_BENIGN_CONTROL = "rampart_benign_control"


# --------------------------------------------------------------------------- data
@dataclass
class RenderResult:
    """The outcome of rendering a URL in a real browser.

    * ``html`` — the final serialized DOM *after* JavaScript has run.
    * ``executed_markers`` — unique strings proving script execution (tokens passed to the
      ``__rampart_xss`` binding, or to a wrapped ``alert``/``confirm``/``prompt``).
    * ``console`` — console messages captured during the load (a secondary execution signal).
    """

    html: str = ""
    executed_markers: list = field(default_factory=list)
    console: list = field(default_factory=list)
    error: str = ""
    url: str = ""

    @property
    def ok(self) -> bool:
        return not self.error


# --------------------------------------------------------------------------- lazy import
def _load_playwright():
    """Import Playwright's sync API lazily. Raises ImportError if the extra is not installed.

    Kept as a tiny module-level indirection so tests can simulate "Playwright absent"
    deterministically (by monkeypatching this function) regardless of the host environment.
    """
    return importlib.import_module("playwright.sync_api")


def _safe_text(msg) -> str:
    try:
        return msg.text
    except Exception:  # noqa: BLE001
        try:
            return str(msg)
        except Exception:  # noqa: BLE001
            return ""


# --------------------------------------------------------------------------- drivers
class BrowserDriver:
    """Abstract headless-browser driver. Subclasses never raise out of :meth:`render`."""

    install_hint = ""

    def is_available(self) -> bool:
        return False

    def render(self, url: str, headers: dict | None = None, timeout: float = 10.0) -> RenderResult:
        raise NotImplementedError


class PlaywrightDriver(BrowserDriver):
    """A :class:`BrowserDriver` backed by Playwright/Chromium, imported lazily.

    Nothing here is imported at module load, so the package is usable with Playwright absent.
    """

    install_hint = "pip install rampart-appsec[browser] && python -m playwright install chromium"

    def is_available(self) -> bool:
        """True only if the ``playwright`` package imports AND a Chromium binary is installed."""
        try:
            sync_api = _load_playwright()
        except Exception:  # noqa: BLE001 — package not installed / broken
            return False
        try:
            with sync_api.sync_playwright() as p:
                path = p.chromium.executable_path
                return bool(path and os.path.exists(path))
        except Exception:  # noqa: BLE001 — browser not installed
            return False

    def render(self, url: str, headers: dict | None = None, timeout: float = 10.0) -> RenderResult:
        """Render ``url`` in headless Chromium and report execution evidence.

        Robust by contract: any failure (no Playwright, no browser, navigation error, timeout)
        returns an empty :class:`RenderResult` with ``error`` set — it never raises.

        Scope: the caller guarantees ``url`` is an authorized, in-scope target (see module docs);
        the browser issues its own network requests and is not policed by Rampart.
        """
        result = RenderResult(url=url)
        try:
            sync_api = _load_playwright()
        except Exception as exc:  # noqa: BLE001
            result.error = f"playwright unavailable: {exc}"
            return result

        markers: list = []
        console: list = []

        def _record(token):
            try:
                token = str(token)
                if token and token not in markers:
                    markers.append(token)
            except Exception:  # noqa: BLE001
                pass
            return True

        try:
            with sync_api.sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                try:
                    context = browser.new_context(extra_http_headers=dict(headers or {}))
                    page = context.new_page()
                    # The injected canary calls window.__rampart_xss('<TOKEN>') if it executes.
                    page.expose_function(_BINDING, _record)
                    # console.log(...) is a secondary execution signal.
                    page.on("console", lambda m: console.append(_safe_text(m)))
                    # alert()/confirm()/prompt() dialogs also prove execution; capture + dismiss.
                    page.on("dialog", lambda d: (_record(d.message), d.dismiss()))
                    # Route alert/confirm/prompt through the binding before any page script runs,
                    # so a classic alert(TOKEN) payload still lands in executed_markers.
                    page.add_init_script(
                        "(()=>{try{var h=window.%s;"
                        "['alert','confirm','prompt'].forEach(function(fn){var o=window[fn];"
                        "window[fn]=function(m){try{if(h){h(String(m));}}catch(e){}"
                        "return o?o.call(window,m):undefined;};});}catch(e){}})();" % _BINDING
                    )
                    page.goto(url, wait_until="networkidle", timeout=int(timeout * 1000))
                    try:
                        page.wait_for_timeout(min(500, int(timeout * 1000)))
                    except Exception:  # noqa: BLE001
                        pass
                    result.html = page.content()
                finally:
                    browser.close()
        except Exception as exc:  # noqa: BLE001 — never raise out of render
            result.error = f"render failed: {exc}"

        result.executed_markers = markers
        result.console = console
        return result


class StubDriver(BrowserDriver):
    """A scriptable driver for tests — no real browser required.

    Constructed with a mapping of ``url-substring -> RenderResult | callable(url) -> RenderResult``.
    The first substring found in the rendered URL wins; if none match, ``default`` is used (a
    :class:`RenderResult` or callable), else an empty :class:`RenderResult` is returned.
    """

    install_hint = "(stub driver — no browser required)"

    def __init__(self, responses: dict | None = None, default=None):
        self._responses = dict(responses or {})
        self._default = default
        self.calls: list = []

    def is_available(self) -> bool:
        return True

    def render(self, url: str, headers: dict | None = None, timeout: float = 10.0) -> RenderResult:
        self.calls.append(url)
        for substr, resp in self._responses.items():
            if substr in url:
                out = resp(url) if callable(resp) else resp
                return out if out is not None else RenderResult(url=url)
        if self._default is not None:
            out = self._default(url) if callable(self._default) else self._default
            return out if out is not None else RenderResult(url=url)
        return RenderResult(url=url)


# --------------------------------------------------------------------------- helpers
def available() -> bool:
    """True if the default (Playwright) browser engine is usable in this environment."""
    try:
        return PlaywrightDriver().is_available()
    except Exception:  # noqa: BLE001
        return False


def _canary_payload(token: str) -> str:
    """Markup that, if reflected/stored *unescaped* and executed, calls the binding with TOKEN."""
    return f'"><script>window.{_BINDING}&&window.{_BINDING}({token!r})</script>'


def _build_url(base_url: str, path: str, param: str, value: str) -> str:
    base = (base_url or "").rstrip("/")
    if path:
        full = base + (path if path.startswith("/") else "/" + path)
    else:
        full = base
    parts = urlsplit(full)
    q = dict(parse_qsl(parts.query, keep_blank_values=True))
    q[param] = value
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(q), parts.fragment))


def _executed(render: RenderResult, token: str) -> bool:
    """Execution proof: the token reached the binding, or appeared in a console message."""
    if token in (getattr(render, "executed_markers", None) or []):
        return True
    for c in getattr(render, "console", None) or []:
        try:
            if token in str(c):
                return True
        except Exception:  # noqa: BLE001
            continue
    return False


# --------------------------------------------------------------------------- oracles
def run_dom_xss_oracle(
    driver: BrowserDriver, base_url: str, path: str, param: str, reproductions: int = 2
) -> OracleVerdict:
    """Confirm DOM/reflected XSS by *execution*, not reflection.

    Renders ``base_url + path?param=<executing canary>`` in a real browser. CONFIRMED only if the
    canary TOKEN actually executes (lands in ``executed_markers``) on ``reproductions``+ renders
    AND a benign control value does NOT execute it. Mirrors the deterministic FP discipline of
    the HTTP oracles: a positive signal alone is never enough.
    """
    token = DOMXSS_TOKEN
    mal_url = _build_url(base_url, path, param, _canary_payload(token))
    benign_url = _build_url(base_url, path, param, _BENIGN_CONTROL)

    reasons: list = []
    fp: list = []

    if not driver.is_available():
        return OracleVerdict(
            validated=False,
            vuln_class="DOM_XSS",
            reasons=[f"FAIL: headless-browser engine unavailable ({getattr(driver, 'install_hint', '')})"],
            false_positive_checks=["no browser engine; cannot prove DOM execution"],
            controls={"token": token, "engine_available": False},
        )

    # negative control: a markup-free value must not execute the canary
    control = driver.render(benign_url)
    control_executed = _executed(control, token)
    reasons.append(
        ("PASS" if not control_executed else "FAIL")
        + ": benign control value does NOT execute the canary in the DOM"
    )
    fp.append(f"control executed_markers={list(control.executed_markers or [])}")

    # the payload must actually execute, reproduced N times from fresh renders
    repro_ok = 0
    consoles: list = []
    for _ in range(max(1, reproductions)):
        r = driver.render(mal_url)
        consoles.extend(r.console or [])
        if _executed(r, token):
            repro_ok += 1
    payload_executes = repro_ok >= reproductions
    reasons.append(
        ("PASS" if payload_executes else "FAIL")
        + f": injected canary EXECUTED in the DOM on {repro_ok}/{reproductions} renders"
    )
    fp.append(
        "execution proven by a JS binding/console callback in the live DOM, "
        "not by the payload merely appearing in the HTML source"
    )
    fp.append(f"reproduced {repro_ok}/{reproductions} times via headless render")

    validated = payload_executes and not control_executed
    return OracleVerdict(
        validated=validated,
        vuln_class="DOM_XSS",
        reasons=reasons,
        false_positive_checks=fp,
        reproductions=repro_ok,
        evidence=list(consoles),
        controls={
            "token": token,
            "engine_available": True,
            "control_executed": control_executed,
            "payload_executes": payload_executes,
            "probe_url": mal_url,
            "control_url": benign_url,
        },
    )


def run_stored_xss_oracle(
    driver: BrowserDriver, write_outcome_bool: bool, read_url: str, token: str, reproductions: int = 2
) -> OracleVerdict:
    """Confirm *stored* XSS — the read/verify half only.

    The caller is responsible for the write (it already stored a payload that, if executed, calls
    the binding with ``token``). This renders ``read_url`` in a real browser and CONFIRMS only if
    ``token`` executes in the DOM on ``reproductions``+ independent page loads AND the write
    precondition held. The write itself is out of scope here.
    """
    reasons: list = []
    fp: list = []

    reasons.append(
        ("PASS" if write_outcome_bool else "FAIL")
        + ": payload was successfully stored by the caller (write precondition)"
    )

    if not driver.is_available():
        return OracleVerdict(
            validated=False,
            vuln_class="STORED_XSS",
            reasons=reasons
            + [f"FAIL: headless-browser engine unavailable ({getattr(driver, 'install_hint', '')})"],
            false_positive_checks=["no browser engine; cannot prove DOM execution"],
            controls={"token": token, "engine_available": False, "write_ok": write_outcome_bool},
        )

    repro_ok = 0
    consoles: list = []
    if write_outcome_bool:
        for _ in range(max(1, reproductions)):
            r = driver.render(read_url)
            consoles.extend(r.console or [])
            if _executed(r, token):
                repro_ok += 1

    executes = bool(write_outcome_bool) and repro_ok >= reproductions
    reasons.append(
        ("PASS" if executes else "FAIL")
        + f": stored payload EXECUTED in the DOM on {repro_ok}/{reproductions} fresh reads"
    )
    fp.append(
        "execution proven by a browser JS callback on a fresh page load "
        "(persistent/stored, not a one-off reflection)"
    )
    fp.append(f"reproduced {repro_ok}/{reproductions} times")

    return OracleVerdict(
        validated=executes,
        vuln_class="STORED_XSS",
        reasons=reasons,
        false_positive_checks=fp,
        reproductions=repro_ok,
        evidence=list(consoles),
        controls={
            "token": token,
            "engine_available": True,
            "write_ok": bool(write_outcome_bool),
            "renders_executed": repro_ok,
            "read_url": read_url,
        },
    )
