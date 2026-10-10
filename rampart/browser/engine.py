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
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

from ..validation.oracle import OracleVerdict

install_hint = "pip install rampart-appsec[browser] && python -m playwright install chromium"

# A module-level, per-process unique canary. If attacker-controlled markup carrying this token
# executes in the DOM, the token lands in RenderResult.executed_markers — our proof of execution.
DOMXSS_TOKEN = f"RAMPART_DOMXSS_{secrets.token_hex(8)}"

# The JS binding/convention name the injected canary calls when it runs.
_BINDING = "__rampart_xss"

# A benign, markup-free control value. A non-executing value must NOT trigger the canary; if it
# does, the "execution" is environment noise, not our injection — so we refuse to confirm.
_BENIGN_CONTROL = "rampart_benign_control"


def same_origin_allow(target_url: str):
    """Build the DEFAULT request predicate: allow only the target's own origin (scheme+host+port).

    Returned callable ``allow(url, method) -> bool``. The integration pass passes its own
    predicate (the policy pipeline's scope check) instead; this is the safe default when none is
    given. A relative/opaque URL (``about:blank``, ``data:``) is allowed — it issues no network.
    """
    t = urlsplit(target_url or "")
    t_origin = (t.scheme, (t.hostname or "").lower(), t.port or _default_port(t.scheme))

    def allow(url: str, method: str = "GET") -> bool:  # noqa: ARG001 - method kept for parity
        try:
            u = urlsplit(url or "")
        except ValueError:
            return False
        if not u.scheme or u.scheme in ("about", "data", "blob", "javascript"):
            return True  # not a network fetch to another origin
        return (u.scheme, (u.hostname or "").lower(), u.port or _default_port(u.scheme)) == t_origin

    return allow


def _default_port(scheme: str):
    return {"http": 80, "https": 443}.get((scheme or "").lower())


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
    # Out-of-scope / excluded sub-requests the route handler aborted (url, method).
    blocked_requests: list = field(default_factory=list)
    # Every sub-request the page attempted, as (url, method, allowed) — for auditing.
    requests: list = field(default_factory=list)
    # The RAW top-level HTTP response body (before JS ran) — lets a caller tell a server-reflected
    # payload (present here) from a pure DOM-sink one (absent here, injected client-side).
    response_body: str = ""
    # --- SPA/JS route-discovery harvest (populated by PlaywrightDriver.discover) ---
    # Anchor hrefs present in the FINAL (post-JS) rendered DOM, as absolute URLs.
    discovered_links: list = field(default_factory=list)
    # In-scope network requests the page issued (fetch/XHR/document), as {"method","url"} dicts.
    discovered_requests: list = field(default_factory=list)
    # Forms in the final DOM, as {"action","method","inputs":[name,...]} dicts (action absolute).
    discovered_forms: list = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.error

    @property
    def skipped(self) -> bool:
        return bool(self.error)


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


# The JS harvested from the final (post-JS) DOM: anchor hrefs (absolute) + form action/method/inputs.
_HARVEST_JS = """
() => {
  const links = Array.from(document.querySelectorAll('a[href]')).map(a => a.href);
  const forms = Array.from(document.querySelectorAll('form')).map(f => ({
    action: f.action || '',
    method: (f.method || 'GET').toUpperCase(),
    inputs: Array.from(f.querySelectorAll('input[name], textarea[name], select[name]')).map(i => i.name)
  }));
  return {links: links, forms: forms};
}
"""

# Network requests worth treating as application endpoints (the API surface a static crawl misses).
# Static sub-resources (images/css/fonts/scripts) are deliberately excluded to keep the model clean.
_API_RESOURCE_TYPES = {"fetch", "xhr", "document"}


def _make_scope_route(allow, on_request, requests, blocked, result=None, capture_body=False):
    """Build a ``context.route`` handler enforcing ``allow(url, method)`` on EVERY sub-request.

    Shared by :meth:`PlaywrightDriver.render` and :meth:`PlaywrightDriver.discover` so the scope
    route-guard (C-3) is identical for both: an out-of-scope sub-request (image/script/iframe/
    fetch/XHR, or a redirect target) is ABORTED, recorded in ``blocked`` and audited via
    ``on_request``; it is never sent. ``capture_body`` grabs the raw top-level document body into
    ``result.response_body`` (render's reflected-vs-DOM triage); discovery does not need it.
    """

    def _route(route):
        req = route.request
        req_url = req.url
        method = req.method
        try:
            permitted = bool(allow(req_url, method))
        except Exception:  # noqa: BLE001 - a broken predicate denies (fail-closed)
            permitted = False
        requests.append((req_url, method, permitted))
        if on_request is not None:
            try:
                on_request(req_url, method, permitted)
            except Exception:  # noqa: BLE001 - auditing must never break the render
                pass
        if permitted:
            try:
                # Fetch WITHOUT auto-following redirects. Chromium follows a FULFILLED redirect
                # internally WITHOUT raising a new route event, so an off-origin 3xx would
                # silently leave scope — we therefore inspect the Location ourselves and abort
                # a redirect whose target is not permitted.
                resp = route.fetch(max_redirects=0)
                status = getattr(resp, "status", 0)
                if 300 <= status < 400:
                    location = ""
                    try:
                        location = (resp.headers or {}).get("location", "")
                    except Exception:  # noqa: BLE001
                        location = ""
                    abs_loc = urljoin(req_url, location) if location else ""
                    permitted_redirect = True
                    if abs_loc:
                        try:
                            permitted_redirect = bool(allow(abs_loc, "GET"))
                        except Exception:  # noqa: BLE001
                            permitted_redirect = False
                    if not permitted_redirect:
                        requests.append((abs_loc, "GET", False))
                        if on_request is not None:
                            try:
                                on_request(abs_loc, "GET", False)
                            except Exception:  # noqa: BLE001
                                pass
                        blocked.append((abs_loc, "GET"))
                        route.abort("blockedbyclient")
                        return
                # Capture the RAW top-level document body (pre-JS) for reflected-vs-DOM triage.
                if capture_body and result is not None and not result.response_body:
                    is_doc = method == "GET"
                    try:
                        is_doc = req.is_navigation_request()
                    except Exception:  # noqa: BLE001
                        pass
                    if is_doc:
                        try:
                            result.response_body = resp.text()
                        except Exception:  # noqa: BLE001
                            pass
                route.fulfill(response=resp)
            except Exception:  # noqa: BLE001 - fall back to a normal continue
                try:
                    route.continue_()
                except Exception:  # noqa: BLE001
                    pass
        else:
            blocked.append((req_url, method))
            try:
                route.abort("blockedbyclient")
            except Exception:  # noqa: BLE001
                pass

    return _route


# --------------------------------------------------------------------------- drivers
class BrowserDriver:
    """Abstract headless-browser driver. Subclasses never raise out of :meth:`render`."""

    install_hint = ""

    def is_available(self) -> bool:
        return False

    def render(
        self,
        url: str,
        headers: dict | None = None,
        timeout: float = 10.0,
        allow=None,
        on_request=None,
    ) -> RenderResult:
        raise NotImplementedError

    def discover(
        self,
        url: str,
        headers: dict | None = None,
        timeout: float = 10.0,
        allow=None,
        on_request=None,
    ) -> RenderResult:
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

    def render(
        self,
        url: str,
        headers: dict | None = None,
        timeout: float = 10.0,
        allow=None,
        on_request=None,
    ) -> RenderResult:
        """Render ``url`` in headless Chromium and report execution evidence.

        Robust by contract: any failure (no Playwright, no browser, navigation error, timeout)
        returns an empty :class:`RenderResult` with ``error`` set — it never raises.

        Scope enforcement (C-3): a ``context.route("**/*", …)`` handler ABORTS every sub-request
        (image/script/iframe/fetch/XHR, and the follow-up of any redirect) whose URL is not
        permitted by ``allow(url, method) -> bool``. ``allow`` defaults to same-origin-only
        (:func:`same_origin_allow` of ``url``); the integration pass passes the policy pipeline's
        scope check. Each attempted sub-request is reported to ``on_request(url, method, allowed)``
        for auditing, and aborted ones are also recorded in ``result.blocked_requests``.
        """
        result = RenderResult(url=url)
        try:
            sync_api = _load_playwright()
        except Exception as exc:  # noqa: BLE001
            result.error = f"playwright unavailable: {exc}"
            return result

        allow = allow or same_origin_allow(url)
        markers: list = []
        console: list = []
        blocked: list = []
        requests: list = []

        def _record(token):
            try:
                token = str(token)
                if token and token not in markers:
                    markers.append(token)
            except Exception:  # noqa: BLE001
                pass
            return True

        _route = _make_scope_route(allow, on_request, requests, blocked, result=result, capture_body=True)

        try:
            with sync_api.sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                try:
                    context = browser.new_context(extra_http_headers=dict(headers or {}))
                    context.route("**/*", _route)
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
        result.blocked_requests = blocked
        result.requests = requests
        return result

    def discover(
        self,
        url: str,
        headers: dict | None = None,
        timeout: float = 10.0,
        allow=None,
        on_request=None,
    ) -> RenderResult:
        """Render ``url`` and harvest its SPA/JS attack surface — the routes/endpoints a GET-only
        static crawl cannot see because they appear only after JavaScript runs.

        Collects, on :class:`RenderResult`:

        * ``discovered_links`` — anchor ``href``s in the FINAL (post-JS) DOM (absolute URLs);
        * ``discovered_forms`` — ``{action, method, inputs}`` for every form in that DOM;
        * ``discovered_requests`` — the in-scope ``{method, url}`` of each fetch/XHR/document
          request the page issued (the real API surface; static sub-resources are dropped).

        Scope is enforced by the SAME route-guard as :meth:`render` (shared
        :func:`_make_scope_route`): an out-of-scope sub-request is aborted and recorded in
        ``blocked_requests`` — never sent — and a request that does not pass ``allow`` is never
        returned as discovered. ``allow`` defaults to :func:`same_origin_allow` of ``url``.

        Robust by contract: any failure returns a :class:`RenderResult` with ``error`` set and
        empty harvest lists — it never raises.
        """
        result = RenderResult(url=url)
        try:
            sync_api = _load_playwright()
        except Exception as exc:  # noqa: BLE001
            result.error = f"playwright unavailable: {exc}"
            return result

        allow = allow or same_origin_allow(url)
        blocked: list = []
        requests: list = []
        net: list = []  # (method, url, resource_type) for every request the page issued

        def _on_req(req):
            try:
                net.append((req.method, req.url, (req.resource_type or "").lower()))
            except Exception:  # noqa: BLE001 - harvesting must never break the render
                pass

        _route = _make_scope_route(allow, on_request, requests, blocked)
        links: list = []
        forms: list = []
        try:
            with sync_api.sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                try:
                    context = browser.new_context(extra_http_headers=dict(headers or {}))
                    context.route("**/*", _route)
                    page = context.new_page()
                    # Capture the method/URL/type of every request the page fires (fetch/XHR/doc).
                    page.on("request", _on_req)
                    page.goto(url, wait_until="networkidle", timeout=int(timeout * 1000))
                    try:
                        page.wait_for_timeout(min(500, int(timeout * 1000)))
                    except Exception:  # noqa: BLE001
                        pass
                    result.html = page.content()
                    try:
                        harvest = page.evaluate(_HARVEST_JS) or {}
                        links = list(harvest.get("links") or [])
                        forms = [dict(f) for f in (harvest.get("forms") or [])]
                    except Exception:  # noqa: BLE001 - a hostile DOM must not break discovery
                        pass
                finally:
                    browser.close()
        except Exception as exc:  # noqa: BLE001 — never raise out of discover
            result.error = f"discover failed: {exc}"

        result.requests = requests
        result.blocked_requests = blocked
        result.discovered_links = links
        result.discovered_forms = forms
        # Keep only in-scope, API-ish network requests; out-of-scope ones were already aborted and
        # are recorded in blocked_requests — they are never returned as discovered.
        seen: set = set()
        disc: list = []
        for method, req_url, rtype in net:
            if rtype and rtype not in _API_RESOURCE_TYPES:
                continue
            try:
                if not allow(req_url, method):
                    continue
            except Exception:  # noqa: BLE001 - fail closed
                continue
            key = ((method or "GET").upper(), req_url)
            if key in seen:
                continue
            seen.add(key)
            disc.append({"method": key[0], "url": req_url})
        result.discovered_requests = disc
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

    def render(
        self,
        url: str,
        headers: dict | None = None,
        timeout: float = 10.0,
        allow=None,
        on_request=None,
    ) -> RenderResult:
        self.calls.append(url)
        for substr, resp in self._responses.items():
            if substr in url:
                out = resp(url) if callable(resp) else resp
                return out if out is not None else RenderResult(url=url)
        if self._default is not None:
            out = self._default(url) if callable(self._default) else self._default
            return out if out is not None else RenderResult(url=url)
        return RenderResult(url=url)

    # Discovery uses the same scripted-response lookup; a test seeds a RenderResult carrying
    # discovered_links / discovered_requests / discovered_forms.
    discover = render


# --------------------------------------------------------------------------- helpers
def available() -> bool:
    """True if the default (Playwright) browser engine is usable in this environment."""
    try:
        return PlaywrightDriver().is_available()
    except Exception:  # noqa: BLE001
        return False


def browser_skip_reason() -> str:
    """ "" when the browser pass can run, else a structured skip reason for the integration pass
    (C-13), e.g. ``"browser: skipped — pip install rampart-appsec[browser] && python -m
    playwright install chromium"``."""
    return "" if available() else f"browser: skipped — {install_hint}"


def audited_on_request(guard):
    """Adapt a :class:`~rampart.infra.sidechannel.SideChannelGuard` to the ``on_request`` hook.

    Returns ``on_request(url, method, allowed)`` that records ONE audit event + consumes ONE
    budget request per browser sub-request (allowed ones; a denied one is audited as blocked).
    ``guard=None`` -> ``None`` (no auditing). Use together with an ``allow`` predicate: the guard
    here audits, the predicate decides."""
    if guard is None:
        return None

    def on_request(url, method, allowed):
        try:
            host = urlsplit(url or "").hostname or ""
        except ValueError:
            host = ""
        guard.admit(host, {"kind": "browser-request", "method": method, "url": url}, allowed=allowed)

    return on_request


def _canary_payload(token: str) -> str:
    """The primary canary (image/onerror). Unlike a bare ``<script>``, this EXECUTES when assigned
    through ``innerHTML`` (the DOM sink in demo's /dom?x=), and also when reflected into markup."""
    return f'"><img src=x onerror="window.{_BINDING}&&window.{_BINDING}(\'{token}\')">'


def _canary_payloads(token: str) -> list[str]:
    """All execution-canary variants, tried in turn. Each runs via ``innerHTML`` assignment:

    * ``<img src=x onerror=…>`` — fires on the failed image load;
    * ``<svg onload=…>`` — fires on SVG insertion;
    * ``"><script>…</script>`` — the classic reflected-XSS variant (does NOT run via innerHTML,
      but does when reflected into the served HTML) kept so server-reflected sinks still execute.
    """
    call = f"window.{_BINDING}&&window.{_BINDING}('{token}')"
    return [
        f'"><img src=x onerror="{call}">',
        f'"><svg onload="{call}">',
        f'"><script>{call}</script>',
    ]


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
    driver: BrowserDriver,
    base_url: str,
    path: str,
    param: str,
    reproductions: int = 2,
    allow=None,
    on_request=None,
) -> OracleVerdict:
    """Confirm *DOM-based* XSS by *execution*, and DEDUPE it from server-reflected XSS (C-4).

    For each innerHTML-capable canary (:func:`_canary_payloads`), renders
    ``base_url + path?param=<canary>`` in a real browser. CONFIRMED only when ALL hold:

    * the canary TOKEN actually executes (lands in ``executed_markers``) on ``reproductions``+
      fresh renders, AND a benign control value does NOT execute it; AND
    * the **raw** payload is NOT present in the server's HTTP response body for that request —
      i.e. the sink is client-side (``innerHTML`` etc.), not a server reflection. When the server
      already echoes the payload into its HTML, this is REFLECTED XSS (reported by the HTTP
      oracle), so the DOM oracle skips it to avoid a double count.

    ``allow``/``on_request`` are forwarded to the driver so the scope route-guard and request
    auditing apply to the browser's own sub-requests.
    """
    token = DOMXSS_TOKEN
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

    def _render(u):
        return driver.render(u, allow=allow, on_request=on_request)

    # negative control: a markup-free value must not execute the canary
    benign_url = _build_url(base_url, path, param, _BENIGN_CONTROL)
    control = _render(benign_url)
    control_executed = _executed(control, token)
    reasons.append(
        ("PASS" if not control_executed else "FAIL")
        + ": benign control value does NOT execute the canary in the DOM"
    )
    fp.append(f"control executed_markers={list(control.executed_markers or [])}")

    consoles: list = []
    chosen_payload = ""
    repro_ok = 0
    server_reflected = False
    for payload in _canary_payloads(token):
        mal_url = _build_url(base_url, path, param, payload)
        ok = 0
        reflected = False
        for _ in range(max(1, reproductions)):
            r = _render(mal_url)
            consoles.extend(r.console or [])
            if payload in (r.response_body or ""):
                reflected = True
            if _executed(r, token):
                ok += 1
        if ok >= reproductions:
            chosen_payload, repro_ok, server_reflected = payload, ok, reflected
            break

    payload_executes = repro_ok >= reproductions
    reasons.append(
        ("PASS" if payload_executes else "FAIL")
        + f": an innerHTML-capable canary EXECUTED in the DOM on {repro_ok}/{reproductions} renders"
    )
    # Dedupe: if the server reflected the raw payload into its response, this is reflected XSS.
    is_dom_sink = payload_executes and not server_reflected
    reasons.append(
        ("PASS" if is_dom_sink else "SKIP")
        + ": the raw payload is "
        + ("ABSENT from" if is_dom_sink else "PRESENT in")
        + " the server's HTTP response body — "
        + ("client-side DOM sink (DOM-XSS)" if is_dom_sink else "server-reflected XSS, deduped here")
    )
    fp.append(
        "execution proven by a JS binding/console callback in the live DOM, "
        "not by the payload merely appearing in the HTML source"
    )
    fp.append(f"reproduced {repro_ok}/{reproductions} times via headless render")
    fp.append(
        "classified DOM-based only because the raw payload was NOT in the server response body "
        "(so the write happened in client JS, e.g. innerHTML), de-duplicating server-reflected XSS"
    )

    validated = payload_executes and not control_executed and is_dom_sink
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
            "server_reflected": server_reflected,
            "is_dom_sink": is_dom_sink,
            "payload": chosen_payload,
            "control_url": benign_url,
        },
    )


def run_stored_xss_oracle(
    driver: BrowserDriver,
    write_outcome_bool: bool,
    read_url: str,
    token: str,
    reproductions: int = 2,
    allow=None,
    on_request=None,
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
            r = driver.render(read_url, allow=allow, on_request=on_request)
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
