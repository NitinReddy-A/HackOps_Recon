"""Pure URL -> Endpoint normalisation for JS/SPA route discovery (no Playwright).

:class:`PlaywrightDriver.discover` harvests anchors, form actions and network requests from a
rendered single-page app; this module turns that raw harvest into :class:`Endpoint` objects
**without importing Playwright**, so the logic unit-tests with no Chromium.

Scope safety: every candidate URL is run through the SAME ``allow(url, method)`` predicate the
browser engine uses (default :func:`same_origin_allow` of the target). An out-of-scope or
non-HTTP(S) URL can never become an endpoint — so an SPA that links to a third-party origin
produces no out-of-scope discovery. Provenance is set to ``"browser"`` so a discovered endpoint
is distinguishable from crawled/spec ones, and it merges through the crawler's ``merge_into_model``
so it flows into hypothesis generation exactly like a crawled endpoint.
"""

from __future__ import annotations

import re
from urllib.parse import parse_qs, urljoin, urlsplit

from ..recon.crawler import CrawlResult
from ..schemas.appmodel import Endpoint
from .engine import same_origin_allow

_HTTP = ("http", "https")
# Hrefs that are not navigable application routes — never turned into endpoints.
_SKIP_HREF_PREFIX = ("#", "javascript:", "mailto:", "tel:", "data:", "blob:", "about:")


def _slug(method: str, path: str) -> str:
    core = re.sub(r"[^a-z0-9]+", "_", (path or "").lower()).strip("_") or "root"
    return f"ep_{core}_{method.lower()}"


def endpoints_from_discovery(
    target_url: str,
    links=None,
    requests=None,
    forms=None,
    allow=None,
) -> list:
    """Normalise a browser harvest into deduped, in-scope :class:`Endpoint` objects.

    * ``links`` — anchor hrefs (absolute or relative strings); each becomes a ``GET`` endpoint,
      its query-string names recorded as ``in="query"`` parameters.
    * ``requests`` — ``{"method","url"}`` dicts (fetch/XHR/document); ``GET`` requests contribute
      their query-param names, other methods contribute just the ``(method, path)``.
    * ``forms`` — ``{"action","method","inputs":[name,...]}`` dicts; a ``GET`` form's inputs are
      ``in="query"``, any other method's inputs are ``in="body"``.

    Dedup is by ``(method, path)``; parameter lists are merged. Only URLs that are HTTP(S) **and**
    pass ``allow(url, method)`` survive — everything else (out-of-scope, non-network schemes,
    malformed) is dropped. ``allow`` defaults to :func:`same_origin_allow` of ``target_url``.
    Returns a list of :class:`Endpoint` with ``provenance="browser"``.
    """
    allow = allow or same_origin_allow(target_url)
    base = target_url or ""
    endpoints: dict[tuple, Endpoint] = {}

    def _ok(url: str, method: str = "GET") -> bool:
        try:
            return bool(allow(url, method))
        except Exception:  # noqa: BLE001 - a broken predicate denies (fail-closed)
            return False

    def _record(method: str, path: str, params) -> None:
        method = (method or "GET").upper()
        key = (method, path)
        ep = endpoints.get(key)
        if ep is None:
            ep = Endpoint(
                id=_slug(method, path), method=method, path=path, provenance="browser", parameters=[]
            )
            endpoints[key] = ep
        have = {(p["name"], p["in"]) for p in ep.parameters}
        for name, loc in params:
            if name and (name, loc) not in have:
                ep.parameters.append({"name": name, "in": loc, "type": "string"})
                have.add((name, loc))

    def _resolve(raw: str, method: str = "GET"):
        """Resolve ``raw`` (possibly relative) against the target; return (path, query_string) if
        it is HTTP(S) and in scope for ``method``, else ``None``."""
        if not raw:
            return None
        s = str(raw).strip()
        if any(s.lower().startswith(p) for p in _SKIP_HREF_PREFIX):
            return None
        try:
            absolute = urljoin(base, s)
            u = urlsplit(absolute)
        except (ValueError, TypeError):
            return None
        if u.scheme not in _HTTP or not u.hostname:
            return None
        if not _ok(absolute, method):
            return None
        return (u.path or "/", u.query)

    # Anchors -> GET endpoints (+ any query params present in the href).
    for href in links or []:
        resolved = _resolve(href, "GET")
        if resolved is None:
            continue
        path, query = resolved
        _record("GET", path, [(k, "query") for k in parse_qs(query, keep_blank_values=True)])

    # Network requests -> endpoints. GET contributes query-param names; others just method+path.
    for req in requests or []:
        if not isinstance(req, dict):
            continue
        method = str(req.get("method") or "GET").upper()
        resolved = _resolve(req.get("url") or "", method)
        if resolved is None:
            continue
        path, query = resolved
        params = [(k, "query") for k in parse_qs(query, keep_blank_values=True)] if method == "GET" else []
        _record(method, path, params)

    # Forms -> endpoints; inputs are query params for GET, body params otherwise.
    for form in forms or []:
        if not isinstance(form, dict):
            continue
        method = str(form.get("method") or "GET").upper()
        resolved = _resolve(form.get("action") or base, method)
        if resolved is None:
            continue
        path, query = resolved
        loc = "query" if method == "GET" else "body"
        names = [(k, "query") for k in parse_qs(query, keep_blank_values=True)] if method == "GET" else []
        names += [(n, loc) for n in (form.get("inputs") or [])]
        _record(method, path, names)

    return list(endpoints.values())


def browser_discover(
    driver,
    target_url: str,
    allow=None,
    on_request=None,
    timeout: float = 10.0,
    seeds=None,
) -> CrawlResult:
    """Render the seed URL(s) with ``driver`` and return a :class:`CrawlResult` of browser-provenance
    endpoints, ready for :func:`rampart.recon.merge_into_model` — the SAME merge the crawler uses.

    A clean no-op (empty :class:`CrawlResult`) when the driver is missing/unavailable; a per-seed
    render error is skipped. Never raises. All scope filtering is delegated to ``allow`` (default
    :func:`same_origin_allow` of ``target_url``), which the driver also enforces as a route-guard.
    """
    result = CrawlResult()
    if driver is None or not driver.is_available():
        return result
    allow = allow or same_origin_allow(target_url)
    base = (target_url or "").rstrip("/")
    links_all: list = []
    requests_all: list = []
    forms_all: list = []
    pages = 0
    urls: list = []
    for seed in seeds or ["/"]:
        seed = str(seed)
        page_url = seed if "://" in seed else base + (seed if seed.startswith("/") else "/" + seed)
        r = driver.discover(page_url, allow=allow, on_request=on_request, timeout=timeout)
        if getattr(r, "error", ""):
            continue
        pages += 1
        urls.append(page_url)
        links_all.extend(r.discovered_links or [])
        requests_all.extend(r.discovered_requests or [])
        forms_all.extend(r.discovered_forms or [])
    result.endpoints = endpoints_from_discovery(
        target_url, links=links_all, requests=requests_all, forms=forms_all, allow=allow
    )
    result.pages_visited = pages
    result.urls = urls
    return result
