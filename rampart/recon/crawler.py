"""Scope-gated crawler + attack-surface extractor (blueprint section 13).

BFS over same-host pages via the policy pipeline (GET only, Tier 0). From each HTML page it
extracts links, forms (action + method + input names) and URL query parameters, plus a light
technology fingerprint from headers/body. Everything is deterministic and bounded by
``max_pages``/``max_depth`` and the engagement budget; out-of-scope links are simply never
followed (and would be denied by the pipeline anyway).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import parse_qs, urljoin, urlparse

from ..schemas.appmodel import Endpoint

_TECH_HEADER_SIGS = {
    "x-powered-by": "x-powered-by",
    "server": "server",
    "x-aspnet-version": "asp.net",
    "x-generator": "generator",
}
_TECH_BODY_SIGS = [
    ("wp-content", "WordPress"),
    ("/_next/", "Next.js"),
    ("ng-version", "Angular"),
    ("react", "React"),
    ("__NUXT__", "Nuxt"),
    ("Django", "Django"),
    ("csrfmiddlewaretoken", "Django"),
    ("laravel_session", "Laravel"),
    ("data-drupal", "Drupal"),
    ("X-Flash-Version", "Flash"),
]


@dataclass
class CrawlResult:
    endpoints: list = field(default_factory=list)  # Endpoint objects (provenance=crawl)
    pages_visited: int = 0
    tech: list = field(default_factory=list)
    urls: list = field(default_factory=list)


class _LinkFormParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []
        self.forms: list[dict] = []
        self._cur: dict | None = None

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "a" and a.get("href"):
            self.links.append(a["href"])
        elif tag in ("script", "link") and a.get("src"):
            self.links.append(a["src"])
        elif tag == "form":
            self._cur = {
                "action": a.get("action", ""),
                "method": (a.get("method") or "GET").upper(),
                "inputs": [],
            }
        elif tag in ("input", "textarea", "select") and self._cur is not None and a.get("name"):
            self._cur["inputs"].append(a["name"])

    def handle_endtag(self, tag):
        if tag == "form" and self._cur is not None:
            self.forms.append(self._cur)
            self._cur = None


def _split_pq(path_q: str) -> tuple[str, str]:
    """Split a stored ``path?query`` without re-parsing it as a URL (a path such as ``//[x``
    would otherwise be read as a malformed netloc and raise)."""
    path, _, query = (path_q or "").partition("?")
    return path.split("#", 1)[0] or "/", query.split("#", 1)[0]


def _slug(method: str, path: str) -> str:
    import re

    core = re.sub(r"[^a-z0-9]+", "_", path.lower()).strip("_") or "root"
    return f"ep_{core}_{method.lower()}"


class Crawler:
    def __init__(self, runner, scope, host, port, scheme, max_pages=40, max_depth=3):
        self.runner = runner
        self.scope = scope
        self.host = host
        self.port = port
        self.scheme = scheme
        self.max_pages = max_pages
        self.max_depth = max_depth

    def _in_scope(self, path: str) -> bool:
        hs = self.scope.host_scope(self.host)
        if hs is None or self.scope.path_excluded(path):
            return False
        from ..schemas.scope import path_glob_match

        return any(path_glob_match(p, path) for p in hs.paths_include)

    def _same_host(self, url: str, base_path: str) -> str | None:
        """Resolve a possibly-relative URL; return its path(+query) if same-host & in scope.

        Malformed hrefs (e.g. ``http://[bad/x``) are skipped, never allowed to crash the crawl."""
        host = f"[{self.host}]" if ":" in self.host and not self.host.startswith("[") else self.host
        try:
            absolute = urljoin(f"{self.scheme}://{host}:{self.port}{base_path}", url)
            u = urlparse(absolute)
            hostname = u.hostname
        except (ValueError, TypeError):
            return None
        if u.scheme and u.scheme not in ("http", "https"):
            return None
        if hostname and hostname.lower() != self.host.strip("[]").lower():
            return None
        path = u.path or "/"
        if not self._in_scope(path):
            return None
        return path + (("?" + u.query) if u.query else "")

    def crawl(self, seeds=None) -> CrawlResult:
        result = CrawlResult()
        seen_paths: set[str] = set()
        endpoints: dict[tuple, Endpoint] = {}
        tech: set[str] = set()
        queue: list[tuple[str, int]] = [(s, 0) for s in (seeds or ["/"])]

        def _record(method, path, params):
            key = (method, path)
            ep = endpoints.get(key)
            if ep is None:
                ep = Endpoint(
                    id=_slug(method, path), method=method, path=path, provenance="crawl", parameters=[]
                )
                endpoints[key] = ep
            have = {(p["name"], p["in"]) for p in ep.parameters}
            for name, loc in params:
                if (name, loc) not in have:
                    ep.parameters.append({"name": name, "in": loc, "type": "string"})
                    have.add((name, loc))

        while queue and result.pages_visited < self.max_pages:
            path_q, depth = queue.pop(0)
            base_path, raw_query = _split_pq(path_q)
            if base_path in seen_paths or depth > self.max_depth:
                continue
            seen_paths.add(base_path)

            query = {k: v[0] for k, v in parse_qs(raw_query).items()}
            outcome = self.runner.get(
                base_path,
                session=None,
                query=query,
                payload_class="benign-read",
                rationale="recon crawl",
                summary=f"crawl {base_path}",
            )
            if not outcome.executed:
                continue
            result.pages_visited += 1
            result.urls.append(path_q)

            # record this endpoint (+ any query params seen in the URL)
            _record("GET", base_path, [(k, "query") for k in query])

            # fingerprint
            hdrs = {str(k).lower(): v for k, v in (getattr(outcome.response, "headers", {}) or {}).items()}
            for h, label in _TECH_HEADER_SIGS.items():
                if h in hdrs and hdrs[h]:
                    tech.add(f"{label}: {hdrs[h][:60]}")
            body = outcome.body or ""
            for marker, label in _TECH_BODY_SIGS:
                if marker in body:
                    tech.add(label)

            if "html" not in hdrs.get("content-type", "").lower():
                continue  # only parse HTML for more links

            parser = _LinkFormParser()
            try:
                parser.feed(body)
            except Exception:  # noqa: BLE001 - never let a malformed page break recon
                pass

            # forms -> endpoints with parameters
            for form in parser.forms:
                fp = self._same_host(form["action"] or base_path, base_path)
                if fp is None:
                    continue
                fpath, _ = _split_pq(fp)
                loc = "query" if form["method"] == "GET" else "body"
                _record(form["method"], fpath, [(n, loc) for n in form["inputs"]])

            # links -> enqueue + record query params
            for href in parser.links:
                resolved = self._same_host(href, base_path)
                if resolved is None:
                    continue
                lp, lraw = _split_pq(resolved)
                lq = parse_qs(lraw)
                if lq:
                    _record("GET", lp, [(k, "query") for k in lq])
                if lp not in seen_paths:
                    queue.append((resolved, depth + 1))

        result.endpoints = list(endpoints.values())
        result.tech = sorted(tech)
        return result


def merge_into_model(model, crawl: CrawlResult) -> int:
    """Merge crawler-discovered endpoints into an ApplicationModel; returns #new endpoints.

    Spec/seed endpoints win on metadata; crawl only adds unseen (method, path) pairs and
    augments parameter lists for endpoints already present.
    """
    existing = {(e.method, e.path): e for e in model.endpoints}
    added = 0
    for ep in crawl.endpoints:
        key = (ep.method, ep.path)
        if key in existing:
            cur = existing[key]
            have = {(p["name"], p["in"]) for p in cur.parameters}
            for p in ep.parameters:
                if (p["name"], p["in"]) not in have:
                    cur.parameters.append(p)
                    have.add((p["name"], p["in"]))
        else:
            model.endpoints.append(ep)
            existing[key] = ep
            added += 1
    return added
