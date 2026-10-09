"""OSV.dev advisory client (stdlib urllib) with an injectable network seam.

OSV (https://osv.dev) is the open, aggregated vulnerability database for OSS. We query it with the
exact version of each package and read back the advisories that affect it, extracting the fixed
version so a finding can recommend a concrete upgrade.

Two deliberate design choices:
  * The ``fetch`` callable is injectable so tests run fully offline and so the whole module stays
    graceful — any network error returns "no advisories", never an exception that breaks a scan.
  * Querying OSV sends package *names/versions* to an external service, so the engagement only does
    it when the operator opts in (``--sca-online``); offline, SCA still inventories dependencies.

Bulk scans use ``/v1/querybatch`` (up to 1000 queries per call, ids only) followed by
``/v1/vulns/{id}`` for the details of each distinct advisory.
"""

from __future__ import annotations

import json
import re
import urllib.request

OSV_QUERY_URL = "https://api.osv.dev/v1/query"
OSV_QUERYBATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/"
QUERYBATCH_MAX = 1000
_USER_AGENT = "rampart-sca/1.0 (+https://osv.dev)"


def http_fetch(url: str, payload: dict | None, timeout: float = 15.0) -> dict | None:
    """Default network fetch: POST JSON to OSV (GET when ``payload`` is None), return parsed JSON,
    or None on any failure."""
    try:
        headers = {"User-Agent": _USER_AGENT}
        data = None
        if payload is not None:
            data = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=data, method="POST" if data else "GET", headers=headers)
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - fixed OSV host
            return json.loads(resp.read().decode("utf-8"))
    except Exception:  # noqa: BLE001 - SCA must degrade gracefully, never crash a scan
        return None


def _name_eq(ecosystem: str, a: str, b: str) -> bool:
    if ecosystem == "PyPI":
        from .parsers import normalize_pypi

        return normalize_pypi(a) == normalize_pypi(b)
    return a == b


def query_package(ecosystem: str, name: str, version: str, fetch=None, timeout: float = 15.0) -> list[dict]:
    """Return the list of OSV advisory dicts affecting ``name@version`` (empty on miss/error).

    ``fetch`` is the network seam, called as ``fetch(url, payload, timeout) -> dict | None``.
    Tests inject their own; the default is :func:`http_fetch`.
    """
    fetch = fetch or http_fetch
    payload = {"version": version, "package": {"name": name, "ecosystem": ecosystem}}
    vulns: list[dict] = []
    for _ in range(20):  # follow pagination (next_page_token) a bounded number of times
        try:
            out = fetch(OSV_QUERY_URL, payload, timeout)
        except Exception:  # noqa: BLE001 - a broken seam means "no advisories", never a crash
            return vulns
        if not isinstance(out, dict):
            return vulns
        page = out.get("vulns")
        if isinstance(page, list):
            vulns.extend(v for v in page if isinstance(v, dict))
        token = out.get("next_page_token")
        if not token:
            break
        payload = dict(payload, page_token=token)
    return vulns


def query_batch(packages: list[tuple[str, str, str]], fetch=None, timeout: float = 15.0):
    """Batch-match ``[(ecosystem, name, version), ...]`` against OSV.

    Returns a list (same order) of advisory-dict lists, or None when the batch endpoint is not
    usable through this ``fetch`` seam (callers then fall back to :func:`query_package`).
    """
    fetch = fetch or http_fetch
    ids_per_pkg: list[list[str]] = []
    paged: set[int] = set()
    for start in range(0, len(packages), QUERYBATCH_MAX):
        chunk = packages[start : start + QUERYBATCH_MAX]
        payload = {"queries": [{"version": v, "package": {"name": n, "ecosystem": e}} for e, n, v in chunk]}
        try:
            out = fetch(OSV_QUERYBATCH_URL, payload, timeout)
        except Exception:  # noqa: BLE001 - seam doesn't speak querybatch -> per-package fallback
            return None
        results = out.get("results") if isinstance(out, dict) else None
        if not isinstance(results, list) or len(results) != len(chunk):
            return None
        for j, res in enumerate(results):
            res = res if isinstance(res, dict) else {}
            ids_per_pkg.append(
                [v.get("id") for v in res.get("vulns") or [] if isinstance(v, dict) and v.get("id")]
            )
            if res.get("next_page_token"):
                paged.add(start + j)
    cache: dict[str, dict | None] = {}
    out_lists: list[list[dict]] = []
    for idx, ids in enumerate(ids_per_pkg):
        if idx in paged:  # more advisories than one batch page — query this package directly
            e, n, v = packages[idx]
            out_lists.append(query_package(e, n, v, fetch=fetch, timeout=timeout))
            continue
        vulns = []
        for vid in dict.fromkeys(ids):
            if vid not in cache:
                try:
                    detail = fetch(OSV_VULN_URL + vid, None, timeout)
                except Exception:  # noqa: BLE001
                    detail = None
                cache[vid] = detail if isinstance(detail, dict) and detail.get("id") else {"id": vid}
            vulns.append(cache[vid])
        out_lists.append(vulns)
    return out_lists


# ------------------------------------------------------------------------- version ordering
_PRE_PHASE = {"dev": -1, "a": 0, "alpha": 0, "b": 1, "beta": 1, "c": 2, "rc": 2, "pre": 2, "preview": 2}
_FINAL_WORDS = {"final", "ga", "release", "r"}
_INF = float("inf")


def _semver_ecosystem(ecosystem: str | None) -> bool:
    return ecosystem in ("npm", "Go", "crates.io", "RubyGems", "NuGet", "Packagist", "Hex", "Pub")


def _version_key(v: str, ecosystem: str | None = None):
    """Comparable key approximating PEP 440 (PyPI) and SemVer 2 (npm/Go/crates) ordering.

    ``1.0.dev1 < 1.0a1 < 1.0b2 < 1.0rc1 < 1.0 < 1.0.post1`` and ``2.0.0-rc.1 < 2.0.0 < 2.0.5``.
    Unrecognised trailing text sorts as a pre-release of the same release (conservative).
    """
    s = str(v or "").strip().lower()
    s = s.lstrip("v").split("+", 1)[0]  # strip leading v and build metadata
    s = re.sub(r"^\d+!", "", s)  # ignore PEP 440 epochs (rare)
    m = re.match(r"^(\d+(?:\.\d+)*)", s)
    if not m:
        return ((), (0, 0, s), -1, _INF)
    release = [int(x) for x in m.group(1).split(".")]
    while len(release) > 1 and release[-1] == 0:
        release.pop()
    rest = s[m.end() :]
    pre = None  # (phase, num, label)
    post = -1
    dev = _INF
    if rest.startswith("-") and _semver_ecosystem(ecosystem):
        # SemVer pre-release: any '-' suffix sorts below the release.
        label = rest[1:]
        parts = re.split(r"[.-]", label)
        head = re.match(r"^([a-z]+)?(\d*)$", parts[0] or "")
        word = head.group(1) if head else None
        num = int(head.group(2)) if head and head.group(2) else 0
        if num == 0 and len(parts) > 1 and parts[1].isdigit():
            num = int(parts[1])
        phase = _PRE_PHASE.get(word or "", 0) if word else 0
        if phase == -1:
            phase = 0
        return (tuple(release), (phase, num, label), -1, _INF)
    for tok_word, tok_num in re.findall(r"[._-]?([a-z]+)?[._-]?(\d+)?", rest):
        if not tok_word and not tok_num:
            continue
        n = int(tok_num) if tok_num else 0
        if tok_word in ("dev", "snapshot"):
            dev = n
        elif tok_word in ("post", "rev") or (tok_word is None or tok_word == "") and pre is None:
            post = n  # PEP 440 implicit post release: "1.0-1"
        elif tok_word in _FINAL_WORDS:
            continue
        elif tok_word in _PRE_PHASE:
            pre = (_PRE_PHASE[tok_word], n, "")
        else:
            pre = (0, n, tok_word)  # unknown label: treat as an early pre-release
    if pre is None:
        # a bare .devN (no pre/post) sorts before every pre-release of that release
        pre = (-1, 0, "") if dev != _INF and post == -1 else (3, 0, "")
    return (tuple(release), pre, post, dev)


def version_gt(a: str, b: str, ecosystem: str | None = None) -> bool:
    return _version_key(a, ecosystem) > _version_key(b, ecosystem)


# ------------------------------------------------------------------------------ fix versions
def _intervals(rng: dict):
    """Yield (introduced, fixed_or_None, last_affected_or_None) intervals for one OSV range."""
    intro = None
    for ev in rng.get("events", []) or []:
        if "introduced" in ev:
            if intro is not None:
                yield intro, None, None
            intro = ev["introduced"]
        elif "fixed" in ev:
            yield (intro if intro is not None else "0"), ev["fixed"], None
            intro = None
        elif "last_affected" in ev:
            yield (intro if intro is not None else "0"), None, ev["last_affected"]
            intro = None
        elif "limit" in ev:
            intro = None
    if intro is not None:
        yield intro, None, None


def fixed_version_for(vuln: dict, ecosystem: str, name: str, installed: str | None = None) -> str:
    """The version that fixes this advisory for the INSTALLED version ('' if none is published).

    With ``installed``: the ``fixed`` event closing the affected range that contains it (the range
    whose ``introduced <= installed < fixed``); if no range brackets it, the smallest ``fixed`` above
    the installed version. Never returns a version <= ``installed`` (that would be a downgrade).
    GIT (commit-hash) ranges are ignored. Without ``installed``: the lowest fixed version.
    """
    fixes: list[str] = []
    bracketing: list[str] = []
    for aff in vuln.get("affected", []) or []:
        pkg = aff.get("package", {}) or {}
        if pkg.get("ecosystem") != ecosystem or not _name_eq(ecosystem, pkg.get("name", ""), name):
            continue
        for rng in aff.get("ranges", []) or []:
            if (rng.get("type") or "").upper() == "GIT":
                continue
            for intro, fixed, _last in _intervals(rng):
                if not fixed:
                    continue
                fixes.append(fixed)
                if installed is not None:
                    lo_ok = intro in ("0", "") or not version_gt(intro, installed, ecosystem)
                    if lo_ok and version_gt(fixed, installed, ecosystem):
                        bracketing.append(fixed)
    if not fixes:
        return ""
    key = lambda x: _version_key(x, ecosystem)  # noqa: E731
    if installed is None:
        return sorted(set(fixes), key=key)[0]
    if bracketing:
        return sorted(set(bracketing), key=key)[0]
    above = [f for f in fixes if version_gt(f, installed, ecosystem)]
    return sorted(set(above), key=key)[0] if above else ""


def cvss_vector(vuln: dict) -> str:
    """Return the first CVSS v3 vector (preferred, we can score it) or else v4 vector ('' if none)."""
    vecs = []
    for sev in vuln.get("severity", []) or []:
        score = sev.get("score", "")
        if isinstance(score, str) and score.upper().startswith("CVSS:"):
            vecs.append(score)
    for v in vecs:
        if v.upper().startswith("CVSS:3"):
            return v
    return vecs[0] if vecs else ""


def cvss_version(vector: str) -> str:
    m = re.match(r"(?i)^CVSS:(\d+(?:\.\d+)?)/", vector or "")
    return m.group(1) if m else ""


def text_severity(vuln: dict) -> str:
    """Advisory text severity (GHSA 'database_specific.severity') when no CVSS vector exists."""
    ds = vuln.get("database_specific", {}) or {}
    return ds.get("severity", "") or ""


def affected_symbols(vuln: dict, ecosystem: str, name: str) -> list[str]:
    """Best-effort extraction of the vulnerable symbols/functions an advisory names, so a
    call-graph reachability check can ask 'is THAT symbol actually called?'. Empty when the
    advisory doesn't say (common for PyPI) — callers fall back to package-level reachability."""
    syms: list[str] = []
    for aff in vuln.get("affected", []) or []:
        pkg = aff.get("package", {}) or {}
        if pkg.get("ecosystem") != ecosystem or not _name_eq(ecosystem, pkg.get("name", ""), name):
            continue
        eco = aff.get("ecosystem_specific", {}) or {}
        for imp in eco.get("imports", []) or []:
            path = imp.get("path", "")
            for s in imp.get("symbols", []) or []:
                syms.append(f"{path}.{s}" if path else s)
            if path and not imp.get("symbols"):
                syms.append(path)
        ds = aff.get("database_specific", {}) or {}
        for s in ds.get("affected_functions") or ds.get("symbols") or []:
            if isinstance(s, str):
                syms.append(s)
    return list(dict.fromkeys(syms))


def cwe_ids(vuln: dict) -> list[str]:
    ds = vuln.get("database_specific", {}) or {}
    ids = ds.get("cwe_ids") or []
    return [c for c in ids if isinstance(c, str) and c.upper().startswith("CWE-")]


def advisory_ids(vuln: dict) -> list[str]:
    ids = [vuln.get("id", "")] + list(vuln.get("aliases", []) or [])
    # Surface CVE ids first (most recognisable), then the rest, de-duplicated.
    cves = [i for i in ids if i.startswith("CVE-")]
    rest = [i for i in ids if i and not i.startswith("CVE-")]
    seen, ordered = set(), []
    for i in cves + rest:
        if i not in seen:
            seen.add(i)
            ordered.append(i)
    return ordered


def unique_vuln_count(advisories: list[dict]) -> int:
    """Number of distinct vulnerabilities: advisories that alias each other (PYSEC/GHSA/CVE for the
    same flaw) count once."""
    parent: dict[str, str] = {}

    def find(x):
        while parent.setdefault(x, x) != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    roots = []
    for v in advisories:
        ids = [i for i in advisory_ids(v) if i]
        if not ids:
            continue
        for i in ids[1:]:
            parent[find(i)] = find(ids[0])
        roots.append(ids[0])
    return len({find(r) for r in roots})
