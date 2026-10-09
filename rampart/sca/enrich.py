"""Exploit-intelligence enrichment for SCA findings: EPSS + CISA KEV + reachability → adjusted
priority. This turns a raw CVSS list into a *prioritized* one — the difference between "47 criticals"
and "the 2 that are actually exploited in the wild and reachable in your code."

  * EPSS (FIRST) — probability the CVE will be exploited in the next 30 days.
  * KEV (CISA Known Exploited Vulnerabilities) — confirmed exploited in the wild.
  * Reachability — does your first-party source actually import the vulnerable package? An advisory
    in a declared-but-never-imported (transitive/unused) dependency is far lower risk. This is
    honest *import-level* reachability, not a full call-graph; we say so.

All network calls are injectable seams and fully graceful (missing data just means "no signal").
"""

from __future__ import annotations

import json
import os
import re
import urllib.request

EPSS_URL = "https://api.first.org/data/v1/epss"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_UA = "rampart-sca/1.0"

# PyPI distribution name -> actual import name(s), where they differ. Default: the name itself.
_PY_IMPORT_ALIASES = {
    "pyyaml": ["yaml"],
    "beautifulsoup4": ["bs4"],
    "pillow": ["PIL"],
    "scikit-learn": ["sklearn"],
    "python-dateutil": ["dateutil"],
    "msgpack-python": ["msgpack"],
    "protobuf": ["google"],
    "opencv-python": ["cv2"],
    "attrs": ["attr"],
    "setuptools": ["setuptools", "pkg_resources"],
}


# --------------------------------------------------------------------------- EPSS
def fetch_epss(cves, fetch=None, timeout: float = 15.0) -> dict:
    """Return {cve: {"epss": float, "percentile": float}} for the given CVE ids (graceful: {})."""
    cves = [c for c in dict.fromkeys(cves) if c.startswith("CVE-")]
    if not cves:
        return {}
    fetch = fetch or _epss_http
    out: dict[str, dict] = {}
    for i in range(0, len(cves), 100):  # EPSS API accepts batches
        batch = cves[i : i + 100]
        data = fetch(f"{EPSS_URL}?cve={','.join(batch)}", timeout)
        if not isinstance(data, dict):
            continue
        for row in data.get("data", []) or []:
            cve = row.get("cve")
            if cve:
                try:
                    out[cve] = {
                        "epss": float(row.get("epss", 0)),
                        "percentile": float(row.get("percentile", 0)),
                    }
                except (TypeError, ValueError):
                    continue
    return out


def _epss_http(url: str, timeout: float = 15.0):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": _UA})
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - fixed FIRST host
            return json.loads(resp.read().decode("utf-8"))
    except Exception:  # noqa: BLE001
        return None


# --------------------------------------------------------------------------- KEV
def fetch_kev(fetch=None, timeout: float = 20.0) -> set:
    """Return the set of CVE ids in the CISA KEV catalog (graceful: empty set)."""
    fetch = fetch or _kev_http
    data = fetch(KEV_URL, timeout)
    if not isinstance(data, dict):
        return set()
    return {v.get("cveID") for v in data.get("vulnerabilities", []) or [] if v.get("cveID")}


def _kev_http(url: str, timeout: float = 20.0):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": _UA})
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - fixed CISA host
            return json.loads(resp.read().decode("utf-8"))
    except Exception:  # noqa: BLE001
        return None


# --------------------------------------------------------------------- reachability
_SKIP_DIRS = {".git", "__pycache__", "node_modules", ".venv", "venv", ".rampart", "dist", "build"}


def _py_import_names(pkg: str) -> list[str]:
    return _PY_IMPORT_ALIASES.get(pkg.lower(), [pkg.replace("-", "_").lower()])


def reachable(dep, repo_path: str, graph=None, affected_symbols=None):
    """Reachability of a dependency. For Python this is a **call-graph** analysis (is the package
    actually called, from a path reachable from an entrypoint, and — when the advisory names the
    vulnerable symbol — is *that symbol* on a live path?). For npm it is import-level. Returns a
    ``(bool_or_None, detail_dict)`` pair; ``detail`` is ``{}`` when nothing could be determined.

    bool: True (reachable / vulnerable symbol exercised), False (unimported / transitive / test-only /
    dead), None (no analysable source → unknown, assume reachable).
    """
    if not repo_path or not os.path.isdir(repo_path):
        return None, {}
    if dep.ecosystem == "PyPI":
        from .reachability import analyze_repo, reachability, tier_to_bool

        if graph is None:
            graph = analyze_repo(repo_path)
        if graph is None:
            return None, {}
        detail = reachability(graph, _py_import_names(dep.name), affected_symbols)
        return tier_to_bool(detail["tier"]), detail
    if dep.ecosystem == "npm":
        n = re.escape(dep.name)
        pats = [
            re.compile(rf"""require\(\s*['"]{n}(?:/|['"])"""),
            re.compile(rf"""from\s+['"]{n}(?:/|['"])"""),
            re.compile(rf"""import\s+['"]{n}(?:/|['"])"""),
        ]
        b = _scan_source(repo_path, (".js", ".ts", ".jsx", ".tsx", ".mjs"), pats)
        return b, ({"tier": "import-level"} if b is not None else {})
    return None, {}  # Go/Maven/RubyGems/crates — not statically analysed here


def _scan_source(repo_path: str, exts: tuple, patterns: list, max_files: int = 4000):
    """True if an import matches, False if source was scanned but no match, None if there is no
    first-party source of this type to analyse (so reachability is *unknown*, not 'unreachable')."""
    seen = 0
    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
        for fn in files:
            if not fn.endswith(exts):
                continue
            seen += 1
            if seen > max_files:
                return False
            try:
                with open(os.path.join(root, fn), encoding="utf-8", errors="ignore") as fh:
                    text = fh.read(400_000)
            except OSError:
                continue
            for line in text.splitlines():
                for p in patterns:
                    if p.search(line):
                        return True
    return False if seen else None


# ------------------------------------------------------------------- adjust priority
_SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
_RANK_SEV = {v: k for k, v in _SEV_RANK.items()}


def _cves_of(finding) -> list[str]:
    out = []
    for ref in finding.references:
        m = re.search(r"(CVE-\d{4}-\d+)", ref)
        if m:
            out.append(m.group(1))
    return list(dict.fromkeys(out))


_TIER_REASON = {
    "function-reachable": "the vulnerable symbol is called on a live (entrypoint-reachable) code path",
    "reachable": "the package is called on a live (entrypoint-reachable) code path",
    "imported-not-on-live-path": "used only in non-test code that is not reachable from an entrypoint (likely dead)",
    "test-only": "used only in test code",
    "imported-unused": "imported but never called (likely transitive/unused)",
    "unreachable": "not imported by first-party source (transitive/unused)",
    "import-level": "imported by first-party source (import-level)",
}


def adjust(finding, dep, epss_map: dict, kev_set: set, reach, reach_detail=None) -> None:
    """Fold EPSS/KEV/reachability into the finding: set exploit_intel, tags, and an ADJUSTED
    severity + priority (P0 critical-now … P3 lowest). Mutates the finding in place."""
    reach_detail = reach_detail or {}
    tier = reach_detail.get("tier")
    cves = _cves_of(finding)
    epss_vals = [epss_map[c]["epss"] for c in cves if c in epss_map]
    epss = max(epss_vals) if epss_vals else None
    percentile = max((epss_map[c]["percentile"] for c in cves if c in epss_map), default=None)
    kev = any(c in kev_set for c in cves)

    base_rank = _SEV_RANK.get(finding.severity, 2)
    adj_rank = base_rank
    reasons = []
    if kev:
        adj_rank = 4  # KEV = exploited in the wild => treat as critical
        reasons.append("in CISA KEV (actively exploited in the wild)")
    if epss is not None and epss >= 0.5:
        adj_rank = max(adj_rank, 3)
        reasons.append(f"high EPSS {epss:.0%} (likely to be exploited)")
    elif epss is not None and epss >= 0.1:
        reasons.append(f"moderate EPSS {epss:.0%}")
    if reach is False:
        # not reachable (unimported / transitive / test-only / dead). De-prioritise harder for the
        # clearly-irrelevant tiers than for a merely-import-level miss.
        drop = 2 if tier in ("unreachable", "imported-unused", "test-only") else 1
        adj_rank = max(0, adj_rank - drop)
        reasons.append(_TIER_REASON.get(tier, "not reachable from first-party source"))
    elif reach is True:
        if tier == "function-reachable":
            adj_rank = max(adj_rank, 3)  # vuln symbol actually exercised => never low
        reasons.append(_TIER_REASON.get(tier, "reachable from first-party source"))

    adjusted_severity = _RANK_SEV[adj_rank]
    # Priority P0..P3: KEV->P0; else by adjusted severity, nudged by reachability.
    if kev or adj_rank >= 4:
        priority = "P0"
    elif adj_rank == 3:
        priority = "P1"
    elif adj_rank == 2:
        priority = "P2"
    else:
        priority = "P3"

    finding.exploit_intel = {
        "epss": round(epss, 4) if epss is not None else None,
        "epss_percentile": round(percentile, 4) if percentile is not None else None,
        "kev": kev,
        "reachable": reach,
        "reachability_tier": tier,
        "reachable_symbols": reach_detail.get("reachable_symbols", []),
        "vulnerable_symbol_reachable": reach_detail.get("vulnerable_symbol_reachable"),
        "base_severity": finding.severity,
        "adjusted_severity": adjusted_severity,
        "priority": priority,
        "rationale": "; ".join(reasons) if reasons else "no additional exploit signal",
    }
    # Tags for quick filtering.
    if kev and "kev" not in finding.tags:
        finding.tags.append("kev")
    if epss is not None:
        finding.tags.append(f"epss:{epss:.0%}")
    if tier:
        finding.tags.append(f"reach:{tier}")
    if reach_detail.get("vulnerable_symbol_reachable") is True:
        finding.tags.append("vuln-symbol-reachable")
    finding.tags.append(f"priority:{priority}")

    # Reflect the adjusted severity on the finding (base CVSS stays in finding.cvss.base_score).
    if adjusted_severity != finding.severity:
        finding.severity = adjusted_severity
        finding.severity_source = "adjusted(cvss+epss+kev+reachability)"
    # Surface the intel in the description + remediation so reports show it without new plumbing.
    intel = finding.exploit_intel
    bits = []
    if intel["kev"]:
        bits.append("**CISA KEV: actively exploited**")
    if intel["epss"] is not None:
        bits.append(
            f"EPSS {intel['epss']:.0%} (pctl {intel['epss_percentile']:.0%})"
            if intel["epss_percentile"] is not None
            else f"EPSS {intel['epss']:.0%}"
        )
    if tier == "function-reachable":
        bits.append("vulnerable symbol reachable (call-graph)")
    elif reach is True:
        bits.append("reachable (call-graph)")
    elif reach is False:
        bits.append(f"not reachable ({tier})")
    if bits:
        finding.description += f"  [Exploit intel: {', '.join(bits)} → priority {priority}]"


def enrich_findings(
    findings,
    deps_by_key: dict,
    repo_path: str = "",
    fetch_epss_fn=None,
    fetch_kev_fn=None,
    online: bool = False,
    affected_by_key: dict = None,
) -> list:
    """Enrich SCA findings in place with EPSS/KEV + call-graph reachability, re-sorted by priority.

    Reachability is always computed (it's local & free) via a Python call graph built ONCE for the
    repo. EPSS/KEV are fetched only when ``online`` is set or an explicit fetch seam is provided — so
    callers that don't opt into the extra external services (or tests) never hit the network and
    severities stay deterministic.
    """
    if not findings:
        return findings
    affected_by_key = affected_by_key or {}
    all_cves = []
    for f in findings:
        all_cves.extend(_cves_of(f))
    want_net = online or fetch_epss_fn is not None or fetch_kev_fn is not None
    epss_map = fetch_epss(all_cves, fetch=fetch_epss_fn) if want_net else {}
    kev_set = fetch_kev(fetch=fetch_kev_fn) if want_net else set()
    # Build the Python call graph once and reuse it for every PyPI dependency.
    graph = None
    if repo_path and os.path.isdir(repo_path):
        try:
            from .reachability import analyze_repo

            graph = analyze_repo(repo_path)
        except Exception:  # noqa: BLE001 - reachability is best-effort; never break a scan
            graph = None
    reach_cache: dict = {}
    for f in findings:
        dep = deps_by_key.get(f.dedupe_key)
        if dep is not None:
            affected = affected_by_key.get(f.dedupe_key) or []
            ckey = (dep.key(), tuple(affected))
            if ckey not in reach_cache:
                try:
                    reach_cache[ckey] = reachable(dep, repo_path, graph=graph, affected_symbols=affected)
                except Exception:  # noqa: BLE001
                    reach_cache[ckey] = (None, {})
            r, detail = reach_cache[ckey]
        else:
            r, detail = None, {}
        adjust(f, dep, epss_map, kev_set, r, reach_detail=detail)
    _pr = {"P0": 0, "P1": 1, "P2": 2, "P3": 3}
    findings.sort(
        key=lambda f: (
            _pr.get(f.exploit_intel.get("priority", "P3"), 3),
            -_SEV_RANK.get(f.severity, 0),
            f.title,
        )
    )
    return findings
