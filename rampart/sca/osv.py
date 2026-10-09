"""OSV.dev advisory client (stdlib urllib) with an injectable network seam.

OSV (https://osv.dev) is the open, aggregated vulnerability database for OSS. We query it per
package with the exact version and read back the advisories that affect it, extracting the fixed
version so a finding can recommend a concrete upgrade.

Two deliberate design choices:
  * The ``fetch`` callable is injectable so tests run fully offline and so the whole module stays
    graceful — any network error returns "no advisories", never an exception that breaks a scan.
  * Querying OSV sends package *names/versions* to an external service, so the engagement only does
    it when the operator opts in (``--sca-online``); offline, SCA still inventories dependencies.
"""

from __future__ import annotations

import json
import urllib.request

OSV_QUERY_URL = "https://api.osv.dev/v1/query"
_USER_AGENT = "rampart-sca/1.0 (+https://osv.dev)"


def http_fetch(url: str, payload: dict, timeout: float = 15.0) -> dict | None:
    """Default network fetch: POST JSON to OSV, return parsed JSON, or None on any failure."""
    try:
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=data,
            method="POST",
            headers={"Content-Type": "application/json", "User-Agent": _USER_AGENT},
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - fixed OSV host
            return json.loads(resp.read().decode("utf-8"))
    except Exception:  # noqa: BLE001 - SCA must degrade gracefully, never crash a scan
        return None


def query_package(ecosystem: str, name: str, version: str, fetch=None, timeout: float = 15.0) -> list[dict]:
    """Return the list of OSV advisory dicts affecting ``name@version`` (empty on miss/error).

    ``fetch`` is the network seam, called as ``fetch(url, payload, timeout) -> dict | None``.
    Tests inject their own; the default is :func:`http_fetch`.
    """
    fetch = fetch or http_fetch
    payload = {"version": version, "package": {"name": name, "ecosystem": ecosystem}}
    out = fetch(OSV_QUERY_URL, payload, timeout)
    if not isinstance(out, dict):
        return []
    vulns = out.get("vulns")
    return vulns if isinstance(vulns, list) else []


def fixed_version_for(vuln: dict, ecosystem: str, name: str) -> str:
    """Extract the lowest 'fixed' version OSV lists for this package in an advisory ('' if none)."""
    fixes = []
    for aff in vuln.get("affected", []) or []:
        pkg = aff.get("package", {}) or {}
        if pkg.get("ecosystem") != ecosystem or pkg.get("name") != name:
            continue
        for rng in aff.get("ranges", []) or []:
            for ev in rng.get("events", []) or []:
                if "fixed" in ev:
                    fixes.append(ev["fixed"])
    if not fixes:
        return ""
    # Lowest fixed version clears this advisory; sort by a best-effort version key.
    return sorted(set(fixes), key=_version_key)[0]


def _version_key(v: str):
    parts = []
    for chunk in str(v).lstrip("vV").replace("-", ".").split("."):
        parts.append((0, int(chunk)) if chunk.isdigit() else (1, chunk))
    return parts


def cvss_vector(vuln: dict) -> str:
    """Return the first CVSS v3/v4 vector string in the advisory's severity list ('' if none)."""
    for sev in vuln.get("severity", []) or []:
        score = sev.get("score", "")
        if isinstance(score, str) and score.upper().startswith("CVSS:"):
            return score
    return ""


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
        if pkg.get("ecosystem") != ecosystem or pkg.get("name") != name:
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
