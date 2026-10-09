"""Full Software Composition Analysis: match pinned dependencies against OSV advisories and
emit actionable, security-only remediation (concrete upgrade targets).

Pipeline: collect exact ``name@version`` deps from every recognised manifest -> batch-query OSV
(``/v1/querybatch``, falling back to per-package ``/v1/query``) -> fold each package's advisories
into ONE finding that lists the CVE/GHSA ids, the worst CVSS severity, and the minimum safe upgrade
that clears them. Findings are static-tier (``validated=False``) — an advisory is strong external
evidence, not an oracle-confirmed exploit, so SCA sits below oracle-``confirmed`` findings but
drives "what to bump" remediation directly.
"""

from __future__ import annotations

import logging

from ..schemas.finding import CVSS, AffectedCode, Finding, Remediation, Reproduction, State, Verification
from ..util import now_iso
from . import cvss as _cvss
from . import osv as _osv
from .parsers import collect_dependencies

_log = logging.getLogger(__name__)

# OSV ecosystem -> the package coordinate shown in remediation (e.g. "pip install", "npm i").
_INSTALL_HINT = {
    "PyPI": "pip install '{name}>={fixed}'",
    "npm": "npm install {name}@{fixed}",
    "Go": "go get {name}@{fixed}",
    "Maven": "set <version>{fixed}</version> for {name}",
    "RubyGems": "bundle update {name} --to {fixed}",
    "crates.io": "cargo update -p {name} --precise {fixed}",
}

# Notes from the most recent scan_sca() call (package cap reached, batch fallback, …).
last_scan_notes: list[str] = []


def _worst(advisories: list[dict]) -> tuple[str, float, str, str]:
    """Return (severity, score, source, vector) for the most severe advisory in the set."""
    best_sev, best_score, best_src, best_vec = "info", 0.0, "none", ""
    for v in advisories:
        vec = _osv.cvss_vector(v)
        score = _cvss.base_score(vec) if vec else None
        if score is not None:
            sev, src = _cvss.severity_band(score), "cvss"
        else:
            sev, score = _cvss.from_text(_osv.text_severity(v))
            src, vec = "text", ""
        if score >= best_score:
            best_sev, best_score, best_src, best_vec = sev, score, src, vec
    return best_sev, round(best_score, 1), best_src, best_vec


def _best_upgrade(advisories: list[dict], ecosystem: str, name: str, installed: str | None = None) -> str:
    """The highest per-advisory fix above the installed version — upgrading there clears every
    advisory that has a fix. Never suggests a version <= the installed one (no downgrades)."""
    fixes = [f for v in advisories if (f := _osv.fixed_version_for(v, ecosystem, name, installed))]
    if installed:
        fixes = [f for f in fixes if _osv.version_gt(f, installed, ecosystem)]
    if not fixes:
        return ""
    return sorted(set(fixes), key=lambda x: _osv._version_key(x, ecosystem))[-1]


def _unfixed_count(advisories: list[dict], ecosystem: str, name: str, installed: str) -> int:
    return sum(1 for v in advisories if not _osv.fixed_version_for(v, ecosystem, name, installed))


def _finding_for(dep, advisories: list[dict], engagement_id: str) -> Finding:
    ids = []
    cwes = []
    summaries = []
    for v in advisories:
        ids.extend(_osv.advisory_ids(v))
        cwes.extend(_osv.cwe_ids(v))
        s = (v.get("summary") or "").strip()
        if s:
            summaries.append(s)
    ids = list(dict.fromkeys(ids))  # de-dup, keep order (CVEs first)
    cves = [i for i in ids if i.startswith("CVE-")]
    n_vulns = _osv.unique_vuln_count(advisories) or len(advisories)
    cwes = list(dict.fromkeys(cwes)) or ["CWE-1395"]  # dependency on vulnerable component
    severity, score, src, vector = _worst(advisories)
    fixed = _best_upgrade(advisories, dep.ecosystem, dep.name, dep.version)
    unfixed = _unfixed_count(advisories, dep.ecosystem, dep.name, dep.version) if fixed else 0

    id_list = ", ".join(ids[:12]) + (" …" if len(ids) > 12 else "")
    headline = summaries[0] if summaries else "known vulnerability"
    if fixed:
        shown = fixed
        if dep.ecosystem == "Go" and not shown.startswith("v"):
            shown = "v" + shown  # Go module versions are v-prefixed
        hint = _INSTALL_HINT.get(dep.ecosystem, "upgrade {name} to {fixed}").format(
            name=dep.name, fixed=shown
        )
        clears = (
            f"clears {n_vulns} advisory/ies" if not unfixed else f"{unfixed} advisory/ies have no fix yet"
        )
        remediation = Remediation(
            summary=f"Upgrade {dep.name} from {dep.version} to >= {shown} ({clears}).",
            type="dependency_upgrade",
            guidance=f"{hint}. Then re-run the build and test suite to confirm no breaking change.",
            effort="low",
        )
    else:
        remediation = Remediation(
            summary=f"No fixed version published for {dep.name} {dep.version}; mitigate or replace the dependency.",
            type="dependency_upgrade",
            guidance=(
                "No upstream fix is listed. Consider removing/replacing the package, applying a "
                "vendor patch, or constraining its exposure until an advisory fix ships."
            ),
            effort="medium",
        )

    upgrade_note = f" Fixed in {fixed}." if fixed else " No fixed version published."
    description = (
        f"{dep.name}@{dep.version} ({dep.ecosystem}) is affected by {n_vulns} known "
        f"advisory/ies: {id_list}. {headline}.{upgrade_note}"
    )

    return Finding(
        engagement_id=engagement_id,
        title=f"Vulnerable dependency: {dep.name} {dep.version} ({n_vulns} advisory/ies, {severity})",
        vuln_class="sca-known-vulnerability",
        severity=severity,
        severity_source=src,
        confidence="firm",
        state=State.EVIDENCE_FOUND,
        cwe=cwes,
        owasp={"web_2021": ["A06:2021-Vulnerable and Outdated Components"]},
        cvss=CVSS(version=_osv.cvss_version(vector), base_score=score, vector=vector, severity=severity),
        asset={
            "type": "dependency",
            "application": "",
            "environment": "authorized",
            "target": f"{dep.ecosystem}:{dep.name}",
        },
        description=description,
        impact="A dependency with a published advisory can expose the application to the described "
        "vulnerability class without any flaw in first-party code.",
        root_cause=f"Project depends on {dep.name} {dep.version}, a version with known advisories.",
        affected_code=AffectedCode(
            detected_by="rampart-sca",
            repo="",
            file=dep.manifest,
            start_line=dep.line,
            end_line=dep.line,
            snippet=f"{dep.name} == {dep.version}",
        ),
        reproduction=Reproduction(
            prerequisites=["Source/manifest access"],
            steps=[f"Inspect {dep.manifest}", f"Query OSV for {dep.name}@{dep.version}"],
            deterministic=True,
        ),
        remediation=remediation,
        references=[f"https://osv.dev/vulnerability/{i}" for i in ids[:8]]
        + ["https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/"],
        compliance_control_refs=["SOC2:CC7.1", "ISO27001:A.8.8"],
        dedupe_key=f"sca:{dep.ecosystem}:{dep.name}:{dep.version}",
        tags=["sca", "dependencies", "white-box", "cve"],
        # The FULL id/CVE lists (references are truncated for display) so KEV/EPSS see every CVE.
        exploit_intel={"advisory_ids": ids, "cves": cves},
        verification=Verification(
            method="osv-advisory",
            validated=False,
            validated_at=now_iso(),
            validator="sca-osv",
            reproductions=0,
            false_positive_checks=[
                f"{n_vulns} OSV advisory/ies ({len(ids)} ids incl. aliases) matched {dep.name}@{dep.version}",
                "advisory-confirmed, not oracle-exploited",
            ],
            confidence_score=0.6,
        ),
    )


def _query_all(deps, fetch, timeout) -> list[list[dict]]:
    """Advisories for each dep: one OSV querybatch round (+ detail fetches), falling back to the
    per-package endpoint when the batch API is unavailable through this fetch seam."""
    batch = _osv.query_batch([(d.ecosystem, d.name, d.version) for d in deps], fetch=fetch, timeout=timeout)
    if batch is not None:
        return batch
    if fetch is None or fetch is _osv.http_fetch:
        # Real OSV endpoint failed (network down / API error): don't retry N packages one by one.
        note = "OSV querybatch request failed; dependency advisories could not be checked"
        last_scan_notes.append(note)
        _log.warning(note)
        return [[] for _ in deps]
    return [_osv.query_package(d.ecosystem, d.name, d.version, fetch=fetch, timeout=timeout) for d in deps]


def scan_sca(
    repo_path: str,
    engagement_id: str = "",
    online: bool = False,
    fetch=None,
    max_packages: int = 20000,
    timeout: float = 15.0,
    enrich: bool = True,
    intel_online: bool = False,
    fetch_epss_fn=None,
    fetch_kev_fn=None,
) -> list[Finding]:
    """Full SCA. Parses manifests and, when ``online`` (operator opt-in), matches each pinned
    dependency against OSV and emits one upgrade-focused finding per vulnerable package, then
    enriches each with EPSS + CISA KEV + import-level reachability and an adjusted P0–P3 priority.

    Offline (``online=False``) it returns ``[]`` here — the dependency *inventory* (unpinned deps)
    is handled separately by ``sast.secrets.scan_dependencies`` so SCA never phones home unasked.
    Coverage limits (e.g. ``max_packages``) are recorded in :data:`last_scan_notes` and logged.
    """
    last_scan_notes.clear()
    deps = collect_dependencies(repo_path)
    if not deps or not online:
        return []
    if len(deps) > max_packages:
        note = (
            f"SCA package cap reached: matched the first {max_packages} of {len(deps)} pinned "
            "dependencies against OSV; the rest were not checked"
        )
        last_scan_notes.append(note)
        _log.warning(note)
        deps = deps[:max_packages]
    findings: list[Finding] = []
    deps_by_key: dict = {}
    affected_by_key: dict = {}
    for dep, advisories in zip(deps, _query_all(deps, fetch, timeout), strict=True):
        if advisories:
            f = _finding_for(dep, advisories, engagement_id)
            f.assert_consistent()
            findings.append(f)
            deps_by_key[f.dedupe_key] = dep
            syms = []
            for v in advisories:
                syms.extend(_osv.affected_symbols(v, dep.ecosystem, dep.name))
            affected_by_key[f.dedupe_key] = list(dict.fromkeys(syms))
    if enrich and findings:
        from .enrich import enrich_findings

        enrich_findings(
            findings,
            deps_by_key,
            repo_path=repo_path,
            online=intel_online,
            fetch_epss_fn=fetch_epss_fn,
            fetch_kev_fn=fetch_kev_fn,
            affected_by_key=affected_by_key,
            all_deps=deps,
        )
    else:
        _sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        findings.sort(key=lambda f: (_sev_rank.get(f.severity, 5), f.title))
    return findings
