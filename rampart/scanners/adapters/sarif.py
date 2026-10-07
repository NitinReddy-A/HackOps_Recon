"""SARIF 2.1.0 -> Rampart Finding normaliser.

SARIF is the common denominator for Semgrep, Trivy, Nuclei (-sarif) and many others, so one
parser covers most adapters. Normalised findings are UNVALIDATED (external leads), consistent
with the base adapter contract — only Rampart's oracles confirm.
"""
from __future__ import annotations

import re

_LEVEL_SEV = {"error": "high", "warning": "medium", "note": "low", "none": "info"}
_CWE_RE = re.compile(r"CWE[-_ ]?(\d+)", re.IGNORECASE)


def _rule_index(run: dict) -> dict:
    rules = {}
    driver = (run.get("tool") or {}).get("driver") or {}
    for r in driver.get("rules") or []:
        rules[r.get("id")] = r
    for ext in driver.get("extensions") or []:
        for r in ext.get("rules") or []:
            rules[r.get("id")] = r
    return rules


def _cwes_from(rule: dict, text: str) -> list[str]:
    found = set()
    blob = text or ""
    if rule:
        props = rule.get("properties") or {}
        for key in ("cwe", "cwes", "tags"):
            val = props.get(key)
            if isinstance(val, list):
                blob += " " + " ".join(str(v) for v in val)
            elif val:
                blob += " " + str(val)
        blob += " " + (rule.get("fullDescription", {}) or {}).get("text", "")
    return [f"CWE-{m}" for m in dict.fromkeys(_CWE_RE.findall(blob))]


def sarif_to_findings(adapter, sarif: dict, application: str, target_url: str) -> list:
    out = []
    for run in sarif.get("runs") or []:
        rules = _rule_index(run)
        for res in run.get("results") or []:
            rule = rules.get(res.get("ruleId"), {}) or {}
            level = res.get("level") or rule.get("defaultConfiguration", {}).get("level") or "warning"
            severity = _LEVEL_SEV.get(level, "medium")
            msg = (res.get("message") or {}).get("text", "") or rule.get("shortDescription", {}).get("text", "")
            title = (rule.get("name") or res.get("ruleId") or "finding")
            help_uri = rule.get("helpUri", "")
            # physical location (file:line or url)
            loc_uri, file_uri, start_line = "", "", 0
            for loc in res.get("locations") or []:
                art = ((loc.get("physicalLocation") or {}).get("artifactLocation") or {})
                if art.get("uri"):
                    region = (loc.get("physicalLocation") or {}).get("region") or {}
                    line = region.get("startLine")
                    file_uri = art["uri"]
                    start_line = int(line) if line else 0
                    loc_uri = file_uri + (f":{line}" if line else "")
                    break
            cwes = _cwes_from(rule, f"{res.get('ruleId','')} {title} {msg}")
            f = adapter._external_finding(
                engagement_id="", application=application, target_url=target_url,
                title=f"{title}: {msg[:120]}" if msg else str(title),
                severity=severity, vuln_class=str(res.get("ruleId") or title),
                cwe=cwes, description=msg or str(title),
                endpoint_url=loc_uri or target_url, help_uri=help_uri,
                rule_id=str(res.get("ruleId") or title))
            # Source-side tools (SAST/SCA): record the source location so SAST<->DAST correlation works.
            if file_uri and "://" not in file_uri:
                from ...schemas.finding import AffectedCode
                f.affected_code = AffectedCode(detected_by=adapter.name, repo="", file=file_uri,
                                               start_line=start_line, end_line=start_line)
                if "sast" not in f.tags and adapter.category in ("sast", "sca"):
                    f.tags.append("sast")
            out.append(f)
    return out
