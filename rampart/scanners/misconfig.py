"""Additional safe, deterministic misconfiguration checks (A05/A02 — Security Misconfiguration).

Like the security-headers check, these are Tier-0 read-only observations whose oracle is the
observation itself, re-confirmed on a second request, so they can carry ``confidence=confirmed``
honestly without an LLM. All are GET-observable (no state change).
"""
from __future__ import annotations

import re

from ..schemas.finding import Finding, Reproduction, State, Remediation, Verification
from ..util import now_iso

_VERSION_RE = re.compile(r"\d+\.\d+")


def _headers_ci(response) -> dict:
    return {str(k).lower(): v for k, v in (getattr(response, "headers", {}) or {}).items()}


def _confirmed_finding(engagement_id, application, target_url, *, title, vuln_class, severity,
                       cwe, owasp, description, impact, root_cause, remediation, references,
                       compliance, tags, checks, path="/") -> Finding:
    f = Finding(
        engagement_id=engagement_id, title=title, vuln_class=vuln_class, severity=severity,
        confidence="confirmed", state=State.VALIDATED, cwe=cwe, owasp=owasp,
        asset={"type": "web", "application": application, "environment": "authorized", "target": target_url},
        endpoint={"method": "GET", "url": f"{target_url}{path}", "auth_required": False},
        description=description, impact=impact, root_cause=root_cause, remediation=remediation,
        references=references, compliance_control_refs=compliance, tags=tags,
        reproduction=Reproduction(prerequisites=["None (unauthenticated GET)"],
                                  steps=[f"GET {path}", "Observe the header(s) on two requests"],
                                  deterministic=True),
        verification=Verification(method="passive-header-inspection", validated=True,
                                  validated_at=now_iso(), validator="misconfig-oracle",
                                  independent_reproduction=True, reproductions=2,
                                  false_positive_checks=checks, confidence_score=0.98),
        dedupe_key=f"{application}:GET:{path}:{cwe[0]}")
    f.assert_consistent()
    return f


def misconfig_checks(runner, appmodel, target_url, application="target", sessions=None) -> list[Finding]:
    first = runner.get("/", session=None, payload_class="benign-read",
                       rationale="passive check: inspect CORS/server headers", summary="misconfig")
    if not first.executed:
        return []
    second = runner.get("/", session=None, payload_class="benign-read",
                        rationale="reproduction: re-inspect headers", summary="misconfig repro")
    h1, h2 = _headers_ci(first.response), _headers_ci(second.response)
    findings: list[Finding] = []

    # --- CORS misconfiguration: ACAO:* together with ACAC:true (CWE-942) ---
    def _cors_bad(h):
        return h.get("access-control-allow-origin") == "*" and \
               str(h.get("access-control-allow-credentials", "")).lower() == "true"
    if _cors_bad(h1) and _cors_bad(h2):
        findings.append(_confirmed_finding(
            runner.engagement_id, application, target_url,
            title="Overly permissive CORS policy (wildcard origin with credentials)",
            vuln_class="security-misconfiguration", severity="high", cwe=["CWE-942"],
            owasp={"web_2025": ["A02:2025-Security Misconfiguration"]},
            description=("The API returns Access-Control-Allow-Origin: * together with "
                         "Access-Control-Allow-Credentials: true, which browsers treat as invalid "
                         "but mis-implementations expose; any origin can read authenticated responses."),
            impact="Any website can issue credentialed cross-origin requests and read the responses.",
            root_cause="CORS is configured with a wildcard origin while also allowing credentials.",
            remediation=Remediation(
                summary="Reflect only an explicit allow-list of trusted origins; never pair '*' with credentials.",
                type="config",
                guidance=("Set Access-Control-Allow-Origin to a specific, validated origin (not '*') "
                          "when Access-Control-Allow-Credentials is true, and omit credentials for "
                          "public endpoints (CWE-942)."),
                effort="low"),
            references=["https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny"],
            compliance=["SOC2:CC6.1", "ISO27001:A.8.26"], tags=["cors", "misconfiguration"],
            checks=["ACAO='*' and ACAC='true' observed on 2/2 requests"]))

    # --- Server/software version disclosure (CWE-200) ---
    server = h1.get("server", "")
    if server and _VERSION_RE.search(server) and _VERSION_RE.search(h2.get("server", "")):
        findings.append(_confirmed_finding(
            runner.engagement_id, application, target_url,
            title=f"Server software/version disclosure in Server header ({server})",
            vuln_class="security-misconfiguration", severity="low", cwe=["CWE-200"],
            owasp={"web_2025": ["A02:2025-Security Misconfiguration"]},
            description=f"The Server response header discloses software and version: '{server}'.",
            impact="Aids attackers in fingerprinting the stack and matching it to known CVEs.",
            root_cause="The server advertises its software name and version in responses.",
            remediation=Remediation(
                summary="Suppress or genericise the Server header.",
                type="config",
                guidance="Remove the version from the Server header at the app or reverse proxy (CWE-200).",
                effort="low"),
            references=["https://owasp.org/www-project-secure-headers/"],
            compliance=["SOC2:CC7.1", "ISO27001:A.8.9"], tags=["version-disclosure", "misconfiguration"],
            checks=[f"Server header '{server}' carries a version on 2/2 requests"]))

    return findings
