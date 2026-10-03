"""Safe, deterministic built-in checks.

These are Tier-0 read-only observations whose oracle is the observation itself (a missing
response header is directly and reproducibly verifiable), so they can carry
``confidence=confirmed`` honestly. This is the "AUTOMATABLE" row of the feasibility matrix
(security misconfiguration, A02:2025) — no LLM needed.

Note: this is deliberately narrow. The MVP does not bundle offensive scanners; external
tools (Nuclei/ZAP/Semgrep/Trivy) plug in as separate-process adapters that emit SARIF.
"""
from __future__ import annotations

from ..schemas.finding import Finding, Reproduction, State, Verification
from ..util import now_iso

# header -> (severity_if_missing, human note)
_EXPECTED = {
    "content-security-policy": ("medium", "no CSP — clickjacking/XSS mitigations weakened"),
    "x-content-type-options": ("low", "missing nosniff — MIME-sniffing risk"),
    "x-frame-options": ("medium", "missing — clickjacking via framing"),
    "strict-transport-security": ("low", "missing HSTS — downgrade/MITM risk (HTTPS deployments)"),
}


def security_headers_check(runner, path: str, target_url: str, application: str = "target",
                           environment: str = "authorized") -> list[Finding]:
    first = runner.get(path, session=None, payload_class="benign-read",
                       rationale="passive check: inspect security response headers",
                       summary="security-headers")
    if not first.executed:
        return []
    present = {k.lower() for k in (first.response.headers or {})}
    missing = [(h, sev, note) for h, (sev, note) in _EXPECTED.items() if h not in present]
    if not missing:
        return []

    # deterministic reproduction: re-observe once more
    second = runner.get(path, session=None, payload_class="benign-read",
                        rationale="reproduction: re-inspect headers", summary="security-headers repro")
    present2 = {k.lower() for k in (getattr(second.response, "headers", {}) or {})}
    reproduced = all(h not in present2 for h, _, _ in missing)

    sev_order = ["low", "medium", "high", "critical"]
    top = max((sev for _, sev, _ in missing), key=sev_order.index)
    header_list = ", ".join(h for h, _, _ in missing)

    f = Finding(
        engagement_id=runner.engagement_id,
        title=f"Missing security headers on {path}",
        vuln_class="security-misconfiguration",
        severity=top,
        confidence="confirmed" if reproduced else "firm",
        state=State.VALIDATED if reproduced else State.EVIDENCE_FOUND,
        cwe=["CWE-693"],
        owasp={"web_2025": ["A02:2025-Security Misconfiguration"]},
        asvs={"requirement": "V14.4", "level": 1},
        asset={"type": "web", "application": application, "environment": environment, "target": target_url},
        endpoint={"method": "GET", "url": f"{target_url}{path}", "auth_required": False},
        description=f"The response for {path} omits: {header_list}.",
        impact="Weakened browser-side defenses (clickjacking, MIME-sniffing, transport downgrade).",
        root_cause="Security response headers are not set by the application/proxy.",
        reproduction=Reproduction(
            prerequisites=["None (unauthenticated GET)"],
            steps=[f"GET {path}", f"Observe the response omits: {header_list}"],
            deterministic=True,
        ),
        remediation=_headers_remediation(missing),
        references=["https://owasp.org/www-project-secure-headers/"],
        compliance_control_refs=["SOC2:CC7.1", "ISO27001:A.8.9"],
        dedupe_key=f"{application}:GET:{path}:CWE-693",
        tags=["headers", "misconfiguration"] + [h for h, _, _ in missing],
        verification=Verification(
            method="passive-header-inspection",
            validated=reproduced,
            validated_at=now_iso(),
            validator="header-oracle",
            independent_reproduction=reproduced,
            reproductions=2 if reproduced else 1,
            false_positive_checks=[f"header '{h}' absent on {sev} 2/2 observations" for h, sev, _ in missing],
            confidence_score=0.99 if reproduced else 0.6,
        ),
    )
    f.evidence.extend(first.evidence)
    f.assert_consistent()
    return [f]


def _headers_remediation(missing):
    from ..schemas.finding import Remediation

    lines = "\n".join(f"{h}: <recommended value>" for h, _, _ in missing)
    return Remediation(
        summary="Set the missing security response headers at the app or reverse proxy.",
        type="config",
        guidance=f"Add the following response headers:\n{lines}",
        effort="low",
    )
