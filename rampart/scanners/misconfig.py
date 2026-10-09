"""Additional safe, deterministic misconfiguration checks (A05/A02 — Security Misconfiguration).

Like the security-headers check, these are Tier-0 read-only observations whose oracle is the
observation itself, re-confirmed on a second request, so they can carry ``confidence=confirmed``
honestly without an LLM. All are GET-observable (no state change).
"""

from __future__ import annotations

import re

from ..schemas.finding import Finding, Remediation, Reproduction, State, Verification
from ..util import now_iso

_VERSION_RE = re.compile(r"\d+\.\d+")
# Headers that reveal an intermediary (proxy/CDN/cache) — the precondition for request smuggling
# and cache poisoning. We NEVER actively test smuggling (a desync poisons a socket/cache shared
# with real users); we only surface the exposure as a human-review indicator.
_PROXY_HEADER_HINTS = (
    "via",
    "x-cache",
    "x-served-by",
    "cf-ray",
    "x-varnish",
    "x-proxy-id",
    "x-forwarded-server",
    "fastly-",
    "x-amz-cf-",
    "x-envoy-",
)


def proxy_indicators(headers_ci: dict) -> list:
    hits = []
    for k in headers_ci:
        if any(k == h or k.startswith(h) for h in _PROXY_HEADER_HINTS):
            hits.append(k)
    return sorted(hits)


def _headers_ci(response) -> dict:
    return {str(k).lower(): v for k, v in (getattr(response, "headers", {}) or {}).items()}


def _confirmed_finding(
    engagement_id,
    application,
    target_url,
    *,
    title,
    vuln_class,
    severity,
    cwe,
    owasp,
    description,
    impact,
    root_cause,
    remediation,
    references,
    compliance,
    tags,
    checks,
    path="/",
) -> Finding:
    f = Finding(
        engagement_id=engagement_id,
        title=title,
        vuln_class=vuln_class,
        severity=severity,
        confidence="confirmed",
        state=State.VALIDATED,
        cwe=cwe,
        owasp=owasp,
        asset={"type": "web", "application": application, "environment": "authorized", "target": target_url},
        endpoint={"method": "GET", "url": f"{target_url}{path}", "auth_required": False},
        description=description,
        impact=impact,
        root_cause=root_cause,
        remediation=remediation,
        references=references,
        compliance_control_refs=compliance,
        tags=tags,
        reproduction=Reproduction(
            prerequisites=["None (unauthenticated GET)"],
            steps=[f"GET {path}", "Observe the header(s) on two requests"],
            deterministic=True,
        ),
        verification=Verification(
            method="passive-header-inspection",
            validated=True,
            validated_at=now_iso(),
            validator="misconfig-oracle",
            independent_reproduction=True,
            reproductions=2,
            false_positive_checks=checks,
            confidence_score=0.98,
        ),
        dedupe_key=f"{application}:GET:{path}:{cwe[0]}",
    )
    f.assert_consistent()
    return f


# Curated sensitive paths with a CONTENT signature (not bare-200) to keep false positives ~zero.
_SENSITIVE_PATHS = [
    ("/.env", "high", re.compile(r"(?mi)^[A-Z0-9_]{2,}\s*=|API_KEY|SECRET|PASSWORD|DB_")),
    ("/.git/config", "high", re.compile(r"\[core\]|repositoryformatversion|\[remote")),
    ("/backup.sql", "high", re.compile(r"(?i)INSERT\s+INTO|CREATE\s+TABLE|dump|DROP\s+TABLE")),
    ("/config.json", "medium", re.compile(r"(?i)\"(password|secret|api[_-]?key|token)\"\s*:")),
    ("/.aws/credentials", "high", re.compile(r"(?i)aws_secret_access_key|aws_access_key_id")),
    ("/wp-config.php", "high", re.compile(r"(?i)DB_PASSWORD|DB_NAME|wp-settings")),
    ("/actuator/env", "medium", re.compile(r"(?i)\"propertySources\"|activeProfiles|spring")),
    ("/server-status", "low", re.compile(r"(?i)Apache Server Status|Scoreboard")),
]


def sensitive_files_check(runner, target_url, application="target") -> list[Finding]:
    """Probe well-known sensitive files; confirm by CONTENT signature on two observations."""
    findings: list[Finding] = []
    for path, sev, sig in _SENSITIVE_PATHS:
        r1 = runner.get(
            path,
            session=None,
            payload_class="benign-read",
            rationale="probe for exposed sensitive file",
            summary=f"sensitive {path}",
        )
        if not r1.executed or r1.status != 200 or not sig.search(r1.body or ""):
            continue
        r2 = runner.get(
            path,
            session=None,
            payload_class="benign-read",
            rationale="reproduction",
            summary=f"sensitive {path} repro",
        )
        if not (r2.executed and r2.status == 200 and sig.search(r2.body or "")):
            continue
        findings.append(
            _confirmed_finding(
                runner.engagement_id,
                application,
                target_url,
                title=f"Exposed sensitive file: {path}",
                vuln_class="sensitive-file-exposure",
                severity=sev,
                cwe=["CWE-538"],
                owasp={"web_2025": ["A02:2025-Security Misconfiguration"]},
                description=f"{path} is web-accessible and returns sensitive content (signature matched).",
                impact="Leaks secrets / source / credentials / internal config to anyone on the internet.",
                root_cause="A sensitive file is served by the web server instead of being blocked.",
                remediation=Remediation(
                    summary=f"Block web access to {path} (and remove it from the web root).",
                    type="config",
                    guidance=f"Deny {path} at the web server/CDN, move secrets "
                    "out of the web root, and rotate any exposed credentials (CWE-538).",
                    effort="low",
                ),
                references=["https://owasp.org/www-project-web-security-testing-guide/"],
                compliance=["SOC2:CC6.1", "ISO27001:A.8.9"],
                tags=["sensitive-file", "exposure"],
                checks=[f"{path} returned 200 with a content signature on 2/2 requests"],
                path=path,
            )
        )
    return findings


def misconfig_checks(runner, appmodel, target_url, application="target", sessions=None) -> list[Finding]:
    first = runner.get(
        "/",
        session=None,
        payload_class="benign-read",
        rationale="passive check: inspect CORS/server headers",
        summary="misconfig",
    )
    if not first.executed:
        return []
    second = runner.get(
        "/",
        session=None,
        payload_class="benign-read",
        rationale="reproduction: re-inspect headers",
        summary="misconfig repro",
    )
    h1, h2 = _headers_ci(first.response), _headers_ci(second.response)
    findings: list[Finding] = []

    # --- CORS misconfiguration: ACAO:* together with ACAC:true (CWE-942) ---
    def _cors_bad(h):
        return (
            h.get("access-control-allow-origin") == "*"
            and str(h.get("access-control-allow-credentials", "")).lower() == "true"
        )

    if _cors_bad(h1) and _cors_bad(h2):
        findings.append(
            _confirmed_finding(
                runner.engagement_id,
                application,
                target_url,
                title="Overly permissive CORS policy (wildcard origin with credentials)",
                vuln_class="security-misconfiguration",
                severity="high",
                cwe=["CWE-942"],
                owasp={"web_2025": ["A02:2025-Security Misconfiguration"]},
                description=(
                    "The API returns Access-Control-Allow-Origin: * together with "
                    "Access-Control-Allow-Credentials: true, which browsers treat as invalid "
                    "but mis-implementations expose; any origin can read authenticated responses."
                ),
                impact="Any website can issue credentialed cross-origin requests and read the responses.",
                root_cause="CORS is configured with a wildcard origin while also allowing credentials.",
                remediation=Remediation(
                    summary="Reflect only an explicit allow-list of trusted origins; never pair '*' with credentials.",
                    type="config",
                    guidance=(
                        "Set Access-Control-Allow-Origin to a specific, validated origin (not '*') "
                        "when Access-Control-Allow-Credentials is true, and omit credentials for "
                        "public endpoints (CWE-942)."
                    ),
                    effort="low",
                ),
                references=["https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny"],
                compliance=["SOC2:CC6.1", "ISO27001:A.8.26"],
                tags=["cors", "misconfiguration"],
                checks=["ACAO='*' and ACAC='true' observed on 2/2 requests"],
            )
        )

    # --- Clickjacking: no X-Frame-Options and no CSP frame-ancestors (CWE-1021) ---
    def _framable(h):
        return ("x-frame-options" not in h) and (
            "frame-ancestors" not in h.get("content-security-policy", "").lower()
        )

    if _framable(h1) and _framable(h2):
        findings.append(
            _confirmed_finding(
                runner.engagement_id,
                application,
                target_url,
                title="Clickjacking: page can be framed (no X-Frame-Options / CSP frame-ancestors)",
                vuln_class="security-misconfiguration",
                severity="medium",
                cwe=["CWE-1021"],
                owasp={"web_2025": ["A02:2025-Security Misconfiguration"]},
                description="Responses set neither X-Frame-Options nor a CSP frame-ancestors directive.",
                impact="The UI can be embedded in a hostile frame for clickjacking / UI-redress attacks.",
                root_cause="No anti-framing control is sent.",
                remediation=Remediation(
                    summary="Set X-Frame-Options: DENY and CSP frame-ancestors 'none'.",
                    type="config",
                    guidance="Add X-Frame-Options: DENY (or SAMEORIGIN) and a "
                    "Content-Security-Policy with frame-ancestors 'none' (CWE-1021).",
                    effort="low",
                ),
                references=["https://owasp.org/www-community/attacks/Clickjacking"],
                compliance=["SOC2:CC6.6", "ISO27001:A.8.9"],
                tags=["clickjacking", "misconfiguration"],
                checks=["no X-Frame-Options and no CSP frame-ancestors on 2/2 responses"],
            )
        )

    # --- Insecure session cookie: missing HttpOnly / Secure / SameSite (CWE-614/1004) ---
    c1 = runner.get(
        "/api/session",
        session=None,
        payload_class="benign-read",
        rationale="cookie hygiene: inspect Set-Cookie flags",
        summary="cookie check",
    )
    c2 = runner.get(
        "/api/session",
        session=None,
        payload_class="benign-read",
        rationale="reproduction",
        summary="cookie check repro",
    )
    if c1.executed and c2.executed:

        def _bad_cookie(outcome):
            sc = _headers_ci(outcome.response).get("set-cookie", "")
            if not sc:
                return None
            low = sc.lower()
            missing = [
                flag
                for flag, tok in (("HttpOnly", "httponly"), ("Secure", "secure"), ("SameSite", "samesite"))
                if tok not in low
            ]
            return missing or None

        m1, m2 = _bad_cookie(c1), _bad_cookie(c2)
        if m1 and m2:
            findings.append(
                _confirmed_finding(
                    runner.engagement_id,
                    application,
                    target_url,
                    title=f"Session cookie missing security flags: {', '.join(m1)}",
                    vuln_class="security-misconfiguration",
                    severity="medium",
                    cwe=["CWE-614", "CWE-1004"],
                    owasp={"web_2025": ["A02:2025-Security Misconfiguration"]},
                    description=f"A Set-Cookie on /api/session omits: {', '.join(m1)}.",
                    impact="Session cookies are exposed to script (no HttpOnly), sent over HTTP (no Secure), "
                    "or usable cross-site (no SameSite) — aiding theft and CSRF.",
                    root_cause="Session cookies are issued without the HttpOnly/Secure/SameSite attributes.",
                    remediation=Remediation(
                        summary="Set HttpOnly, Secure and SameSite on session cookies.",
                        type="config",
                        guidance="Issue session cookies with HttpOnly; Secure; "
                        "SameSite=Strict (or Lax), and consider the __Host- prefix (CWE-614/1004).",
                        effort="low",
                    ),
                    references=["https://owasp.org/www-community/controls/SecureCookieAttribute"],
                    compliance=["SOC2:CC6.1", "ISO27001:A.8.5"],
                    tags=["cookie", "misconfiguration"],
                    checks=[f"Set-Cookie missing {', '.join(m1)} on 2/2 responses"],
                    path="/api/session",
                )
            )

            # --- CSRF (passive partial detector) — cookie session w/o SameSite + state-changing POSTs ---
            if m1 and "SameSite" in m1:
                post_eps = [
                    e
                    for e in getattr(appmodel, "endpoints", [])
                    if (e.method or "GET").upper() in ("POST", "PUT", "PATCH", "DELETE")
                ]
                if post_eps:
                    csrf = Finding(
                        engagement_id=runner.engagement_id,
                        title="Possible CSRF exposure (cookie session without SameSite + state-changing endpoints)",
                        vuln_class="csrf",
                        severity="medium",
                        confidence="firm",
                        state=State.EVIDENCE_FOUND,
                        cwe=["CWE-352"],
                        owasp={"web_2025": ["A01:2025-Broken Access Control"]},
                        asset={
                            "type": "web",
                            "application": application,
                            "environment": "authorized",
                            "target": target_url,
                        },
                        endpoint={
                            "method": "POST",
                            "url": f"{target_url}{post_eps[0].path}",
                            "auth_required": True,
                        },
                        description=(
                            "The session cookie lacks SameSite and the app exposes state-changing "
                            "endpoints; cross-site requests may be accepted (CSRF)."
                        ),
                        impact="An attacker page could trigger authenticated state-changing actions as the victim.",
                        root_cause="Cookie-based sessions without SameSite and no anti-CSRF token enforcement.",
                        reproduction=Reproduction(
                            prerequisites=["Cookie session"],
                            steps=[
                                "Observe Set-Cookie without SameSite",
                                "Note state-changing POST endpoints with no CSRF token",
                            ],
                            deterministic=False,
                        ),
                        remediation=Remediation(
                            summary="Set SameSite on session cookies and require anti-CSRF tokens.",
                            type="code_patch",
                            guidance="Use SameSite=Lax/Strict, synchronizer/double-submit CSRF "
                            "tokens on state-changing requests, and verify Origin (CWE-352).",
                            effort="medium",
                        ),
                        references=["https://owasp.org/www-community/attacks/csrf"],
                        compliance_control_refs=["SOC2:CC6.1"],
                        dedupe_key=f"{application}:csrf",
                        tags=["csrf", "partial-detector", "needs-human-review"],
                        verification=Verification(
                            method="passive-detector",
                            validated=False,
                            validated_at=now_iso(),
                            validator="csrf-detector",
                            reproductions=0,
                            false_positive_checks=[
                                "PARTIAL: passive signal — modern SameSite=Lax "
                                "defaults mean a browser is needed to confirm"
                            ],
                            confidence_score=0.4,
                        ),
                    )
                    findings.append(csrf)

    # --- Request-smuggling exposure (PASSIVE indicator only — never actively tested) ---
    proxies = proxy_indicators(h1)
    if proxies:
        findings.append(
            Finding(
                engagement_id=runner.engagement_id,
                title="Request-smuggling / cache-poisoning exposure (intermediary detected) — manual testing recommended",
                vuln_class="request-smuggling-indicator",
                severity="info",
                confidence="tentative",
                state=State.EVIDENCE_FOUND,
                cwe=["CWE-444"],
                owasp={"web_2025": ["A02:2025-Security Misconfiguration"]},
                asset={
                    "type": "web",
                    "application": application,
                    "environment": "authorized",
                    "target": target_url,
                },
                endpoint={"method": "GET", "url": f"{target_url}/", "auth_required": False},
                description=(
                    f"A front-end intermediary/CDN/cache was detected (headers: {', '.join(proxies)}). "
                    "Front-end/back-end pairs can be vulnerable to HTTP request smuggling / cache poisoning."
                ),
                impact="If the proxy and origin disagree on request boundaries: request smuggling, cache poisoning.",
                root_cause="A multi-hop HTTP path exists; boundary handling must be verified manually.",
                reproduction=Reproduction(
                    prerequisites=["None"], steps=["Observe proxy/cache response headers"], deterministic=True
                ),
                remediation=Remediation(
                    summary="Normalize ambiguous requests at the edge; keep front-end/back-end HTTP "
                    "parsers aligned; prefer HTTP/2 end-to-end.",
                    type="config",
                    guidance="Manually test with PortSwigger's HTTP Request Smuggler / Param Miner; "
                    "Rampart does NOT auto-test this (a desync would affect real users).",
                    effort="medium",
                ),
                references=[
                    "https://portswigger.net/web-security/request-smuggling",
                    "https://cwe.mitre.org/data/definitions/444.html",
                ],
                compliance_control_refs=["SOC2:CC7.1"],
                dedupe_key=f"{application}:request-smuggling-indicator",
                tags=["request-smuggling", "passive-indicator", "human-only", "needs-human-review"],
                verification=Verification(
                    method="passive-indicator",
                    validated=False,
                    validated_at=now_iso(),
                    validator="smuggling-indicator",
                    reproductions=0,
                    false_positive_checks=[
                        "INDICATOR ONLY — an intermediary exists; smuggling "
                        "requires expert manual confirmation (not auto-tested)"
                    ],
                    confidence_score=0.2,
                ),
            )
        )

    # --- Server/software version disclosure (CWE-200) ---
    server = h1.get("server", "")
    if server and _VERSION_RE.search(server) and _VERSION_RE.search(h2.get("server", "")):
        findings.append(
            _confirmed_finding(
                runner.engagement_id,
                application,
                target_url,
                title=f"Server software/version disclosure in Server header ({server})",
                vuln_class="security-misconfiguration",
                severity="low",
                cwe=["CWE-200"],
                owasp={"web_2025": ["A02:2025-Security Misconfiguration"]},
                description=f"The Server response header discloses software and version: '{server}'.",
                impact="Aids attackers in fingerprinting the stack and matching it to known CVEs.",
                root_cause="The server advertises its software name and version in responses.",
                remediation=Remediation(
                    summary="Suppress or genericise the Server header.",
                    type="config",
                    guidance="Remove the version from the Server header at the app or reverse proxy (CWE-200).",
                    effort="low",
                ),
                references=["https://owasp.org/www-project-secure-headers/"],
                compliance=["SOC2:CC7.1", "ISO27001:A.8.9"],
                tags=["version-disclosure", "misconfiguration"],
                checks=[f"Server header '{server}' carries a version on 2/2 requests"],
            )
        )

    return findings
