"""Web/API injection workers (reflected XSS, SQLi, open redirect).

These classes share one shape: the worker turns a grounded hypothesis into a candidate
Finding carrying the class metadata (CWE/OWASP/CVSS/remediation), then hands it — state
``EVIDENCE_FOUND`` — to the independent validator, which runs the matching deterministic
oracle as the sole confirmation gate. The worker deliberately does not decide validity, so
there is exactly one source of truth (the oracle) and no heuristic that could disagree with it.
"""
from __future__ import annotations

from ..schemas.finding import CVSS, Finding, Remediation, Reproduction, State

# class -> everything needed to render a defensible finding before proof is attached
WEB_CLASS_META = {
    "XSS": {
        "title": "Reflected cross-site scripting (XSS) in '{param}' on {method} {path}",
        "severity": "medium",
        "cwe": ["CWE-79"],
        "owasp": {"web_2025": ["A03:2025-Injection"]},
        "asvs": {"requirement": "V5.3.3", "level": 1},
        "cvss": CVSS(version="4.0", base_score=6.1,
                     vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:L/VA:N/SC:L/SI:L/SA:N",
                     severity="medium",
                     v31_fallback={"base_score": 6.1,
                                   "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"}),
        "description": ("The '{param}' parameter on {method} {path} is reflected into an HTML "
                        "response without output encoding, so attacker-supplied markup/script "
                        "executes in the victim's browser."),
        "impact": ("Session theft, credential harvesting, and action-on-behalf-of-user in the "
                   "victim's authenticated context."),
        "root_cause": "User input is written into an HTML response without context-aware output encoding.",
        "remediation": Remediation(
            summary="Context-encode all user input on output and add a restrictive CSP.",
            type="code_patch",
            guidance=("HTML-encode the reflected value at the point of output (e.g. a templating "
                      "engine with auto-escaping, or an explicit HTML-entity encoder). Add a "
                      "Content-Security-Policy that disallows inline script as defence in depth. "
                      "Validate/reject unexpected input server-side (CWE-79, OWASP ASVS V5.3)."),
            effort="low"),
        "references": ["https://owasp.org/www-community/attacks/xss/",
                       "https://cwe.mitre.org/data/definitions/79.html"],
        "compliance": ["SOC2:CC7.1", "ISO27001:A.8.26", "PCI-DSS:6.2.4"],
        "tags": ["xss", "injection", "reflected"],
    },
    "SQLI": {
        "title": "SQL injection in '{param}' on {method} {path}",
        "severity": "high",
        "cwe": ["CWE-89"],
        "owasp": {"web_2025": ["A03:2025-Injection"], "api_2023": ["API8:2023-Security Misconfiguration"]},
        "asvs": {"requirement": "V5.3.4", "level": 1},
        "cvss": CVSS(version="4.0", base_score=8.6,
                     vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:L/SC:N/SI:N/SA:N",
                     severity="high",
                     v31_fallback={"base_score": 8.6,
                                   "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L"}),
        "description": ("The '{param}' parameter on {method} {path} is concatenated into a SQL "
                        "statement. A single quote raises a database error (error-based) and "
                        "boolean conditions change the result set (boolean-based inference)."),
        "impact": ("Read/alter arbitrary database rows, bypass authentication, and exfiltrate "
                   "other users' data; frequently escalates to full database compromise."),
        "root_cause": "Untrusted input is interpolated into a SQL statement instead of being bound as a parameter.",
        "remediation": Remediation(
            summary="Use parameterized queries / prepared statements for every SQL call.",
            type="code_patch",
            guidance=("Replace string concatenation with bound parameters (prepared statements) "
                      "or a vetted ORM. Apply least-privilege DB accounts and allow-list input "
                      "types. Never surface raw driver errors to clients (CWE-89, OWASP ASVS V5.3.4)."),
            effort="medium"),
        "references": ["https://owasp.org/www-community/attacks/SQL_Injection",
                       "https://cwe.mitre.org/data/definitions/89.html"],
        "compliance": ["SOC2:CC7.1", "ISO27001:A.8.28", "PCI-DSS:6.2.4"],
        "tags": ["sqli", "injection", "database"],
    },
    "OPEN_REDIRECT": {
        "title": "Open redirect via '{param}' on {method} {path}",
        "severity": "medium",
        "cwe": ["CWE-601"],
        "owasp": {"web_2025": ["A01:2025-Broken Access Control"]},
        "asvs": {"requirement": "V5.1.5", "level": 1},
        "cvss": CVSS(version="4.0", base_score=6.1,
                     vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
                     severity="medium",
                     v31_fallback={"base_score": 6.1,
                                   "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"}),
        "description": ("The '{param}' parameter on {method} {path} is used as a redirect target "
                        "without validation, so the endpoint will redirect users to an arbitrary "
                        "external site."),
        "impact": ("Convincing phishing and OAuth/token-leak chains that abuse the trusted domain "
                   "to send victims to attacker-controlled sites."),
        "root_cause": "A user-supplied URL is used as a redirect destination without allow-list validation.",
        "remediation": Remediation(
            summary="Allow-list redirect targets; never redirect to a raw user-supplied URL.",
            type="code_patch",
            guidance=("Accept only relative paths or an explicit allow-list of hosts. Map a short "
                      "token to an internal destination instead of echoing a URL. Reject absolute "
                      "/ protocol-relative URLs to untrusted hosts (CWE-601, OWASP ASVS V5.1.5)."),
            effort="low"),
        "references": ["https://owasp.org/www-community/attacks/Unvalidated_Redirects_and_Forwards_Cheat_Sheet",
                       "https://cwe.mitre.org/data/definitions/601.html"],
        "compliance": ["SOC2:CC7.1", "ISO27001:A.8.26"],
        "tags": ["open-redirect", "access-control"],
    },
}

WEB_CLASSES = set(WEB_CLASS_META)


class WebWorker:
    """One worker for the reflected-XSS / SQLi / open-redirect family (by hypothesis class)."""

    profile = "web-injection"

    def __init__(self, runner, application: str = "target", environment: str = "authorized"):
        self.runner = runner
        self.application = application
        self.environment = environment

    def investigate(self, hyp: dict, target_url: str) -> Finding | None:
        meta = WEB_CLASS_META.get(hyp.get("vuln_class"))
        if meta is None:
            return None
        param = hyp["selector_param"]
        method = hyp["endpoint_method"]
        path = hyp["endpoint_path"]
        fmt = {"param": param, "method": method, "path": path}
        concrete_url = f"{target_url}{path}"

        finding = Finding(
            engagement_id=self.runner.engagement_id,
            title=meta["title"].format(**fmt),
            vuln_class=hyp["vuln_class"],
            severity=meta["severity"],
            confidence="firm",
            state=State.EVIDENCE_FOUND,       # the independent validator is the sole gate
            cwe=list(meta["cwe"]),
            owasp={k: list(v) for k, v in meta["owasp"].items()},
            asvs=dict(meta["asvs"]),
            cvss=meta["cvss"],
            asset={"type": "api_endpoint", "application": self.application,
                   "environment": self.environment, "target": target_url},
            endpoint={"method": method, "url": concrete_url,
                      "parameters": [{"name": param, "in": "query"}], "auth_required": False},
            description=meta["description"].format(**fmt),
            impact=meta["impact"],
            root_cause=meta["root_cause"],
            reproduction=Reproduction(
                prerequisites=["None (unauthenticated request)"],
                steps=[f"Send {method} {path} with a crafted '{param}' value",
                       "Observe the deterministic oracle signal (see proof below)"],
                deterministic=True),
            remediation=Remediation(**{k: getattr(meta["remediation"], k)
                                       for k in ("summary", "type", "guidance", "effort")}),
            references=list(meta["references"]),
            compliance_control_refs=list(meta["compliance"]),
            dedupe_key=f"{self.application}:{method}:{path}:{param}:{meta['cwe'][0]}",
            tags=list(meta["tags"]),
        )
        return finding
