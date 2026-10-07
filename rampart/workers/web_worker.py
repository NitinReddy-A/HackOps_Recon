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
    "SSRF": {
        "title": "Server-side request forgery (SSRF) via '{param}' on {method} {path}",
        "severity": "high",
        "cwe": ["CWE-918"],
        "owasp": {"web_2025": ["A10:2025-Server-Side Request Forgery"], "api_2023": ["API7:2023-SSRF"]},
        "asvs": {"requirement": "V12.6", "level": 2},
        "cvss": CVSS(version="4.0", base_score=8.6,
                     vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:N/SC:L/SI:N/SA:N",
                     severity="high",
                     v31_fallback={"base_score": 8.6, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N"}),
        "description": ("The '{param}' parameter on {method} {path} causes the server to fetch a "
                        "user-supplied URL, reaching internal/cloud-metadata endpoints it should not."),
        "impact": ("Access to internal services and cloud metadata (credentials/IAM tokens), "
                   "internal port scanning, and pivoting into the internal network."),
        "root_cause": "A user-controlled URL is fetched server-side without host allow-listing.",
        "remediation": Remediation(
            summary="Allow-list destinations; block internal/link-local ranges and metadata IPs.",
            type="code_patch",
            guidance=("Validate the URL against an allow-list of schemes/hosts, resolve and reject "
                      "private/link-local/metadata ranges (incl. 169.254.169.254), disable redirects, "
                      "and use a dedicated egress proxy (CWE-918, OWASP ASVS V12.6)."),
            effort="medium"),
        "references": ["https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
                       "https://cwe.mitre.org/data/definitions/918.html"],
        "compliance": ["SOC2:CC6.6", "ISO27001:A.8.22"],
        "tags": ["ssrf", "injection"],
    },
    "CMDI": {
        "title": "OS command injection via '{param}' on {method} {path}",
        "severity": "critical",
        "cwe": ["CWE-78"],
        "owasp": {"web_2025": ["A03:2025-Injection"]},
        "asvs": {"requirement": "V5.3.8", "level": 1},
        "cvss": CVSS(version="4.0", base_score=9.3,
                     vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
                     severity="critical",
                     v31_fallback={"base_score": 9.8, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}),
        "description": ("The '{param}' parameter on {method} {path} is passed to an OS command; shell "
                        "metacharacters let an attacker run arbitrary commands on the server."),
        "impact": "Arbitrary command execution on the host — full server compromise.",
        "root_cause": "Untrusted input is concatenated into a shell command.",
        "remediation": Remediation(
            summary="Never build shell strings from input; use argument arrays and strict validation.",
            type="code_patch",
            guidance=("Avoid the shell: call programs with an argument vector (execve-style), not a shell "
                      "string. Validate input against a strict allow-list, drop metacharacters, and run "
                      "with least privilege (CWE-78, OWASP ASVS V5.3.8)."),
            effort="medium"),
        "references": ["https://owasp.org/www-community/attacks/Command_Injection",
                       "https://cwe.mitre.org/data/definitions/78.html"],
        "compliance": ["SOC2:CC7.1", "ISO27001:A.8.28", "PCI-DSS:6.2.4"],
        "tags": ["command-injection", "injection", "rce"],
    },
    "PATH_TRAVERSAL": {
        "title": "Path traversal via '{param}' on {method} {path}",
        "severity": "high",
        "cwe": ["CWE-22"],
        "owasp": {"web_2025": ["A01:2025-Broken Access Control"]},
        "asvs": {"requirement": "V12.3.1", "level": 1},
        "cvss": CVSS(version="4.0", base_score=7.5,
                     vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
                     severity="high",
                     v31_fallback={"base_score": 7.5, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}),
        "description": ("The '{param}' parameter on {method} {path} is used as a file path without "
                        "canonicalisation, so '../' sequences read files outside the intended directory."),
        "impact": "Disclosure of arbitrary server files (configs, credentials, source, /etc/passwd).",
        "root_cause": "A user-controlled filename is joined to a base path without canonicalisation/containment.",
        "remediation": Remediation(
            summary="Canonicalise and contain file paths; reject traversal sequences.",
            type="code_patch",
            guidance=("Resolve the path and verify it stays within an allowed base directory, reject '..' "
                      "and absolute paths, and prefer an id→filename map over raw names (CWE-22, ASVS V12.3)."),
            effort="low"),
        "references": ["https://owasp.org/www-community/attacks/Path_Traversal",
                       "https://cwe.mitre.org/data/definitions/22.html"],
        "compliance": ["SOC2:CC6.1", "ISO27001:A.8.3"],
        "tags": ["path-traversal", "lfi"],
    },
    "BFLA": {
        "title": "Broken function-level authorization on {method} {path}",
        "severity": "high",
        "cwe": ["CWE-285", "CWE-862"],
        "owasp": {"api_2023": ["API5:2023-Broken Function Level Authorization"],
                  "web_2025": ["A01:2025-Broken Access Control"]},
        "asvs": {"requirement": "V4.1.1", "level": 1},
        "cvss": CVSS(version="4.0", base_score=8.3,
                     vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N",
                     severity="high",
                     v31_fallback={"base_score": 8.1, "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N"}),
        "description": ("A low-privilege authenticated principal can invoke the privileged function "
                        "{method} {path}, which should require elevated (e.g. admin) role."),
        "impact": "Non-admin users perform administrative actions / read all tenants' data.",
        "root_cause": "The endpoint authenticates the caller but does not enforce a role/function check.",
        "remediation": Remediation(
            summary="Enforce a server-side role/permission check on every privileged function.",
            type="code_patch",
            guidance=("Add centralized function-level authorization (deny-by-default) keyed on the "
                      "authenticated principal's role/permissions, not on client-supplied data "
                      "(CWE-285, OWASP API5:2023)."),
            effort="medium"),
        "references": ["https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/",
                       "https://cwe.mitre.org/data/definitions/285.html"],
        "compliance": ["SOC2:CC6.3", "ISO27001:A.8.2", "PCI-DSS:7.1"],
        "tags": ["bfla", "access-control", "authorization"],
    },
    "EXCESSIVE_DATA": {
        "title": "Excessive data exposure on {method} {path}",
        "severity": "medium",
        "cwe": ["CWE-213"],
        "owasp": {"api_2023": ["API3:2023-Broken Object Property Level Authorization"],
                  "web_2025": ["A01:2025-Broken Access Control"]},
        "asvs": {"requirement": "V8.3.1", "level": 1},
        "cvss": CVSS(version="4.0", base_score=6.9,
                     vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
                     severity="medium",
                     v31_fallback={"base_score": 6.5, "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"}),
        "description": ("The response from {method} {path} includes sensitive fields (PII / secrets) "
                        "that should not be returned to the client."),
        "impact": "Leaks PII and secrets (SSN, password hashes, tokens, card data) to any authorized caller.",
        "root_cause": "The API serializes the full object instead of an explicit, minimal response schema.",
        "remediation": Remediation(
            summary="Return an explicit allow-listed response schema; never serialize whole records.",
            type="code_patch",
            guidance=("Define per-endpoint output DTOs/serializers that expose only required fields, "
                      "and filter secrets/PII server-side (CWE-213, OWASP API3:2023)."),
            effort="low"),
        "references": ["https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/",
                       "https://cwe.mitre.org/data/definitions/213.html"],
        "compliance": ["SOC2:CC6.1", "ISO27001:A.8.12", "PCI-DSS:3.3"],
        "tags": ["excessive-data-exposure", "pii", "api"],
    },
    "SSTI": {
        "title": "Server-side template injection in '{param}' on {method} {path}",
        "severity": "critical",
        "cwe": ["CWE-1336", "CWE-94"],
        "owasp": {"web_2025": ["A03:2025-Injection"]},
        "asvs": {"requirement": "V5.2.5", "level": 2},
        "cvss": CVSS(version="4.0", base_score=9.1,
                     vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:L/SC:N/SI:N/SA:N",
                     severity="critical",
                     v31_fallback={"base_score": 9.8, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}),
        "description": ("The '{param}' parameter on {method} {path} is rendered by a template engine; a "
                        "template expression ({{1337*1338}}) is evaluated server-side."),
        "impact": "Server-side code/template execution, typically escalating to remote code execution.",
        "root_cause": "User input is concatenated into a template that is then evaluated.",
        "remediation": Remediation(
            summary="Never render user input as a template; use a logic-less, sandboxed engine with data binding.",
            type="code_patch",
            guidance=("Pass user input as template *data*, never as template *source*. Use a sandboxed/"
                      "logic-less engine (e.g. auto-escaping) and validate input (CWE-1336, OWASP ASVS V5.2.5)."),
            effort="medium"),
        "references": ["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server-side_Template_Injection",
                       "https://cwe.mitre.org/data/definitions/1336.html"],
        "compliance": ["SOC2:CC6.8", "ISO27001:A.8.28", "PCI-DSS:6.2.4"],
        "tags": ["ssti", "injection", "rce"],
    },
    "JWT": {
        "title": "JWT accepted without signature verification (alg=none) on {method} {path}",
        "severity": "critical",
        "cwe": ["CWE-347"],
        "owasp": {"api_2023": ["API2:2023-Broken Authentication"], "web_2025": ["A07:2021-Identification and Authentication Failures"]},
        "asvs": {"requirement": "V3.5.3", "level": 2},
        "cvss": CVSS(version="4.0", base_score=9.3,
                     vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
                     severity="critical",
                     v31_fallback={"base_score": 9.8, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"}),
        "description": ("{method} {path} accepts a JWT whose signature is not verified (alg=none / unsigned), "
                        "so an attacker can forge any identity and claims."),
        "impact": "Full authentication bypass and privilege escalation by forging arbitrary identities/roles.",
        "root_cause": "The token is decoded without cryptographically verifying its signature and allowed algorithm.",
        "remediation": Remediation(
            summary="Verify the JWT signature with a pinned algorithm; reject 'none' and algorithm confusion.",
            type="code_patch",
            guidance=("Verify every token's signature with a server-held key and an explicit allow-list of "
                      "algorithms; reject alg=none and RS/HS confusion; check exp/aud/iss (CWE-347, ASVS V3.5)."),
            effort="low"),
        "references": ["https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/",
                       "https://cwe.mitre.org/data/definitions/347.html"],
        "compliance": ["SOC2:CC6.1", "ISO27001:A.8.5", "PCI-DSS:8.3"],
        "tags": ["jwt", "authentication", "auth-bypass"],
    },
    "HOST_HEADER_INJECTION": {
        "title": "Host header injection on {method} {path}",
        "severity": "medium",
        "cwe": ["CWE-644"],
        "owasp": {"web_2025": ["A02:2025-Security Misconfiguration"]},
        "asvs": {"requirement": "V5.1.3", "level": 1},
        "cvss": CVSS(version="4.0", base_score=6.1,
                     vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
                     severity="medium",
                     v31_fallback={"base_score": 6.1, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"}),
        "description": ("{method} {path} reflects the client-supplied Host header into generated "
                        "links/content, enabling password-reset poisoning and web-cache poisoning."),
        "impact": "Password-reset links / absolute URLs point at an attacker host; account takeover via poisoned links.",
        "root_cause": "The application trusts the incoming Host (or X-Forwarded-Host) header to build URLs.",
        "remediation": Remediation(
            summary="Build absolute URLs from a configured canonical host, not the request Host header.",
            type="code_patch",
            guidance=("Use a server-side allow-list of expected hosts; derive links from a fixed canonical "
                      "base URL; validate Host/X-Forwarded-Host at the edge (CWE-644)."),
            effort="low"),
        "references": ["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/17-Testing_for_Host_Header_Injection",
                       "https://cwe.mitre.org/data/definitions/644.html"],
        "compliance": ["SOC2:CC6.1", "ISO27001:A.8.26"],
        "tags": ["host-header-injection", "misconfiguration"],
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
        param = hyp.get("selector_param") or ""
        method = hyp["endpoint_method"]
        path = hyp["endpoint_path"]
        fmt = {"param": param, "method": method, "path": path}
        concrete_url = f"{target_url}{path}"
        params_block = [{"name": param, "in": "query"}] if param else []
        dedupe_suffix = param or "function"

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
                      "parameters": params_block, "auth_required": bool(hyp.get("actor_principal"))},
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
            dedupe_key=f"{self.application}:{method}:{path}:{dedupe_suffix}:{meta['cwe'][0]}",
            tags=list(meta["tags"]),
        )
        return finding
