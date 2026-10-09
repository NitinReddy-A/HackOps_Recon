"""Multi-framework compliance control catalogs + the CWE→domain→control mapping engine.

Every finding carries one or more CWE ids. We map each CWE to one or more security-control
*domains* (access control, injection, crypto, …), and each domain to the concrete control id(s)
it provides evidence for in each framework. That indirection means a new vuln class only needs its
CWE added to one small table and it is instantly mapped across *every* framework — SOC 2, ISO
27001:2022, PCI DSS v4.0, NIST 800-53 Rev5 (the FedRAMP baseline), the HIPAA Security Rule, GDPR,
OWASP ASVS, and CIS Controls v8. The mapping is deterministic and auditable, never guessed.
"""

from __future__ import annotations

# ---------------------------------------------------------------- frameworks (control id -> title)
FRAMEWORKS = {
    "SOC2": {
        "title": "SOC 2 (Trust Services Criteria, 2017)",
        "controls": {
            "CC6.1": "Logical access — restrict access to data/functions to authorized users",
            "CC6.3": "Role-based access & least privilege",
            "CC6.6": "Boundary protection against external threats",
            "CC6.7": "Restrict transmission/movement of data",
            "CC6.8": "Prevent/detect unauthorized or malicious software & inputs",
            "CC7.1": "Detect and monitor vulnerabilities and config changes",
            "CC7.2": "Monitor components for anomalies / indicators of compromise",
            "CC8.1": "Change management (remediation / retest)",
        },
    },
    "ISO27001": {
        "title": "ISO/IEC 27001:2022 (Annex A)",
        "controls": {
            "A.5.15": "Access control",
            "A.8.3": "Information access restriction",
            "A.8.5": "Secure authentication",
            "A.8.8": "Management of technical vulnerabilities",
            "A.8.9": "Configuration management",
            "A.8.12": "Data leakage prevention",
            "A.8.15": "Logging",
            "A.8.22": "Segregation of networks",
            "A.8.23": "Web filtering",
            "A.8.24": "Use of cryptography",
            "A.8.28": "Secure coding",
        },
    },
    "PCI-DSS": {
        "title": "PCI DSS v4.0",
        "controls": {
            "2.2": "Secure configuration of system components",
            "3.5": "Protect stored account data",
            "4.2": "Strong cryptography in transit",
            "6.2.4": "Secure coding — prevent common software attacks",
            "6.3.3": "Remediate known vulnerabilities (patching)",
            "7.2": "Access control — least privilege / need to know",
            "8.3": "Strong authentication",
            "10.2": "Audit logs for access & actions",
            "11.3": "Vulnerability scanning",
            "11.4": "Penetration testing",
        },
    },
    "NIST-800-53": {
        "title": "NIST SP 800-53 Rev5 (FedRAMP baseline)",
        "controls": {
            "AC-3": "Access Enforcement",
            "AC-6": "Least Privilege",
            "IA-2": "Identification & Authentication (organizational users)",
            "IA-5": "Authenticator Management",
            "SC-7": "Boundary Protection",
            "SC-8": "Transmission Confidentiality & Integrity",
            "SC-13": "Cryptographic Protection",
            "SC-28": "Protection of Information at Rest",
            "SI-2": "Flaw Remediation",
            "SI-10": "Information Input Validation",
            "CM-6": "Configuration Settings",
            "CM-7": "Least Functionality",
            "RA-5": "Vulnerability Monitoring & Scanning",
            "AU-2": "Event Logging",
            "AU-6": "Audit Record Review & Analysis",
        },
    },
    "HIPAA": {
        "title": "HIPAA Security Rule (45 CFR Part 164)",
        "controls": {
            "164.308(a)(1)": "Security Management Process (risk analysis & management)",
            "164.308(a)(5)": "Security Awareness & Training",
            "164.308(a)(8)": "Evaluation (periodic technical testing)",
            "164.312(a)(1)": "Access Control",
            "164.312(b)": "Audit Controls",
            "164.312(c)(1)": "Integrity",
            "164.312(d)": "Person or Entity Authentication",
            "164.312(e)(1)": "Transmission Security",
        },
    },
    "GDPR": {
        "title": "EU GDPR (technical measures)",
        "controls": {
            "Art.5(1)(f)": "Integrity & confidentiality of personal data",
            "Art.25": "Data protection by design and by default",
            "Art.32": "Security of processing",
        },
    },
    "OWASP-ASVS": {
        "title": "OWASP ASVS v4.0",
        "controls": {
            "V2": "Authentication",
            "V4": "Access Control",
            "V5": "Validation, Sanitization & Encoding",
            "V6": "Stored Cryptography",
            "V7": "Error Handling & Logging",
            "V8": "Data Protection",
            "V9": "Communications",
            "V13": "API & Web Service",
            "V14": "Configuration",
        },
    },
    "CIS": {
        "title": "CIS Controls v8",
        "controls": {
            "CIS-3": "Data Protection",
            "CIS-4": "Secure Configuration of Enterprise Assets & Software",
            "CIS-6": "Access Control Management",
            "CIS-7": "Continuous Vulnerability Management",
            "CIS-8": "Audit Log Management",
            "CIS-13": "Network Monitoring & Defense",
            "CIS-16": "Application Software Security",
        },
    },
}

# ---------------------------------------------------------------- domain -> controls per framework
DOMAIN_CONTROLS = {
    "ACCESS_CONTROL": {
        "SOC2": ["CC6.1", "CC6.3"],
        "ISO27001": ["A.8.3", "A.5.15"],
        "PCI-DSS": ["7.2"],
        "NIST-800-53": ["AC-3", "AC-6"],
        "HIPAA": ["164.312(a)(1)"],
        "GDPR": ["Art.32"],
        "OWASP-ASVS": ["V4"],
        "CIS": ["CIS-6"],
    },
    "AUTHENTICATION": {
        "SOC2": ["CC6.1"],
        "ISO27001": ["A.8.5"],
        "PCI-DSS": ["8.3"],
        "NIST-800-53": ["IA-2", "IA-5"],
        "HIPAA": ["164.312(d)"],
        "GDPR": ["Art.32"],
        "OWASP-ASVS": ["V2"],
        "CIS": ["CIS-6"],
    },
    "INJECTION": {
        "SOC2": ["CC6.8"],
        "ISO27001": ["A.8.28"],
        "PCI-DSS": ["6.2.4"],
        "NIST-800-53": ["SI-10"],
        "HIPAA": ["164.312(c)(1)"],
        "GDPR": ["Art.32"],
        "OWASP-ASVS": ["V5"],
        "CIS": ["CIS-16"],
    },
    "INPUT_VALIDATION": {
        "SOC2": ["CC6.8"],
        "ISO27001": ["A.8.28"],
        "PCI-DSS": ["6.2.4"],
        "NIST-800-53": ["SI-10"],
        "HIPAA": ["164.312(c)(1)"],
        "GDPR": ["Art.25"],
        "OWASP-ASVS": ["V5", "V13"],
        "CIS": ["CIS-16"],
    },
    "CRYPTO": {
        "SOC2": ["CC6.7"],
        "ISO27001": ["A.8.24"],
        "PCI-DSS": ["4.2"],
        "NIST-800-53": ["SC-8", "SC-13"],
        "HIPAA": ["164.312(e)(1)"],
        "GDPR": ["Art.32"],
        "OWASP-ASVS": ["V6", "V9"],
        "CIS": ["CIS-3"],
    },
    "CONFIG": {
        "SOC2": ["CC7.1"],
        "ISO27001": ["A.8.9"],
        "PCI-DSS": ["2.2"],
        "NIST-800-53": ["CM-6", "CM-7"],
        "HIPAA": ["164.308(a)(8)"],
        "GDPR": ["Art.25"],
        "OWASP-ASVS": ["V14"],
        "CIS": ["CIS-4"],
    },
    "DATA_EXPOSURE": {
        "SOC2": ["CC6.1", "CC6.7"],
        "ISO27001": ["A.8.12"],
        "PCI-DSS": ["3.5"],
        "NIST-800-53": ["SC-28", "AC-3"],
        "HIPAA": ["164.312(a)(1)"],
        "GDPR": ["Art.5(1)(f)", "Art.32"],
        "OWASP-ASVS": ["V8"],
        "CIS": ["CIS-3"],
    },
    "SSRF_REDIRECT": {
        "SOC2": ["CC6.6"],
        "ISO27001": ["A.8.22", "A.8.23"],
        "PCI-DSS": ["6.2.4"],
        "NIST-800-53": ["SC-7"],
        "HIPAA": ["164.312(e)(1)"],
        "GDPR": ["Art.32"],
        "OWASP-ASVS": ["V5"],
        "CIS": ["CIS-13"],
    },
    "VULN_MGMT": {
        "SOC2": ["CC7.1"],
        "ISO27001": ["A.8.8"],
        "PCI-DSS": ["6.3.3", "11.3"],
        "NIST-800-53": ["RA-5", "SI-2"],
        "HIPAA": ["164.308(a)(1)"],
        "GDPR": ["Art.32"],
        "OWASP-ASVS": ["V14"],
        "CIS": ["CIS-7"],
    },
    "LOGGING": {
        "SOC2": ["CC7.2"],
        "ISO27001": ["A.8.15"],
        "PCI-DSS": ["10.2"],
        "NIST-800-53": ["AU-2", "AU-6"],
        "HIPAA": ["164.312(b)"],
        "GDPR": ["Art.32"],
        "OWASP-ASVS": ["V7"],
        "CIS": ["CIS-8"],
    },
}

# ---------------------------------------------------------------- CWE -> domain(s)
CWE_DOMAINS = {
    # access control / authorization
    "CWE-639": ["ACCESS_CONTROL"],
    "CWE-284": ["ACCESS_CONTROL"],
    "CWE-285": ["ACCESS_CONTROL"],
    "CWE-650": ["ACCESS_CONTROL"],
    "CWE-22": ["ACCESS_CONTROL"],
    "CWE-668": ["ACCESS_CONTROL", "DATA_EXPOSURE"],
    "CWE-269": ["ACCESS_CONTROL"],
    "CWE-862": ["ACCESS_CONTROL"],
    "CWE-863": ["ACCESS_CONTROL"],
    # authentication / session
    "CWE-347": ["AUTHENTICATION"],
    "CWE-287": ["AUTHENTICATION"],
    "CWE-384": ["AUTHENTICATION"],
    "CWE-613": ["AUTHENTICATION"],
    "CWE-307": ["AUTHENTICATION"],
    "CWE-522": ["AUTHENTICATION"],
    # injection / secure coding
    "CWE-89": ["INJECTION"],
    "CWE-78": ["INJECTION"],
    "CWE-79": ["INJECTION"],
    "CWE-1336": ["INJECTION"],
    "CWE-94": ["INJECTION"],
    "CWE-95": ["INJECTION"],
    "CWE-91": ["INJECTION"],
    "CWE-90": ["INJECTION"],
    "CWE-643": ["INJECTION"],
    "CWE-611": ["INJECTION", "SSRF_REDIRECT"],
    "CWE-502": ["INJECTION"],
    "CWE-74": ["INJECTION"],
    # input validation / business logic
    "CWE-840": ["INPUT_VALIDATION"],
    "CWE-841": ["INPUT_VALIDATION"],
    "CWE-20": ["INPUT_VALIDATION"],
    "CWE-915": ["INPUT_VALIDATION", "ACCESS_CONTROL"],
    "CWE-770": ["INPUT_VALIDATION"],
    # crypto / transport
    "CWE-327": ["CRYPTO"],
    "CWE-326": ["CRYPTO"],
    "CWE-295": ["CRYPTO"],
    "CWE-916": ["CRYPTO"],
    "CWE-311": ["CRYPTO", "DATA_EXPOSURE"],
    "CWE-319": ["CRYPTO"],
    # configuration / hardening
    "CWE-16": ["CONFIG"],
    "CWE-942": ["CONFIG"],
    "CWE-1021": ["CONFIG"],
    "CWE-614": ["CONFIG"],
    "CWE-1004": ["CONFIG"],
    "CWE-489": ["CONFIG"],
    "CWE-756": ["CONFIG"],
    "CWE-250": ["CONFIG"],
    "CWE-1104": ["VULN_MGMT"],
    "CWE-494": ["VULN_MGMT", "CONFIG"],
    # data exposure / disclosure
    "CWE-200": ["DATA_EXPOSURE"],
    "CWE-213": ["DATA_EXPOSURE"],
    "CWE-538": ["DATA_EXPOSURE"],
    "CWE-798": ["DATA_EXPOSURE", "AUTHENTICATION"],
    "CWE-532": ["DATA_EXPOSURE", "LOGGING"],
    # ssrf / redirect / boundary
    "CWE-918": ["SSRF_REDIRECT"],
    "CWE-601": ["SSRF_REDIRECT"],
    "CWE-644": ["SSRF_REDIRECT"],
    "CWE-444": ["SSRF_REDIRECT", "CONFIG"],
    # vulnerable / outdated components (SCA)
    "CWE-1395": ["VULN_MGMT"],
    "CWE-937": ["VULN_MGMT"],
    "CWE-1035": ["VULN_MGMT"],
    # logging / monitoring
    "CWE-778": ["LOGGING"],
    "CWE-223": ["LOGGING"],
}

# vuln_class fallback -> domain(s), used when a finding carries no mapped CWE.
CLASS_DOMAINS = {
    "IDOR/BOLA": ["ACCESS_CONTROL"],
    "BFLA": ["ACCESS_CONTROL"],
    "EXCESSIVE_DATA": ["DATA_EXPOSURE"],
    "SQLI": ["INJECTION"],
    "CMDI": ["INJECTION"],
    "XSS": ["INJECTION"],
    "SSTI": ["INJECTION"],
    "PATH_TRAVERSAL": ["ACCESS_CONTROL"],
    "OPEN_REDIRECT": ["SSRF_REDIRECT"],
    "SSRF": ["SSRF_REDIRECT"],
    "JWT": ["AUTHENTICATION"],
    "HOST_HEADER_INJECTION": ["SSRF_REDIRECT"],
    "MASS_ASSIGNMENT": ["INPUT_VALIDATION"],
    "GRAPHQL": ["CONFIG"],
    "XXE": ["INJECTION"],
    "LLM": ["INJECTION"],
    "EXPOSED_SERVICE": ["CONFIG", "ACCESS_CONTROL"],
    "HTTP_METHOD_TAMPERING": ["ACCESS_CONTROL"],
    "BUSINESS_LOGIC_ECONOMIC": ["INPUT_VALIDATION"],
    "BUSINESS_LOGIC_WORKFLOW": ["INPUT_VALIDATION"],
    "sca-known-vulnerability": ["VULN_MGMT"],
    "sca-unpinned-dependency": ["VULN_MGMT"],
    "sast-hardcoded-secret": ["DATA_EXPOSURE"],
    "security-misconfiguration": ["CONFIG"],
    "sensitive-file-exposure": ["DATA_EXPOSURE"],
}

ALL_FRAMEWORKS = list(FRAMEWORKS.keys())


def domains_for(cwes, vuln_class: str = "") -> list[str]:
    """Return the security-control domains a finding touches, from its CWEs (+ class fallback)."""
    doms: list[str] = []
    for c in cwes or []:
        for d in CWE_DOMAINS.get(c, []):
            if d not in doms:
                doms.append(d)
    if not doms:
        for d in CLASS_DOMAINS.get(vuln_class, []):
            if d not in doms:
                doms.append(d)
    if not doms:
        doms = ["CONFIG"]  # conservative default so nothing is left unmapped
    return doms
