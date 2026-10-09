"""Multi-framework compliance mapping for Rampart.

Maps findings — deterministically, by CWE — to the controls they provide evidence for across
SOC 2, ISO 27001:2022, PCI DSS v4.0, NIST 800-53 Rev5 (FedRAMP), the HIPAA Security Rule, GDPR,
OWASP ASVS, and CIS Controls v8, and renders an audit-ready coverage matrix.
"""

from .frameworks import ALL_FRAMEWORKS, FRAMEWORKS, domains_for
from .mapper import compliance_matrix_report, coverage, map_finding

__all__ = [
    "FRAMEWORKS",
    "ALL_FRAMEWORKS",
    "domains_for",
    "map_finding",
    "coverage",
    "compliance_matrix_report",
]
