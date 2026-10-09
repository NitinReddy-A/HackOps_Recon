"""White-box (SAST) source scanning + secret detection.

A native, dependency-free Python-AST scanner for high-signal sink patterns, plus a regex
secret scanner. These are STATIC findings (no runtime proof), so they are tiered below
oracle-`confirmed`: confidence='firm', method='static-analysis'. When a static finding's CWE
matches a runtime-confirmed DAST finding, the two are correlated into the highest-confidence
result ("proven at runtime AND located in source"). External SAST/SCA tools (Semgrep, Bandit,
Trivy, gitleaks, pip-audit) plug in via the scanner-adapter framework and normalise to the same
Finding shape.
"""

from .scanner import scan_source
from .secrets import scan_dependencies, scan_secrets

__all__ = ["scan_source", "scan_secrets", "scan_dependencies"]
