"""Native, dependency-free Infrastructure-as-Code / cloud-config security scanner.

Deterministic, line/regex-based checks over Terraform, CloudFormation, Kubernetes and
Dockerfile templates. Each hit is a STATIC finding (``method='iac-static'``, not
``validated``), tiered below runtime-``confirmed`` oracle findings and correlated by CWE —
the same trust model as the SAST scanner. To keep false positives low, every check requires
a specific dangerous literal (e.g. ``"0.0.0.0/0"``, ``public-read``, ``privileged: true``).
Deeper coverage plugs in via scanner adapters (Checkov, Trivy-config, tfsec) that normalise
to the same Finding shape.
"""

from .scanner import scan_iac

__all__ = ["scan_iac"]
