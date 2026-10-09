"""Out-of-band (OOB) collaborator — makes *blind* vulnerabilities deterministic.

Many high-impact bugs give no response signal: blind SSRF, blind XXE, some deserialization.
The only reliable, false-positive-free proof is an out-of-band callback: inject a URL pointing
at a collaborator we control with a unique token, then observe whether the target server
connected back. A hit is deterministic proof the server made the request. The collaborator is
a tiny stdlib HTTP server you self-host (loopback by default).
"""

from .blind import blind_ssrf_scan, blind_xxe_scan
from .collaborator import OOBCollaborator, oob_skip_reason

__all__ = ["OOBCollaborator", "blind_ssrf_scan", "blind_xxe_scan", "oob_skip_reason"]
