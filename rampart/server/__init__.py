"""Zero-dependency local web dashboard for Rampart runs (stdlib http.server).

Serves a dashboard over a run work-dir: risk score, attack chains, findings table, the full
HTML report, and a scope-gated "run a scan" form. Bound to loopback by default. Launching a
scan still passes through the engagement's scope gate, so the dashboard cannot test anything
the SECURITY.md contract does not authorize.
"""
from .dashboard import serve

__all__ = ["serve"]
