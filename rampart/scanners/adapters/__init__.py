"""External OSS scanner adapters — optional, opt-in, graceful when not installed."""

from __future__ import annotations

from .base import ScannerAdapter, docker_available
from .tools import (
    BanditAdapter,
    GitleaksAdapter,
    NmapAdapter,
    NucleiAdapter,
    OpengrepAdapter,
    SemgrepAdapter,
    TestsslAdapter,
    TrivyAdapter,
)

ADAPTERS = {
    "nuclei": NucleiAdapter,
    "nmap": NmapAdapter,
    "semgrep": SemgrepAdapter,
    "opengrep": OpengrepAdapter,
    "bandit": BanditAdapter,
    "gitleaks": GitleaksAdapter,
    "trivy": TrivyAdapter,
    "testssl": TestsslAdapter,
}


def build_adapters(names, repo: str = "", timeout: float = 300.0) -> list:
    """Instantiate the requested adapters. 'all' expands to every adapter."""
    if isinstance(names, str):
        names = [n.strip() for n in names.split(",") if n.strip()]
    if not names:
        return []
    if "all" in names:
        names = list(ADAPTERS)
    out = []
    for n in names:
        cls = ADAPTERS.get(n)
        if cls:
            out.append(cls(repo=repo, timeout=timeout))
    return out


def doctor() -> dict:
    """Report which tools are installed (for the `rampart tools` command)."""
    rows = []
    for name, cls in ADAPTERS.items():
        a = cls()
        avail = a.is_available()
        rows.append(
            {
                "name": name,
                "category": a.category,
                "network": a.network,
                "available": avail,
                "version": a.version() if avail else "",
                "install_hint": a.install_hint,
                "help_uri": a.help_uri,
            }
        )
    return {"docker": docker_available(), "adapters": rows}


__all__ = ["ScannerAdapter", "ADAPTERS", "build_adapters", "doctor", "docker_available"]
