"""Base class for external OSS scanner adapters (blueprint sections 7, 17).

An adapter wraps a widely-used open-source tool (Nuclei, Nmap, Semgrep, Trivy, testssl) as a
separate-process plugin that normalises its output into Rampart ``Finding`` objects. Three
rules keep this safe and honest:

* **Graceful degradation.** If the tool is not installed, :meth:`is_available` returns False and
  the run is skipped with an install hint — the product still works with zero external deps.
* **Evidence over alerts.** External findings are *unvalidated* (``confidence='firm'``,
  ``state=EvidenceFound``, ``validated=False``) and tagged ``external-scanner``. Only Rampart's
  own independent oracles may mark a finding ``confirmed``. A scanner alert is a lead, not proof.
* **Scope.** Network adapters target only the single authorized in-scope URL; source adapters
  read only the provided repo. External tools run outside the policy choke-point, so they are
  opt-in (``--scanners``), never on by default.
"""

from __future__ import annotations

import shutil
import subprocess

from ...schemas.finding import Finding, Reproduction, State, Verification
from ...util import now_iso

_SARIF_LEVEL_SEV = {"error": "high", "warning": "medium", "note": "low", "none": "info"}


def docker_available() -> bool:
    exe = shutil.which("docker")
    if not exe:
        return False
    try:
        r = subprocess.run(
            [exe, "info"], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=8
        )
        return r.returncode == 0
    except Exception:  # noqa: BLE001
        return False


class ScannerAdapter:
    name = "scanner"
    binary = ""  # the executable we look for on PATH
    category = "dast"  # dast | sast | sca | network | tls
    network = False  # True if it sends traffic to the target
    install_hint = ""
    help_uri = ""

    def __init__(
        self, repo: str = "", timeout: float = 300.0, extra_args=None, scope=None, active: bool = False
    ):
        """``scope`` (an EngagementScope) and ``active`` let network adapters derive safe
        flags — rate limits, excluded paths, intrusive-template gating. Both default to the most
        conservative behaviour (no scope = default limits; ``active=False`` = non-intrusive)."""
        self.repo = repo
        self.timeout = timeout
        self.extra_args = list(extra_args or [])
        self.scope = scope
        self.active = bool(active)

    def skip_reason(self) -> str:
        """Non-empty when the adapter is installed but must NOT run (e.g. missing explicit config).

        The supervisor should check this after :meth:`is_available` and log the reason instead of
        running. Default: "" (run)."""
        return ""

    def uses_network(self) -> bool:
        """True if this run will make network requests (to the target OR to a rule registry)."""
        return bool(self.network)

    # -- availability --------------------------------------------------------
    def resolved_binary(self) -> str | None:
        return shutil.which(self.binary) if self.binary else None

    def is_available(self) -> bool:
        return self.resolved_binary() is not None

    def version(self) -> str:
        exe = self.resolved_binary()
        if not exe:
            return ""
        for flag in ("-version", "--version", "version", "-V"):
            try:
                r = subprocess.run(
                    [exe, flag],
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=15,
                )
                out = (r.stdout or r.stderr or "").strip().splitlines()
                if out:
                    return out[0][:80]
            except Exception:  # noqa: BLE001
                continue
        return "installed"

    # -- execution helpers ---------------------------------------------------
    def _exec(self, cmd: list[str]) -> subprocess.CompletedProcess:
        return subprocess.run(
            cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=self.timeout
        )

    def _external_finding(
        self,
        *,
        engagement_id,
        application,
        target_url,
        title,
        severity,
        vuln_class,
        cwe,
        description,
        endpoint_url="",
        help_uri="",
        tags=None,
        rule_id="",
    ) -> Finding:
        f = Finding(
            engagement_id=engagement_id,
            title=title,
            vuln_class=vuln_class,
            severity=severity if severity in ("info", "low", "medium", "high", "critical") else "medium",
            confidence="firm",  # NOT confirmed — no independent oracle re-derivation
            state=State.EVIDENCE_FOUND,
            cwe=list(cwe or []),
            asset={
                "type": self.category,
                "application": application,
                "environment": "authorized",
                "target": target_url,
            },
            endpoint={"method": "GET", "url": endpoint_url or target_url, "auth_required": False},
            description=description,
            reproduction=Reproduction(
                prerequisites=[f"{self.name} installed"],
                steps=[f"Run {self.name} against the authorized target"],
                deterministic=False,
            ),
            references=[help_uri] if help_uri else [],
            verification=Verification(
                method=f"external-scanner:{self.name}",
                validated=False,
                validated_at=now_iso(),
                validator=self.name,
                independent_reproduction=False,
                reproductions=0,
                false_positive_checks=[
                    f"reported by {self.name}; NOT independently validated by a Rampart oracle"
                ],
                confidence_score=0.5,
            ),
            dedupe_key=f"{application}:{self.name}:{rule_id or title}",
            tags=["external-scanner", self.name] + list(tags or []),
        )
        return f

    # -- interface -----------------------------------------------------------
    def run(self, appmodel, target_url: str, application: str) -> list[Finding]:
        raise NotImplementedError
