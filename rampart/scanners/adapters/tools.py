"""Concrete adapters for widely-used OSS security tools.

Each adapter separates *parsing* (pure, unit-tested on recorded output) from *execution*
(shelling the tool). When the tool is not installed, the supervisor skips it via
:meth:`ScannerAdapter.is_available`. All findings are unvalidated external leads.
"""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from urllib.parse import urlparse

from .base import ScannerAdapter
from .sarif import sarif_to_findings

_NUCLEI_SEV = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "info",
    "unknown": "info",
}


class NucleiAdapter(ScannerAdapter):
    name = "nuclei"
    binary = "nuclei"
    category = "dast"
    network = True
    install_hint = "install from https://github.com/projectdiscovery/nuclei (go install / brew / binary)"
    help_uri = "https://github.com/projectdiscovery/nuclei"

    def _parse(self, raw: str, application, target_url) -> list:
        out = []
        for line in (raw or "").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue
            info = ev.get("info") or {}
            sev = _NUCLEI_SEV.get(str(info.get("severity", "info")).lower(), "info")
            cwes = []
            classif = info.get("classification") or {}
            for c in classif.get("cwe-id") or []:
                cwes.append(c.upper().replace("CWE_", "CWE-") if "cwe" in c.lower() else f"CWE-{c}")
            out.append(
                self._external_finding(
                    engagement_id="",
                    application=application,
                    target_url=target_url,
                    title=f"[nuclei] {info.get('name', ev.get('template-id', 'match'))}",
                    severity=sev,
                    vuln_class=str(ev.get("template-id") or "nuclei"),
                    cwe=cwes,
                    description=info.get("description", "") or info.get("name", ""),
                    endpoint_url=ev.get("matched-at") or ev.get("host") or target_url,
                    help_uri=(info.get("reference") or [""])[0]
                    if isinstance(info.get("reference"), list)
                    else "",
                    tags=[str(t) for t in (info.get("tags") or [])][:6],
                    rule_id=str(ev.get("template-id") or info.get("name")),
                )
            )
        return out

    # Intrusive/fuzz template tags run only when the operator authorized active testing (--active);
    # denial-of-service templates are never run, even with --active (Tier-3 destructive).
    _EXCLUDE_TAGS_PASSIVE = ("intrusive", "dos", "fuzz")
    _EXCLUDE_TAGS_ACTIVE = ("dos",)

    def rate_limit(self) -> int:
        """Requests/second derived from the scope: ``max_requests_per_host_per_min / 60`` (>= 1)."""
        limits = getattr(self.scope, "limits", None)
        per_min = getattr(limits, "max_requests_per_host_per_min", None) or 120
        try:
            return max(1, int(per_min) // 60)
        except (TypeError, ValueError):
            return 2

    def build_argv(self, target_url) -> list:
        """The nuclei command line, constrained by scope (C-9).

        * ``-ni`` — disable the interactsh/OAST client (no external callback server);
        * ``-rl <rate>`` — cap requests/second from the engagement limits (:meth:`rate_limit`);
        * ``-etags`` — exclude intrusive/dos/fuzz templates unless ``active`` (dos always excluded);
        * ``-dr`` — never follow redirects (so a redirect cannot carry the scan off-host);
        * excluded paths — nuclei has no per-path allow/deny for a single ``-u`` target, so each
          scoped exclusion is documented in docs/EXTERNAL_TOOLS.md and surfaced via
          :meth:`excluded_paths` for the integration pass (it narrows ``-u``/seeds upstream).
        """
        argv = [
            self.resolved_binary(),
            "-u",
            target_url,
            "-jsonl",
            "-silent",
            "-disable-update-check",
            "-ni",
            "-dr",
            "-rl",
            str(self.rate_limit()),
        ]
        tags = self._EXCLUDE_TAGS_ACTIVE if self.active else self._EXCLUDE_TAGS_PASSIVE
        if tags:
            argv += ["-etags", ",".join(tags)]
        argv += list(self.extra_args)
        return argv

    def excluded_paths(self) -> list:
        """Scope path-exclusions nuclei cannot enforce itself (documented; for the integration pass)."""
        return list(getattr(self.scope, "paths_exclude", None) or [])

    def run(self, appmodel, target_url, application) -> list:
        r = self._exec(self.build_argv(target_url))
        return self._parse(r.stdout, application, target_url)


class NmapAdapter(ScannerAdapter):
    name = "nmap"
    binary = "nmap"
    category = "network"
    network = True
    install_hint = "install nmap (apt/brew/choco install nmap)"
    help_uri = "https://nmap.org"

    def _parse(self, xml_text: str, application, target_url) -> list:
        out = []
        try:
            root = ET.fromstring(xml_text)
        except ET.ParseError:
            return out
        for host in root.findall("host"):
            for port in host.findall("./ports/port"):
                state = port.find("state")
                if state is None or state.get("state") != "open":
                    continue
                svc = port.find("service")
                portid = port.get("portid")
                name = svc.get("name", "") if svc is not None else ""
                product = (
                    " ".join(x for x in [svc.get("product", ""), svc.get("version", "")] if x)
                    if svc is not None
                    else ""
                )
                desc = f"Open port {portid}/{port.get('protocol', 'tcp')} — {name} {product}".strip()
                out.append(
                    self._external_finding(
                        engagement_id="",
                        application=application,
                        target_url=target_url,
                        title=f"[nmap] open port {portid} ({name or 'unknown'})",
                        severity="info",
                        vuln_class="exposed-service",
                        cwe=[],
                        description=desc,
                        endpoint_url=target_url,
                        tags=["port", name] if name else ["port"],
                        rule_id=f"port-{portid}",
                    )
                )
        return out

    def run(self, appmodel, target_url, application) -> list:
        u = urlparse(target_url)
        host = u.hostname or "127.0.0.1"
        port = u.port or (443 if u.scheme == "https" else 80)
        r = self._exec(
            [self.resolved_binary(), "-sV", "-Pn", "-p", str(port), "-oX", "-", host, *self.extra_args]
        )
        return self._parse(r.stdout, application, target_url)


class _SarifRepoAdapter(ScannerAdapter):
    """Shared base for source-side tools that emit SARIF over a repo path."""

    def _cmd(self, repo) -> list:
        raise NotImplementedError

    def run(self, appmodel, target_url, application) -> list:
        if not self.repo:
            return []
        r = self._exec(self._cmd(self.repo))
        try:
            sarif = json.loads(r.stdout)
        except json.JSONDecodeError:
            return []
        return sarif_to_findings(self, sarif, application, target_url)


class SemgrepAdapter(_SarifRepoAdapter):
    name = "semgrep"
    binary = "semgrep"
    category = "sast"
    network = False
    install_hint = (
        "pip install semgrep AND set RAMPART_SEMGREP_CONFIG to a local rules path/pack "
        "(prefer Opengrep — Semgrep registry rules are not OSS since 2024)"
    )
    help_uri = "https://semgrep.dev"

    def _config(self):
        """The configured ruleset, or ``None`` when none is provided (C-16).

        There is intentionally NO default: ``--config p/default`` and ``--config auto`` both fetch
        from Semgrep's registry over the network (and the registry rules are non-OSS since 2024-12),
        which contradicts an 'offline SAST' promise. A ruleset must be opted into explicitly via
        ``RAMPART_SEMGREP_CONFIG`` (a local path, a local pack, or e.g. ``p/ci`` if the operator
        accepts the network fetch)."""
        import os

        return os.environ.get("RAMPART_SEMGREP_CONFIG") or None

    def skip_reason(self) -> str:
        if not self._config():
            return (
                "semgrep: skipped — set RAMPART_SEMGREP_CONFIG to a local rules path/pack. "
                "(No default is used: '--config p/default'/'auto' fetch non-OSS registry rules over "
                "the network. Prefer the Opengrep adapter for offline SAST.)"
            )
        return ""

    def uses_network(self) -> bool:
        # A local file/dir config is offline; a registry pack (p/…, r/…, auto) fetches rules.
        cfg = self._config() or ""
        import os

        if cfg and (os.path.sep in cfg or os.path.exists(cfg)):
            return False
        return bool(cfg)

    def _cmd(self, repo):
        config = self._config()
        if not config:  # defensive: supervisor should have skipped via skip_reason()
            return []
        return [self.resolved_binary(), "scan", "--config", config, "--sarif", "-q", repo, *self.extra_args]

    def run(self, appmodel, target_url, application) -> list:
        if not self._config():
            return []  # no config => do not shell semgrep (see skip_reason)
        return super().run(appmodel, target_url, application)


class OpengrepAdapter(_SarifRepoAdapter):
    name = "opengrep"
    binary = "opengrep"
    category = "sast"
    network = False
    install_hint = "install Opengrep (LGPL engine+rules, OSS) from https://github.com/opengrep/opengrep"
    help_uri = "https://opengrep.dev"

    def _cmd(self, repo):
        import os

        config = os.environ.get("RAMPART_OPENGREP_CONFIG", "auto")
        return [self.resolved_binary(), "scan", "--config", config, "--sarif", "-q", repo, *self.extra_args]


class BanditAdapter(_SarifRepoAdapter):
    name = "bandit"
    binary = "bandit"
    category = "sast"
    network = False
    install_hint = "pip install bandit (Python SAST)"
    help_uri = "https://bandit.readthedocs.io"

    def _cmd(self, repo):
        return [self.resolved_binary(), "-r", repo, "-f", "sarif", "-q", *self.extra_args]


class GitleaksAdapter(_SarifRepoAdapter):
    name = "gitleaks"
    binary = "gitleaks"
    category = "sca"
    network = False
    install_hint = "install gitleaks (secret scanning) from https://github.com/gitleaks/gitleaks"
    help_uri = "https://gitleaks.io"

    def _cmd(self, repo, report_path="/dev/stdout"):
        return [
            self.resolved_binary(),
            "detect",
            "--source",
            repo,
            "--no-git",
            "--report-format",
            "sarif",
            "--report-path",
            report_path,
            "--redact",
            *self.extra_args,
        ]

    def run(self, appmodel, target_url, application) -> list:
        """Write the SARIF report to a temp FILE and read it back (C-17).

        ``--report-path /dev/stdout`` does not exist on Windows (gitleaks fails to open it), so we
        hand gitleaks a real temp path and parse the file afterwards. gitleaks also exits non-zero
        when leaks are found, so the report is read regardless of the return code."""
        if not self.repo:
            return []
        import os
        import tempfile

        fd, report = tempfile.mkstemp(prefix="rampart-gitleaks-", suffix=".sarif")
        os.close(fd)
        try:
            self._exec(self._cmd(self.repo, report))
            try:
                with open(report, encoding="utf-8", errors="replace") as fh:
                    sarif = json.loads(fh.read() or "{}")
            except (OSError, json.JSONDecodeError):
                return []
            return sarif_to_findings(self, sarif, application, target_url)
        finally:
            try:
                os.unlink(report)
            except OSError:
                pass


class TrivyAdapter(_SarifRepoAdapter):
    name = "trivy"
    binary = "trivy"
    category = "sca"
    network = False
    install_hint = "install trivy (brew/apt/choco install trivy)"
    help_uri = "https://trivy.dev"

    def _cmd(self, repo):
        return [self.resolved_binary(), "fs", "--format", "sarif", "--quiet", repo, *self.extra_args]


class TestsslAdapter(ScannerAdapter):
    name = "testssl"
    binary = "testssl.sh"
    category = "tls"
    network = True
    install_hint = "clone https://github.com/drwetter/testssl.sh (bash; https targets only)"
    help_uri = "https://testssl.sh"

    def _parse(self, raw: str, application, target_url) -> list:
        out = []
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return out
        rows = data if isinstance(data, list) else data.get("scanResult", [])
        for row in rows if isinstance(rows, list) else []:
            sev = str(row.get("severity", "INFO")).lower()
            if sev in ("ok", "info", "debug", "warn"):
                continue
            sev = {"critical": "critical", "high": "high", "medium": "medium", "low": "low"}.get(sev, "low")
            out.append(
                self._external_finding(
                    engagement_id="",
                    application=application,
                    target_url=target_url,
                    title=f"[testssl] {row.get('id', 'tls-issue')}",
                    severity=sev,
                    vuln_class="tls-misconfiguration",
                    cwe=["CWE-326"],
                    description=row.get("finding", ""),
                    endpoint_url=target_url,
                    tags=["tls"],
                    rule_id=str(row.get("id")),
                )
            )
        return out

    def run(self, appmodel, target_url, application) -> list:
        if urlparse(target_url).scheme != "https":
            return []  # TLS checks only apply to https targets
        u = urlparse(target_url)
        hostport = f"{u.hostname}:{u.port or 443}"
        r = self._exec([self.resolved_binary(), "--jsonfile", "-", "--quiet", "--color", "0", hostport])
        return self._parse(r.stdout, application, target_url)
