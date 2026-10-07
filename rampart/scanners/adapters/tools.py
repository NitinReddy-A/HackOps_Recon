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

_NUCLEI_SEV = {"critical": "critical", "high": "high", "medium": "medium",
               "low": "low", "info": "info", "unknown": "info"}


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
            for c in (classif.get("cwe-id") or []):
                cwes.append(c.upper().replace("CWE_", "CWE-") if "cwe" in c.lower() else f"CWE-{c}")
            out.append(self._external_finding(
                engagement_id="", application=application, target_url=target_url,
                title=f"[nuclei] {info.get('name', ev.get('template-id', 'match'))}",
                severity=sev, vuln_class=str(ev.get("template-id") or "nuclei"),
                cwe=cwes, description=info.get("description", "") or info.get("name", ""),
                endpoint_url=ev.get("matched-at") or ev.get("host") or target_url,
                help_uri=(info.get("reference") or [""])[0] if isinstance(info.get("reference"), list) else "",
                tags=[str(t) for t in (info.get("tags") or [])][:6],
                rule_id=str(ev.get("template-id") or info.get("name"))))
        return out

    def run(self, appmodel, target_url, application) -> list:
        r = self._exec([self.resolved_binary(), "-u", target_url, "-jsonl", "-silent",
                        "-disable-update-check", *self.extra_args])
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
                product = " ".join(x for x in [svc.get("product", ""), svc.get("version", "")]
                                   if x) if svc is not None else ""
                desc = f"Open port {portid}/{port.get('protocol','tcp')} — {name} {product}".strip()
                out.append(self._external_finding(
                    engagement_id="", application=application, target_url=target_url,
                    title=f"[nmap] open port {portid} ({name or 'unknown'})",
                    severity="info", vuln_class="exposed-service", cwe=[],
                    description=desc, endpoint_url=target_url,
                    tags=["port", name] if name else ["port"], rule_id=f"port-{portid}"))
        return out

    def run(self, appmodel, target_url, application) -> list:
        u = urlparse(target_url)
        host = u.hostname or "127.0.0.1"
        port = u.port or (443 if u.scheme == "https" else 80)
        r = self._exec([self.resolved_binary(), "-sV", "-Pn", "-p", str(port), "-oX", "-",
                        host, *self.extra_args])
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
    install_hint = "pip install semgrep (prefer Opengrep — Semgrep registry rules are not OSS since 2024)"
    help_uri = "https://semgrep.dev"

    def _cmd(self, repo):
        # NOTE: `--config auto` pulls Semgrep's registry rules (restrictive license since 2024-12)
        # and needs network. Default to a local/offline config; override via RAMPART_SEMGREP_CONFIG.
        import os
        config = os.environ.get("RAMPART_SEMGREP_CONFIG", "p/default")
        return [self.resolved_binary(), "scan", "--config", config, "--sarif", "-q", repo, *self.extra_args]


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

    def _cmd(self, repo):
        return [self.resolved_binary(), "detect", "--source", repo, "--no-git",
                "--report-format", "sarif", "--report-path", "/dev/stdout", "--redact", *self.extra_args]


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
            out.append(self._external_finding(
                engagement_id="", application=application, target_url=target_url,
                title=f"[testssl] {row.get('id', 'tls-issue')}",
                severity=sev, vuln_class="tls-misconfiguration", cwe=["CWE-326"],
                description=row.get("finding", ""), endpoint_url=target_url,
                tags=["tls"], rule_id=str(row.get("id"))))
        return out

    def run(self, appmodel, target_url, application) -> list:
        if urlparse(target_url).scheme != "https":
            return []    # TLS checks only apply to https targets
        u = urlparse(target_url)
        hostport = f"{u.hostname}:{u.port or 443}"
        r = self._exec([self.resolved_binary(), "--jsonfile", "-", "--quiet", "--color", "0", hostport])
        return self._parse(r.stdout, application, target_url)
