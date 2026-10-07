"""Regex secret scanner + a light dependency inventory (SCA).

Secrets are matched with high-signal patterns (keys with recognisable shapes), not bare
keyword hits, to keep false positives low. Real dependency-CVE scanning is delegated to
adapters (pip-audit / Trivy / grype); the native inventory just flags unpinned deps.
"""
from __future__ import annotations

import os
import re

from ..schemas.finding import AffectedCode, Finding, Reproduction, Remediation, State, Verification
from ..util import now_iso

_SKIP_DIRS = {".git", "__pycache__", "node_modules", ".venv", "venv", ".rampart", "dist", "build"}
_SCAN_EXT = (".py", ".js", ".ts", ".json", ".yml", ".yaml", ".env", ".txt", ".ini", ".cfg",
             ".toml", ".sh", ".rb", ".go", ".java", ".properties", "")

_SECRET_PATTERNS = [
    ("AWS access key id", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("AWS secret access key", re.compile(r"(?i)aws_secret_access_key\s*[:=]\s*['\"]?[A-Za-z0-9/+]{40}")),
    ("Private key block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")),
    ("Slack token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[0-9A-Za-z]{36,}\b")),
    ("Stripe secret key", re.compile(r"\bsk_live_[0-9A-Za-z]{24,}\b")),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b")),
    ("Generic hardcoded secret", re.compile(
        r"(?i)\b(password|passwd|secret|api[_-]?key|apikey|access[_-]?token|auth[_-]?token)\b"
        r"\s*[:=]\s*['\"][^'\"\s]{8,}['\"]")),
]
_PLACEHOLDERS = re.compile(r"(?i)(example|changeme|your[_-]?|xxx|placeholder|dummy|test|<.*>|\$\{)")


def _secret_finding(engagement_id, repo, rel, lineno, label, line) -> Finding:
    return Finding(
        engagement_id=engagement_id, title=f"Hardcoded secret: {label} ({rel}:{lineno})",
        vuln_class="sast-hardcoded-secret", severity="high", confidence="firm",
        state=State.EVIDENCE_FOUND, cwe=["CWE-798"],
        owasp={"web_2025": ["A02:2025-Security Misconfiguration"]},
        asset={"type": "source", "application": "", "environment": "authorized", "target": repo},
        description=f"A {label} appears hardcoded in source.",
        root_cause="Secret committed to source instead of a secrets manager / environment.",
        affected_code=AffectedCode(detected_by="rampart-secret-scan", repo=repo, file=rel,
                                   start_line=lineno, end_line=lineno,
                                   snippet="<redacted secret on this line>"),
        reproduction=Reproduction(prerequisites=["Source access"], steps=[f"Inspect {rel}:{lineno}"],
                                  deterministic=True),
        remediation=Remediation(summary="Remove the secret, rotate it, and load from a secrets manager/env.",
                                type="config", guidance="Purge from history, rotate the credential, and inject "
                                "at runtime via env/secret store (CWE-798).", effort="medium"),
        references=["https://cwe.mitre.org/data/definitions/798.html"],
        compliance_control_refs=["SOC2:CC6.1", "ISO27001:A.8.24"],
        dedupe_key=f"secret:{rel}:{lineno}:{label}", tags=["sast", "secret", "white-box"],
        verification=Verification(method="secret-regex", validated=False, validated_at=now_iso(),
                                  validator="secret-scan", reproductions=0,
                                  false_positive_checks=["regex match — verify it is a live credential"],
                                  confidence_score=0.5))


def scan_secrets(repo_path: str, engagement_id: str = "", max_files: int = 4000) -> list[Finding]:
    findings = []
    if not repo_path or not os.path.isdir(repo_path):
        return findings
    seen = 0
    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
        for fn in sorted(files):
            if not (fn.endswith(_SCAN_EXT) or "." not in fn):
                continue
            seen += 1
            if seen > max_files:
                return findings
            path = os.path.join(root, fn)
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                    content = fh.read(512_000)
            except OSError:
                continue
            rel = os.path.relpath(path, repo_path).replace("\\", "/")
            for i, line in enumerate(content.splitlines(), 1):
                if len(line) > 1000:
                    continue
                for label, pat in _SECRET_PATTERNS:
                    m = pat.search(line)
                    if m and not _PLACEHOLDERS.search(m.group(0)):
                        findings.append(_secret_finding(engagement_id, repo_path, rel, i, label, line))
                        break
    return findings


def scan_dependencies(repo_path: str, engagement_id: str = "") -> list[Finding]:
    """Light dependency inventory: flag UNPINNED requirements (informational). Real CVE
    scanning is delegated to the pip-audit / Trivy / grype adapters."""
    findings = []
    if not repo_path:
        return findings
    req = os.path.join(repo_path, "requirements.txt")
    if not os.path.isfile(req):
        return findings
    try:
        with open(req, "r", encoding="utf-8", errors="ignore") as fh:
            lines = fh.readlines()
    except OSError:
        return findings
    unpinned = []
    for i, ln in enumerate(lines, 1):
        s = ln.split("#", 1)[0].strip()
        if not s or s.startswith("-"):
            continue
        if not re.search(r"[=<>~!]=|@", s):
            unpinned.append((i, s))
    if unpinned:
        names = ", ".join(n for _, n in unpinned[:20])
        findings.append(Finding(
            engagement_id=engagement_id, title=f"Unpinned dependencies in requirements.txt ({len(unpinned)})",
            vuln_class="sca-unpinned-dependency", severity="low", confidence="firm",
            state=State.EVIDENCE_FOUND, cwe=["CWE-1104"],
            owasp={"web_2025": ["A06:2021-Vulnerable and Outdated Components"]},
            asset={"type": "source", "application": "", "environment": "authorized", "target": repo_path},
            description=f"Unpinned dependencies make builds non-reproducible and can pull vulnerable versions: {names}.",
            root_cause="Dependencies are not pinned to exact versions.",
            affected_code=AffectedCode(detected_by="rampart-sca", repo=repo_path, file="requirements.txt",
                                       start_line=unpinned[0][0], end_line=unpinned[-1][0], snippet=names[:300]),
            reproduction=Reproduction(prerequisites=["Source access"], steps=["Inspect requirements.txt"],
                                      deterministic=True),
            remediation=Remediation(summary="Pin exact versions and run a CVE scanner (pip-audit/Trivy).",
                                    type="config", guidance="Pin each dependency (==) and add SCA to CI.",
                                    effort="low"),
            references=["https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/"],
            compliance_control_refs=["SOC2:CC7.1"], tags=["sca", "dependencies", "white-box"],
            verification=Verification(method="dependency-inventory", validated=False, validated_at=now_iso(),
                                      validator="sca", reproductions=0,
                                      false_positive_checks=["informational — run a CVE scanner for actual advisories"],
                                      confidence_score=0.4)))
    return findings
