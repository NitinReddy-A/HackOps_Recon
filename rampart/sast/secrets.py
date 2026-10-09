"""Regex secret scanner + a light dependency inventory (SCA).

Secrets are matched with high-signal patterns (keys with recognisable shapes), not bare
keyword hits, to keep false positives low. Real dependency-CVE scanning is delegated to
adapters (pip-audit / Trivy / grype); the native inventory just flags unpinned deps.
"""

from __future__ import annotations

import logging
import os
import re

from ..schemas.finding import AffectedCode, Finding, Remediation, Reproduction, State, Verification
from ..util import now_iso

_log = logging.getLogger(__name__)

_SKIP_DIRS = {".git", "__pycache__", "node_modules", ".venv", "venv", ".rampart", "dist", "build"}
# Text formats that commonly carry credentials. Binary files are never scanned (null-byte sniff).
_SCAN_EXT = (
    ".py",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".mjs",
    ".cjs",
    ".json",
    ".yml",
    ".yaml",
    ".env",
    ".txt",
    ".ini",
    ".cfg",
    ".conf",
    ".config",
    ".toml",
    ".properties",
    ".sh",
    ".bash",
    ".zsh",
    ".ps1",
    ".rb",
    ".go",
    ".java",
    ".kt",
    ".scala",
    ".cs",
    ".php",
    ".rs",
    ".swift",
    ".tf",
    ".tfvars",
    ".xml",
    ".gradle",
    ".sql",
    ".md",
    ".pem",
    ".key",
    ".dockerfile",
)
# Extension-less (or dot-) files that are scanned by exact name.
_SCAN_NAMES = {
    "dockerfile",
    "containerfile",
    "makefile",
    "procfile",
    "jenkinsfile",
    "vagrantfile",
    ".env",
    ".npmrc",
    ".pypirc",
    ".netrc",
    ".htpasswd",
    ".git-credentials",
    ".dockercfg",
}
# Formats where an UNQUOTED value after "KEY=" / "key:" is a literal (not a variable reference).
_UNQUOTED_EXT = (".env", ".ini", ".cfg", ".conf", ".properties", ".yml", ".yaml", ".dockerfile")
_UNQUOTED_NAMES = {"dockerfile", "containerfile", ".env", ".npmrc", ".pypirc", ".netrc"}

# key identifiers: optional prefix (DB_, STRIPE_, client_ …) + a secret word + optional *_key/_token
_KEY = (
    r"(?<![A-Za-z0-9_.-])[A-Za-z0-9_.-]*?"
    r"(?:password|passwd|pwd_?hash|secret|api[_-]?key|apikey|access[_-]?token|auth[_-]?token|"
    r"private[_-]?key|access[_-]?key)"
    r"(?:[_-]?(?:key|token|value|string|str))?(?![A-Za-z0-9_])"
)
_ASSIGN = r"""['"]?\s*(?:=>|:=|[:=])\s*"""

_SECRET_PATTERNS = [
    ("AWS access key id", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("AWS secret access key", re.compile(r"(?i)aws_secret_access_key\s*[:=]\s*['\"]?[A-Za-z0-9/+]{40}")),
    ("Private key block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")),
    ("Slack token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[0-9A-Za-z]{36,}\b")),
    ("Stripe secret key", re.compile(r"\b[sr]k_live_[0-9A-Za-z]{24,}\b")),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b")),
    (
        "Generic hardcoded secret",
        re.compile(rf"(?i){_KEY}{_ASSIGN}(?P<q>['\"])(?P<val>[^'\"\s]{{8,}})(?P=q)"),
    ),
]
# Unquoted form (``DB_PASSWORD=Hunter2``, ``ENV DB_PASSWORD=x``, ``password = x`` in .ini) — only
# applied to config formats, where an unquoted value is a literal rather than a variable reference.
_GENERIC_UNQUOTED = re.compile(rf"(?i){_KEY}\s*(?:=|:)\s*(?P<val>[^\s'\"#;,${{<%!(&*][^\s'\"#;,]{{7,}})")

# Whole-token placeholder words (matched against the VALUE's tokens only, never the key name).
_PLACEHOLDER_WORDS = {
    "example",
    "examples",
    "changeme",
    "change",
    "placeholder",
    "dummy",
    "test",
    "testing",
    "sample",
    "fake",
    "demo",
    "your",
    "yours",
    "redacted",
    "replace",
    "replaceme",
    "todo",
    "fixme",
    "foobar",
    "xxx",
    "none",
    "null",
    "required",
    "optional",
}
_PLACEHOLDER_SHAPES = re.compile(r"^(?:<.*>|\$\{.*\}|\{\{.*\}\}|%\(.*\)s?|\*+|x{3,}|\.\.\.+)$", re.IGNORECASE)


def _value_tokens(value: str) -> list[str]:
    toks = []
    for chunk in re.split(r"[^A-Za-z0-9]+", value):
        # split on lower->Upper and letter<->digit boundaries: latestRelease2024 -> latest/Release/2024
        toks += re.findall(r"[A-Z]+(?=[A-Z][a-z])|[A-Z]?[a-z]+|[A-Z]+|\d+", chunk)
    return [t.lower() for t in toks]


def _is_placeholder(value: str) -> bool:
    v = value.strip().strip("'\"")
    if not v or _PLACEHOLDER_SHAPES.match(v) or v.startswith(("$", "{{", "%(", "<")):
        return True
    if "..." in v or "…" in v:  # elided / truncated example ("sk-or-...")
        return True
    toks = _value_tokens(v)
    return any(t in _PLACEHOLDER_WORDS or re.fullmatch(r"x{3,}", t) for t in toks)


def _allows_unquoted(fn: str) -> bool:
    low = fn.lower()
    return (
        low in _UNQUOTED_NAMES
        or low.endswith(_UNQUOTED_EXT)
        or low.startswith((".env.", "dockerfile."))
        or ".env." in low
    )


def _scannable(fn: str) -> bool:
    low = fn.lower()
    return (
        low.endswith(_SCAN_EXT)
        or low in _SCAN_NAMES
        or low.startswith((".env.", "dockerfile.", "containerfile."))
        or ".env." in low
    )


def _match_secret(line: str, unquoted_ok: bool):
    """Return the label of the first real (non-placeholder) secret on the line, else None."""
    for label, pat in _SECRET_PATTERNS:
        m = pat.search(line)
        if not m:
            continue
        value = m.group("val") if "val" in pat.groupindex else m.group(0)
        if not _is_placeholder(value):
            return label
    if unquoted_ok:
        m = _GENERIC_UNQUOTED.search(line)
        if m and re.search(r"\d", m.group("val")) and not _is_placeholder(m.group("val")):
            return "Generic hardcoded secret"
    return None


# Notes from the most recent scan_secrets() call (e.g. "file cap hit").
last_scan_notes: list[str] = []


def _secret_finding(engagement_id, repo, rel, lineno, label, line) -> Finding:
    return Finding(
        engagement_id=engagement_id,
        title=f"Hardcoded secret: {label} ({rel}:{lineno})",
        vuln_class="sast-hardcoded-secret",
        severity="high",
        confidence="firm",
        state=State.EVIDENCE_FOUND,
        cwe=["CWE-798"],
        owasp={"web_2025": ["A02:2025-Security Misconfiguration"]},
        asset={"type": "source", "application": "", "environment": "authorized", "target": repo},
        description=f"A {label} appears hardcoded in source.",
        root_cause="Secret committed to source instead of a secrets manager / environment.",
        affected_code=AffectedCode(
            detected_by="rampart-secret-scan",
            repo=repo,
            file=rel,
            start_line=lineno,
            end_line=lineno,
            snippet="<redacted secret on this line>",
        ),
        reproduction=Reproduction(
            prerequisites=["Source access"], steps=[f"Inspect {rel}:{lineno}"], deterministic=True
        ),
        remediation=Remediation(
            summary="Remove the secret, rotate it, and load from a secrets manager/env.",
            type="config",
            guidance="Purge from history, rotate the credential, and inject "
            "at runtime via env/secret store (CWE-798).",
            effort="medium",
        ),
        references=["https://cwe.mitre.org/data/definitions/798.html"],
        compliance_control_refs=["SOC2:CC6.1", "ISO27001:A.8.24"],
        dedupe_key=f"secret:{rel}:{lineno}:{label}",
        tags=["sast", "secret", "white-box"],
        verification=Verification(
            method="secret-regex",
            validated=False,
            validated_at=now_iso(),
            validator="secret-scan",
            reproductions=0,
            false_positive_checks=["regex match — verify it is a live credential"],
            confidence_score=0.5,
        ),
    )


def scan_secrets(repo_path: str, engagement_id: str = "", max_files: int = 4000) -> list[Finding]:
    findings = []
    last_scan_notes.clear()
    if not repo_path or not os.path.isdir(repo_path):
        return findings
    seen = 0
    for root, dirs, files in os.walk(repo_path):
        dirs[:] = sorted(d for d in dirs if d not in _SKIP_DIRS)
        for fn in sorted(files):
            if not _scannable(fn):
                continue
            seen += 1
            if seen > max_files:
                note = f"secret scan file cap reached: scanned the first {max_files} files; the rest were skipped"
                last_scan_notes.append(note)
                _log.warning(note)
                return findings
            path = os.path.join(root, fn)
            try:
                with open(path, "rb") as fh:
                    blob = fh.read(512_000)
            except OSError:
                continue
            if b"\x00" in blob[:8192]:
                continue  # binary file (image, archive, compiled object …)
            content = blob.decode("utf-8", errors="ignore")
            rel = os.path.relpath(path, repo_path).replace("\\", "/")
            unquoted_ok = _allows_unquoted(fn)
            for i, line in enumerate(content.splitlines(), 1):
                if len(line) > 1000:
                    continue
                label = _match_secret(line, unquoted_ok)
                if label:
                    findings.append(_secret_finding(engagement_id, repo_path, rel, i, label, line))
    return findings


def scan_dependencies(repo_path: str, engagement_id: str = "") -> list[Finding]:
    """Light dependency inventory: flag UNPINNED declarations (ranges, wildcards, bare names) in
    every requirements file / pyproject.toml / lockfile-less package.json — informational. Real CVE
    matching is the opt-in OSV SCA (``rampart.sca``) or the pip-audit / Trivy / grype adapters."""
    from ..sca.parsers import collect_unpinned

    findings = []
    if not repo_path or not os.path.isdir(repo_path):
        return findings
    by_manifest: dict[str, list] = {}
    for u in collect_unpinned(repo_path):
        by_manifest.setdefault(u.manifest, []).append(u)
    for manifest, items in sorted(by_manifest.items()):
        unpinned = sorted(items, key=lambda u: u.line)
        names = ", ".join(f"{u.name}{'' if u.spec == '(any)' else ' ' + u.spec}" for u in unpinned[:20])
        findings.append(
            Finding(
                engagement_id=engagement_id,
                title=f"Unpinned dependencies in {manifest} ({len(unpinned)})",
                vuln_class="sca-unpinned-dependency",
                severity="low",
                confidence="firm",
                state=State.EVIDENCE_FOUND,
                cwe=["CWE-1104"],
                owasp={"web_2025": ["A06:2021-Vulnerable and Outdated Components"]},
                asset={"type": "source", "application": "", "environment": "authorized", "target": repo_path},
                description=f"Unpinned dependencies make builds non-reproducible and can pull vulnerable versions: {names}.",
                root_cause="Dependencies are not pinned to exact versions.",
                affected_code=AffectedCode(
                    detected_by="rampart-sca",
                    repo=repo_path,
                    file=manifest,
                    start_line=max(1, unpinned[0].line),
                    end_line=max(1, unpinned[-1].line),
                    snippet=names[:300],
                ),
                reproduction=Reproduction(
                    prerequisites=["Source access"], steps=[f"Inspect {manifest}"], deterministic=True
                ),
                remediation=Remediation(
                    summary="Pin exact versions and run a CVE scanner (pip-audit/Trivy).",
                    type="config",
                    guidance="Pin each dependency to an exact version (== / exact semver) or commit a "
                    "lockfile, and add SCA to CI.",
                    effort="low",
                ),
                references=["https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/"],
                compliance_control_refs=["SOC2:CC7.1"],
                dedupe_key=f"sca-unpinned:{manifest}",
                tags=["sca", "dependencies", "white-box"],
                verification=Verification(
                    method="dependency-inventory",
                    validated=False,
                    validated_at=now_iso(),
                    validator="sca",
                    reproductions=0,
                    false_positive_checks=["informational — run a CVE scanner for actual advisories"],
                    confidence_score=0.4,
                ),
            )
        )
    return findings
