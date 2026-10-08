"""Native, dependency-free Infrastructure-as-Code / cloud-config scanner.

Walks a repository and applies LOW-false-positive, high-signal, line/regex-based checks to
Terraform (``*.tf``), CloudFormation / generic templates (``*.yaml|*.yml|*.json`` that look
like CFN), Kubernetes manifests (workload ``kind:``) and Dockerfiles. No third-party parser
is used (no pyyaml); detection keys on exact dangerous literals so a hit is a strong signal.

Each hit becomes a STATIC :class:`~rampart.schemas.finding.Finding`
(``confidence='firm'``, ``verification.method='iac-static'``, ``validated=False``,
``state=EvidenceFound``) carrying an ``affected_code`` file:line. These are tiered below
runtime-``confirmed`` findings and correlated by CWE, exactly like the SAST scanner.
"""
from __future__ import annotations

import os
import re

from ..schemas.finding import AffectedCode, Finding, Reproduction, Remediation, State, Verification
from ..util import now_iso

_SKIP_DIRS = {".git", "__pycache__", "node_modules", ".venv", "venv", ".rampart", "dist", "build"}

# ---------------------------------------------------------------------------- line checks
# Each entry: (compiled_regex, cwe, severity, vuln_class, title, description, remediation)

_TF_LINE = [
    (re.compile(r'(?i)\bacl\s*=\s*"(public-read|public-read-write)"'),
     "CWE-284", "high", "iac-tf-s3-public-acl",
     "S3 bucket ACL grants public access",
     "An S3 bucket ACL is set to a public-read / public-read-write value, exposing object "
     "data to anyone on the internet.",
     "Set the ACL to \"private\" and enforce S3 Block Public Access at the account/bucket level."),
    (re.compile(r'(?i)\bcidr_blocks\s*=\s*\[[^\]]*0\.0\.0\.0/0'),
     "CWE-284", "high", "iac-tf-open-security-group",
     "Security group ingress open to 0.0.0.0/0",
     "A security group ingress rule allows traffic from 0.0.0.0/0 (the entire internet).",
     "Restrict ingress cidr_blocks to specific trusted CIDR ranges; never expose "
     "administrative ports to 0.0.0.0/0."),
    (re.compile(r'(?i)\b(encrypted|encryption|storage_encrypted)\s*=\s*false\b'),
     "CWE-311", "medium", "iac-tf-encryption-disabled",
     "Storage encryption explicitly disabled",
     "A storage resource sets a known encryption attribute to false, leaving data "
     "unencrypted at rest.",
     "Enable encryption at rest (set the encryption attribute to true and supply a KMS key "
     "where supported)."),
]

_CFN_LINE = [
    (re.compile(r'(?i)"?accesscontrol"?\s*[:=]\s*"?(public-?read-?write|public-?read)"?'),
     "CWE-284", "high", "iac-cfn-public-acl",
     "CloudFormation resource grants public-read access",
     "A CloudFormation resource sets AccessControl to a public-read value, exposing data "
     "publicly.",
     "Use a private AccessControl value and enable S3 Block Public Access."),
    (re.compile(r'0\.0\.0\.0/0'),
     "CWE-284", "high", "iac-cfn-open-security-group",
     "Security group / ingress open to 0.0.0.0/0",
     "A CloudFormation ingress rule allows traffic from 0.0.0.0/0 (the entire internet).",
     "Restrict CidrIp to specific trusted ranges; do not expose management ports to 0.0.0.0/0."),
    (re.compile(r'(?i)"?(encryption|encrypted)"?\s*:\s*"?false"?'),
     "CWE-311", "medium", "iac-cfn-encryption-disabled",
     "Encryption explicitly disabled",
     "A CloudFormation property sets Encryption/Encrypted to false, leaving data "
     "unencrypted at rest.",
     "Set Encryption/Encrypted to true and configure a KMS key where supported."),
]

_K8S_LINE = [
    (re.compile(r'(?i)\bprivileged\s*:\s*true\b'),
     "CWE-250", "high", "iac-k8s-privileged-container",
     "Privileged container (privileged: true)",
     "A container runs with privileged: true, granting near-root access to the host kernel "
     "and devices.",
     "Remove privileged: true; drop all capabilities and add back only the minimum required."),
    (re.compile(r'(?i)\bhostNetwork\s*:\s*true\b'),
     "CWE-250", "medium", "iac-k8s-host-network",
     "Pod uses the host network (hostNetwork: true)",
     "A pod sets hostNetwork: true, sharing the node's network namespace and bypassing "
     "network policy.",
     "Set hostNetwork: false unless strictly required; isolate workloads with NetworkPolicies."),
    (re.compile(r'(?i)\brunAsNonRoot\s*:\s*false\b'),
     "CWE-250", "medium", "iac-k8s-run-as-root",
     "Container allowed to run as root (runAsNonRoot: false)",
     "A securityContext sets runAsNonRoot: false, permitting the container to run as UID 0.",
     "Set runAsNonRoot: true and specify a non-zero runAsUser."),
    (re.compile(r'(?i)\bimage\s*:\s*["\']?[\w./@-]+:latest\b'),
     "CWE-1104", "medium", "iac-k8s-latest-image-tag",
     "Container image pinned to the :latest tag",
     "A container uses the :latest image tag, which is mutable and not reproducible.",
     "Pin images to an immutable tag or digest (e.g. image@sha256:...)."),
]

_DOCKER_LINE = [
    (re.compile(r'(?i)^\s*FROM\s+\S+:latest\b'),
     "CWE-1104", "medium", "iac-docker-latest-base-image",
     "Base image pinned to the :latest tag",
     "A Dockerfile FROM uses the :latest tag, which is mutable and breaks reproducible builds.",
     "Pin the base image to an explicit version or digest (FROM image@sha256:...)."),
    (re.compile(r'(?i)\b(curl|wget)\b[^\n|]*\|\s*(sh|bash)\b'),
     "CWE-494", "high", "iac-docker-remote-pipe-shell",
     "Remote script piped directly into a shell",
     "A RUN step downloads a script with curl/wget and pipes it straight into sh/bash with no "
     "integrity check — a supply-chain / remote-code-execution risk.",
     "Download to a file, verify a checksum/signature, then execute; never pipe network "
     "content into a shell."),
    (re.compile(r'(?i)^\s*ADD\s+https?://'),
     "CWE-494", "medium", "iac-docker-add-remote-url",
     "ADD fetches a remote URL",
     "A Dockerfile ADD pulls content from a remote URL without integrity verification.",
     "Use a pinned package manager or COPY a verified local artifact; avoid ADD <url>."),
]

# Wildcard IAM: matches HCL (Action = "*"), JSON ("Action": "*") and list forms (["*"]).
_ACTION_WILD = re.compile(r'(?i)"?actions?"?\s*[:=]\s*(\[\s*"?\*"?\s*\]|"\*")')
_RESOURCE_WILD = re.compile(r'(?i)"?resources?"?\s*[:=]\s*(\[\s*"?\*"?\s*\]|"\*")')

_K8S_KIND = re.compile(r'(?im)^\s*kind\s*:\s*["\']?(Pod|Deployment|DaemonSet|StatefulSet)\b')
_CFN_RESOURCES = re.compile(r'(?im)^\s*Resources\s*:')


def _classify(path: str, content: str) -> str | None:
    """Return the template kind for a candidate file, or None if it is not IaC we scan."""
    name = os.path.basename(path).lower()
    ext = os.path.splitext(name)[1]
    if name == "dockerfile" or name.startswith("dockerfile.") or ext == ".dockerfile":
        return "docker"
    if ext == ".tf":
        return "terraform"
    if ext in (".yaml", ".yml"):
        if _K8S_KIND.search(content):
            return "k8s"
        if "AWSTemplateFormatVersion" in content or _CFN_RESOURCES.search(content):
            return "cfn"
        return None
    if ext == ".json":
        if "AWSTemplateFormatVersion" in content or '"Resources"' in content:
            return "cfn"
        return None
    return None


def _finding(engagement_id: str, repo: str, rel: str, lineno: int, line: str,
             cwe: str, sev: str, klass: str, title: str, desc: str, rem: str) -> Finding:
    snippet = line.strip()[:600]
    cwe_num = cwe.split("-")[1]
    return Finding(
        engagement_id=engagement_id, title=f"{title} ({rel}:{lineno})", vuln_class=klass,
        severity=sev, confidence="firm", state=State.EVIDENCE_FOUND, cwe=[cwe],
        owasp={"web_2021": ["A05:2021-Security Misconfiguration"]},
        asset={"type": "iac", "application": "", "environment": "authorized", "target": repo},
        description=desc,
        root_cause="Detected by static analysis of an infrastructure-as-code template "
                   "(dangerous literal / misconfiguration).",
        affected_code=AffectedCode(detected_by="rampart-iac", repo=repo, file=rel,
                                   start_line=lineno, end_line=lineno, snippet=snippet),
        reproduction=Reproduction(prerequisites=["IaC / source access"],
                                  steps=[f"Inspect {rel}:{lineno}"], deterministic=True),
        remediation=Remediation(summary=rem, type="config_change", guidance=rem, effort="low"),
        references=[f"https://cwe.mitre.org/data/definitions/{cwe_num}.html"],
        compliance_control_refs=["SOC2:CC6.1"],
        dedupe_key=f"iac:{rel}:{lineno}:{cwe}:{klass}",
        tags=["iac", "white-box", "static"],
        verification=Verification(method="iac-static", validated=False, validated_at=now_iso(),
                                  validator="iac-scanner", independent_reproduction=False,
                                  reproductions=0,
                                  false_positive_checks=["static IaC literal match — not "
                                                         "runtime-proven; confirm the resource "
                                                         "is deployed/reachable and intended"],
                                  confidence_score=0.5))


def _iam_wildcard(engagement_id, repo, rel, lines) -> list[Finding]:
    """Flag a policy that allows a wildcard Action on a wildcard Resource (both must be present)."""
    action_hit = None
    has_resource = False
    for i, line in enumerate(lines, start=1):
        if action_hit is None and _ACTION_WILD.search(line):
            action_hit = (i, line)
        if _RESOURCE_WILD.search(line):
            has_resource = True
    if action_hit and has_resource:
        i, line = action_hit
        return [_finding(engagement_id, repo, rel, i, line, "CWE-269", "high",
                         "iac-iam-wildcard-policy",
                         "IAM policy grants wildcard Action on wildcard Resource",
                         "An IAM policy statement allows Action \"*\" on Resource \"*\", "
                         "granting unrestricted privileges (privilege escalation risk).",
                         "Scope the policy to the specific actions and resource ARNs required "
                         "(principle of least privilege).")]
    return []


def _docker_no_user(engagement_id, repo, rel, lines, content) -> list[Finding]:
    if re.search(r'(?im)^\s*USER\s+\S+', content):
        return []
    ln = 1
    for i, line in enumerate(lines, start=1):
        if re.match(r'(?i)^\s*FROM\s+', line):
            ln = i
            break
    return [_finding(engagement_id, repo, rel, ln, lines[ln - 1] if lines else "", "CWE-250",
                     "medium", "iac-docker-no-user",
                     "Container runs as root (no USER instruction)",
                     "The Dockerfile never drops privileges with a USER instruction, so the "
                     "container process runs as root.",
                     "Add a non-root USER (create a dedicated user and switch to it before "
                     "CMD/ENTRYPOINT).")]


def _k8s_missing_securitycontext(engagement_id, repo, rel, lines, content) -> list[Finding]:
    if "securityContext" in content:
        return []
    if not re.search(r'(?im)^\s*containers\s*:', content):
        return []
    ln = 1
    for i, line in enumerate(lines, start=1):
        if re.match(r'(?i)^\s*kind\s*:', line):
            ln = i
            break
    return [_finding(engagement_id, repo, rel, ln, lines[ln - 1] if lines else "", "CWE-250",
                     "medium", "iac-k8s-missing-securitycontext",
                     "Workload defines no securityContext",
                     "A Kubernetes workload defines containers but no securityContext, so pods "
                     "run with permissive defaults (root, writable rootfs, full capabilities).",
                     "Add a securityContext with runAsNonRoot: true, readOnlyRootFilesystem: "
                     "true and drop all capabilities.")]


def _scan_file(engagement_id, repo, rel, kind, lines, content) -> list[Finding]:
    out: list[Finding] = []
    line_checks = {"terraform": _TF_LINE, "cfn": _CFN_LINE,
                   "k8s": _K8S_LINE, "docker": _DOCKER_LINE}.get(kind, [])
    for i, line in enumerate(lines, start=1):
        for rx, cwe, sev, klass, title, desc, rem in line_checks:
            if rx.search(line):
                out.append(_finding(engagement_id, repo, rel, i, line,
                                    cwe, sev, klass, title, desc, rem))
    if kind in ("terraform", "cfn"):
        out.extend(_iam_wildcard(engagement_id, repo, rel, lines))
    if kind == "docker":
        out.extend(_docker_no_user(engagement_id, repo, rel, lines, content))
    if kind == "k8s":
        out.extend(_k8s_missing_securitycontext(engagement_id, repo, rel, lines, content))
    return out


def scan_iac(repo_path: str, engagement_id: str = "", max_files: int = 4000) -> list[Finding]:
    """Walk ``repo_path`` and return static IaC/cloud-config misconfiguration findings.

    Returns ``[]`` gracefully for a missing/empty path. Each finding carries an
    ``affected_code`` file:line, ``confidence='firm'`` and ``verification.method='iac-static'``
    (never runtime-validated).
    """
    findings: list[Finding] = []
    if not repo_path or not os.path.isdir(repo_path):
        return findings
    seen = 0
    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
        for fn in sorted(files):
            name = fn.lower()
            ext = os.path.splitext(name)[1]
            is_candidate = (ext in (".tf", ".yaml", ".yml", ".json", ".dockerfile")
                            or name == "dockerfile" or name.startswith("dockerfile."))
            if not is_candidate:
                continue
            seen += 1
            if seen > max_files:
                return findings
            path = os.path.join(root, fn)
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as fh:
                    content = fh.read()
            except OSError:
                continue
            kind = _classify(path, content)
            if not kind:
                continue
            rel = os.path.relpath(path, repo_path).replace("\\", "/")
            lines = content.splitlines()
            findings.extend(_scan_file(engagement_id, repo_path, rel, kind, lines, content))
    return findings
