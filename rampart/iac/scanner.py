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

from ..schemas.finding import AffectedCode, Finding, Remediation, Reproduction, State, Verification
from ..util import now_iso

_SKIP_DIRS = {".git", "__pycache__", "node_modules", ".venv", "venv", ".rampart", "dist", "build"}

# ---------------------------------------------------------------------------- line checks
# Each entry: (compiled_regex, cwe, severity, vuln_class, title, description, remediation)

_TF_LINE = [
    (
        re.compile(r'(?i)\bacl\s*=\s*"(public-read|public-read-write)"'),
        "CWE-284",
        "high",
        "iac-tf-s3-public-acl",
        "S3 bucket ACL grants public access",
        "An S3 bucket ACL is set to a public-read / public-read-write value, exposing object "
        "data to anyone on the internet.",
        'Set the ACL to "private" and enforce S3 Block Public Access at the account/bucket level.',
    ),
    (
        re.compile(r"(?i)\b(encrypted|encryption|storage_encrypted)\s*=\s*false\b"),
        "CWE-311",
        "medium",
        "iac-tf-encryption-disabled",
        "Storage encryption explicitly disabled",
        "A storage resource sets a known encryption attribute to false, leaving data unencrypted at rest.",
        "Enable encryption at rest (set the encryption attribute to true and supply a KMS key "
        "where supported).",
    ),
]

_TF_OPEN_SG = (
    re.compile(r"(?i)\bcidr_blocks\s*=\s*\[[^\]]*0\.0\.0\.0/0"),
    "CWE-284",
    "high",
    "iac-tf-open-security-group",
    "Security group ingress open to 0.0.0.0/0",
    "A security group ingress rule allows traffic from 0.0.0.0/0 (the entire internet).",
    "Restrict ingress cidr_blocks to specific trusted CIDR ranges; never expose "
    "administrative ports to 0.0.0.0/0.",
)

_CFN_LINE = [
    (
        re.compile(r'(?i)"?accesscontrol"?\s*[:=]\s*"?(public-?read-?write|public-?read)"?'),
        "CWE-284",
        "high",
        "iac-cfn-public-acl",
        "CloudFormation resource grants public-read access",
        "A CloudFormation resource sets AccessControl to a public-read value, exposing data publicly.",
        "Use a private AccessControl value and enable S3 Block Public Access.",
    ),
    (
        re.compile(r"0\.0\.0\.0/0"),
        "CWE-284",
        "high",
        "iac-cfn-open-security-group",
        "Security group / ingress open to 0.0.0.0/0",
        "A CloudFormation ingress rule allows traffic from 0.0.0.0/0 (the entire internet).",
        "Restrict CidrIp to specific trusted ranges; do not expose management ports to 0.0.0.0/0.",
    ),
    (
        re.compile(r'(?i)"?(encryption|encrypted)"?\s*:\s*"?false"?'),
        "CWE-311",
        "medium",
        "iac-cfn-encryption-disabled",
        "Encryption explicitly disabled",
        "A CloudFormation property sets Encryption/Encrypted to false, leaving data unencrypted at rest.",
        "Set Encryption/Encrypted to true and configure a KMS key where supported.",
    ),
]

_K8S_LINE = [
    (
        re.compile(r"(?i)\bprivileged\s*:\s*true\b"),
        "CWE-250",
        "high",
        "iac-k8s-privileged-container",
        "Privileged container (privileged: true)",
        "A container runs with privileged: true, granting near-root access to the host kernel and devices.",
        "Remove privileged: true; drop all capabilities and add back only the minimum required.",
    ),
    (
        re.compile(r"(?i)\bhostNetwork\s*:\s*true\b"),
        "CWE-250",
        "medium",
        "iac-k8s-host-network",
        "Pod uses the host network (hostNetwork: true)",
        "A pod sets hostNetwork: true, sharing the node's network namespace and bypassing network policy.",
        "Set hostNetwork: false unless strictly required; isolate workloads with NetworkPolicies.",
    ),
    (
        re.compile(r"(?i)\brunAsNonRoot\s*:\s*false\b"),
        "CWE-250",
        "medium",
        "iac-k8s-run-as-root",
        "Container allowed to run as root (runAsNonRoot: false)",
        "A securityContext sets runAsNonRoot: false, permitting the container to run as UID 0.",
        "Set runAsNonRoot: true and specify a non-zero runAsUser.",
    ),
    (
        re.compile(r'(?i)\bimage\s*:\s*["\']?[\w./@-]+:latest\b'),
        "CWE-1104",
        "medium",
        "iac-k8s-latest-image-tag",
        "Container image pinned to the :latest tag",
        "A container uses the :latest image tag, which is mutable and not reproducible.",
        "Pin images to an immutable tag or digest (e.g. image@sha256:...).",
    ),
]

_DOCKER_LATEST = (
    re.compile(r"(?i)^\s*FROM\s+\S+:latest\b"),
    "CWE-1104",
    "medium",
    "iac-docker-latest-base-image",
    "Base image pinned to the :latest tag",
    "A Dockerfile FROM uses the :latest tag, which is mutable and breaks reproducible builds.",
    "Pin the base image to an explicit version or digest (FROM image@sha256:...).",
)

_DOCKER_LINE = [
    (
        re.compile(r"(?i)\b(curl|wget)\b[^\n|]*\|\s*(sh|bash)\b"),
        "CWE-494",
        "high",
        "iac-docker-remote-pipe-shell",
        "Remote script piped directly into a shell",
        "A RUN step downloads a script with curl/wget and pipes it straight into sh/bash with no "
        "integrity check — a supply-chain / remote-code-execution risk.",
        "Download to a file, verify a checksum/signature, then execute; never pipe network "
        "content into a shell.",
    ),
    (
        re.compile(r"(?i)^\s*ADD\s+https?://"),
        "CWE-494",
        "medium",
        "iac-docker-add-remote-url",
        "ADD fetches a remote URL",
        "A Dockerfile ADD pulls content from a remote URL without integrity verification.",
        "Use a pinned package manager or COPY a verified local artifact; avoid ADD <url>.",
    ),
]

# Wildcard IAM: matches HCL (Action = "*"), JSON ("Action": "*"), YAML ('*') and list forms (["*"]).
_ACTION_WILD = re.compile(
    r"""(?i)(?<![A-Za-z])["']?actions?["']?\s*[:=]\s*(\[\s*["']?\*["']?\s*\]|["']\*["'])"""
)
_RESOURCE_WILD = re.compile(
    r"""(?i)(?<![A-Za-z])["']?resources?["']?\s*[:=]\s*(\[\s*["']?\*["']?\s*\]|["']\*["'])"""
)

_K8S_KIND = re.compile(
    r"(?m)^\s*kind\s*:\s*[\"']?(Pod|Deployment|DaemonSet|StatefulSet|ReplicaSet|ReplicationController|Job|CronJob)\b"
)
# CloudFormation: a top-level (column-0, case-sensitive) Resources key with AWS:: resource types,
# or the template-format marker. A Helm values.yaml / CI workflow with a lowercase `resources:`
# key is NOT CloudFormation.
_CFN_RESOURCES = re.compile(r"(?m)^Resources\s*:")
_CFN_FORMAT = re.compile(r"(?m)^[\"']?AWSTemplateFormatVersion[\"']?\s*:")
_CFN_AWS_TYPE = re.compile(r"""(?m)^\s*["']?Type["']?\s*:\s*["']?AWS::""")


def _classify(path: str, content: str) -> str | None:
    """Return the template kind for a candidate file, or None if it is not IaC we scan."""
    name = os.path.basename(path).lower()
    ext = os.path.splitext(name)[1]
    if name in ("dockerfile", "containerfile") or name.startswith("dockerfile.") or ext == ".dockerfile":
        return "docker"
    if ext == ".tf":
        return "terraform"
    if ext in (".yaml", ".yml"):
        if _K8S_KIND.search(content):
            return "k8s"
        if _CFN_FORMAT.search(content) or (_CFN_RESOURCES.search(content) and _CFN_AWS_TYPE.search(content)):
            return "cfn"
        return None
    if ext == ".json":
        if '"AWSTemplateFormatVersion"' in content or ('"Resources"' in content and '"AWS::' in content):
            return "cfn"
        return None
    return None


def _finding(
    engagement_id: str,
    repo: str,
    rel: str,
    lineno: int,
    line: str,
    cwe: str,
    sev: str,
    klass: str,
    title: str,
    desc: str,
    rem: str,
) -> Finding:
    snippet = line.strip()[:600]
    cwe_num = cwe.split("-")[1]
    return Finding(
        engagement_id=engagement_id,
        title=f"{title} ({rel}:{lineno})",
        vuln_class=klass,
        severity=sev,
        confidence="firm",
        state=State.EVIDENCE_FOUND,
        cwe=[cwe],
        owasp={"web_2021": ["A05:2021-Security Misconfiguration"]},
        asset={"type": "iac", "application": "", "environment": "authorized", "target": repo},
        description=desc,
        root_cause="Detected by static analysis of an infrastructure-as-code template "
        "(dangerous literal / misconfiguration).",
        affected_code=AffectedCode(
            detected_by="rampart-iac",
            repo=repo,
            file=rel,
            start_line=lineno,
            end_line=lineno,
            snippet=snippet,
        ),
        reproduction=Reproduction(
            prerequisites=["IaC / source access"], steps=[f"Inspect {rel}:{lineno}"], deterministic=True
        ),
        remediation=Remediation(summary=rem, type="config_change", guidance=rem, effort="low"),
        references=[f"https://cwe.mitre.org/data/definitions/{cwe_num}.html"],
        compliance_control_refs=["SOC2:CC6.1"],
        dedupe_key=f"iac:{rel}:{lineno}:{cwe}:{klass}",
        tags=["iac", "white-box", "static"],
        verification=Verification(
            method="iac-static",
            validated=False,
            validated_at=now_iso(),
            validator="iac-scanner",
            independent_reproduction=False,
            reproductions=0,
            false_positive_checks=[
                "static IaC literal match — not "
                "runtime-proven; confirm the resource "
                "is deployed/reachable and intended"
            ],
            confidence_score=0.5,
        ),
    )


# ------------------------------------------------------------------------- comment stripping
def _strip_comments(lines: list[str], kind: str) -> list[str]:
    """Same-length list of lines with comments blanked (so line numbers stay aligned).

    Terraform: ``#`` / ``//`` line + trailing comments and ``/* … */`` blocks. YAML / Dockerfile:
    ``#`` comments (outside quotes). JSON has no comments.
    """
    if kind == "cfn-json":
        return list(lines)
    out = []
    in_block = False
    for line in lines:
        buf = []
        i = 0
        quote = ""
        n = len(line)
        while i < n:
            ch = line[i]
            if in_block:
                if line.startswith("*/", i):
                    in_block = False
                    i += 2
                else:
                    i += 1
                continue
            if quote:
                buf.append(ch)
                if ch == "\\" and i + 1 < n:
                    buf.append(line[i + 1])
                    i += 2
                    continue
                if ch == quote:
                    quote = ""
                i += 1
                continue
            if ch in "\"'" and (kind != "terraform" or ch == '"'):
                quote = ch
                buf.append(ch)
                i += 1
                continue
            is_hash_comment = ch == "#" and (
                kind in ("terraform", "docker") or i == 0 or line[i - 1].isspace()
            )
            if is_hash_comment and (kind != "docker" or not "".join(buf).strip()):
                break  # (Dockerfile comments are full-line only)
            if kind == "terraform" and line.startswith("//", i):
                break
            if kind == "terraform" and line.startswith("/*", i):
                in_block = True
                i += 2
                continue
            buf.append(ch)
            i += 1
        out.append("".join(buf))
    return out


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


# --------------------------------------------------------------------------------- Terraform
_TF_BLOCK_OPEN = re.compile(r'^\s*([A-Za-z_][\w-]*)\s*((?:"[^"]*"\s*)*)\{')
_TF_OPEN_CIDR = re.compile(r"(?i)\b(?:ipv6_)?cidr_blocks\s*=\s*\[")
_TF_OPEN_CIDR_SINGLE = re.compile(r'(?i)\bcidr_ipv[46]\s*=\s*"(0\.0\.0\.0/0|::/0)"')
_OPEN_WORLD = re.compile(r"0\.0\.0\.0/0|::/0")


def _tf_contexts(code: list[str]):
    """Per-line block-name stack for HCL (e.g. ['resource', 'ingress']) plus, per line, the label
    of the enclosing top-level resource type and its full block text."""
    stack: list[str] = []
    ctx: list[tuple] = []
    top_start = None
    top_type = ""
    tops: dict[int, list[int]] = {}
    for i, line in enumerate(code):
        if not stack:
            m = _TF_BLOCK_OPEN.match(line)
            labels = re.findall(r'"([^"]*)"', m.group(2)) if m else []
            top_type = labels[0] if m and m.group(1) == "resource" and labels else ""
            top_start = i
        ctx.append((tuple(stack), top_type, top_start))
        tops.setdefault(top_start, []).append(i)
        opener = _TF_BLOCK_OPEN.match(line)
        net = line.count("{") - line.count("}")
        if net > 0:
            stack.append(opener.group(1) if opener else "{")
            stack.extend(["{"] * (net - 1))
        elif net < 0:
            del stack[len(stack) + net :]
        if not stack:
            top_start = None
    # include the opener line's own name for lines inside it
    full = []
    for i, (st, ttype, tstart) in enumerate(ctx):
        opener = _TF_BLOCK_OPEN.match(code[i])
        names = st + ((opener.group(1),) if opener else ())
        block_text = "\n".join(code[j] for j in tops.get(tstart, [])) if tstart is not None else ""
        full.append((names, ttype, block_text))
    return full


def _tf_is_egress(names, ttype: str, block_text: str) -> bool:
    if "egress" in names:
        return True
    if ttype in ("aws_vpc_security_group_egress_rule",):
        return True
    return ttype == "aws_security_group_rule" and bool(re.search(r'(?m)^\s*type\s*=\s*"egress"', block_text))


def _scan_terraform(engagement_id, repo, rel, lines, code) -> list[Finding]:
    out: list[Finding] = []
    ctx = _tf_contexts(code)
    for i, line in enumerate(code):
        if not line.strip():
            continue
        names, ttype, block_text = ctx[i]
        for rx, cwe, sev, klass, title, desc, rem in _TF_LINE:
            if klass == "iac-tf-open-security-group":
                continue  # handled below with list/egress awareness
            if rx.search(line):
                out.append(
                    _finding(engagement_id, repo, rel, i + 1, lines[i], cwe, sev, klass, title, desc, rem)
                )
        open_hit = False
        if _TF_OPEN_CIDR.search(line):
            # gather a (possibly multi-line) list literal up to its closing bracket
            text, depth = "", 0
            for j in range(i, min(len(code), i + 200)):
                seg = code[j] if j > i else code[j][_TF_OPEN_CIDR.search(code[j]).end() - 1 :]
                text += seg + "\n"
                depth += seg.count("[") - seg.count("]")
                if depth <= 0:
                    break
            open_hit = bool(_OPEN_WORLD.search(text))
        elif _TF_OPEN_CIDR_SINGLE.search(line):
            open_hit = True
        if open_hit and not _tf_is_egress(names, ttype, block_text):
            rx, cwe, sev, klass, title, desc, rem = _TF_OPEN_SG
            out.append(_finding(engagement_id, repo, rel, i + 1, lines[i], cwe, sev, klass, title, desc, rem))
    out.extend(_iam_wildcard(engagement_id, repo, rel, lines, code))
    return out


# ----------------------------------------------------------------------------- CloudFormation
_CFN_CIDR_OPEN = re.compile(r"""(?i)["']?CidrIp(?:v6)?["']?\s*:\s*["']?(0\.0\.0\.0/0|::/0)\b""")


def _cfn_ancestors(code: list[str], idx: int) -> list[int]:
    """Indices of the structural ancestors (by indentation) of line ``idx``, nearest first."""
    out = []
    cur = _indent(code[idx])
    for j in range(idx - 1, -1, -1):
        s = code[j]
        if not s.strip():
            continue
        ind = _indent(s)
        if ind < cur:
            out.append(j)
            cur = ind
            if ind == 0:
                break
    return out


def _cfn_is_egress(code: list[str], idx: int) -> bool:
    anc = _cfn_ancestors(code, idx)
    for j in anc:
        key = code[j].strip().lstrip("-").strip().strip('"').lower()
        if "egress" in key.split(":", 1)[0]:
            return True
        if "ingress" in key.split(":", 1)[0]:
            return False
    # the enclosing resource: the ancestor whose parent is the Resources key
    for k, j in enumerate(anc):
        if code[j].strip().strip('"').startswith("Resources") and k > 0:
            res = anc[k - 1]
            rind = _indent(code[res])
            for t in range(res + 1, len(code)):
                if code[t].strip() and _indent(code[t]) <= rind:
                    break
                if re.search(r"""["']?Type["']?\s*:\s*["']?AWS::EC2::SecurityGroupEgress""", code[t]):
                    return True
            break
    return False


def _scan_cfn(engagement_id, repo, rel, lines, code) -> list[Finding]:
    out: list[Finding] = []
    for i, line in enumerate(code):
        if not line.strip():
            continue
        for rx, cwe, sev, klass, title, desc, rem in _CFN_LINE:
            if klass == "iac-cfn-open-security-group":
                if _CFN_CIDR_OPEN.search(line) and not _cfn_is_egress(code, i):
                    out.append(
                        _finding(engagement_id, repo, rel, i + 1, lines[i], cwe, sev, klass, title, desc, rem)
                    )
            elif rx.search(line):
                out.append(
                    _finding(engagement_id, repo, rel, i + 1, lines[i], cwe, sev, klass, title, desc, rem)
                )
    out.extend(_iam_wildcard(engagement_id, repo, rel, lines, code))
    return out


# ------------------------------------------------------------------------------------- IAM
_EFFECT_DENY = re.compile(r"""(?i)["']?effect["']?\s*[:=]\s*["']?deny\b""")


def _brace_span(text: str, pos: int) -> tuple[int, int] | None:
    """Span of the innermost {...} object enclosing ``pos`` in ``text`` (None if not enclosed)."""
    depth = 0
    start = None
    for k in range(pos - 1, -1, -1):
        c = text[k]
        if c == "}":
            depth += 1
        elif c == "{":
            if depth == 0:
                start = k
                break
            depth -= 1
    if start is None:
        return None
    depth = 0
    for k in range(start, len(text)):
        c = text[k]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return start, k + 1
    return start, len(text)


def _yaml_item_span(code: list[str], idx: int) -> tuple[int, int]:
    """Line span [start, end) of the YAML list item (``- Effect: …``) or mapping that contains line
    ``idx`` — i.e. one policy statement."""
    ind = _indent(code[idx])
    start, item_ind, is_item = idx, ind, False
    for j in range(idx, -1, -1):
        s = code[j]
        if not s.strip():
            continue
        if s.lstrip().startswith("- ") and _indent(s) <= ind:
            start, item_ind, is_item = j, _indent(s), True
            break
        if _indent(s) < ind:
            start = j + 1  # parent key: the statement is a plain mapping below it
            break
        start = j
    end = idx + 1
    for j in range(idx + 1, len(code)):
        s = code[j]
        if not s.strip():
            continue
        if (is_item and _indent(s) <= item_ind) or (not is_item and _indent(s) < ind):
            break
        end = j + 1
    return start, end


def _iam_wildcard(engagement_id, repo, rel, lines, code) -> list[Finding]:
    """Flag each policy STATEMENT that allows a wildcard Action on a wildcard Resource. Statements
    with ``Effect: Deny`` (or a scoped Resource) are not flagged; evaluation is per statement, not
    per file."""
    out: list[Finding] = []
    text = "\n".join(code)
    offsets = [0]
    for ln in code:
        offsets.append(offsets[-1] + len(ln) + 1)
    seen_spans = set()
    for m in _ACTION_WILD.finditer(text):
        line_idx = text.count("\n", 0, m.start())
        span = _brace_span(text, m.start())
        if span is not None:
            stmt = text[span[0] : span[1]]
        else:
            s, e = _yaml_item_span(code, line_idx)
            span = (offsets[s], offsets[e])
            stmt = "\n".join(code[s:e])
        if span in seen_spans:
            continue
        seen_spans.add(span)
        if not _RESOURCE_WILD.search(stmt) or _EFFECT_DENY.search(stmt):
            continue
        out.append(
            _finding(
                engagement_id,
                repo,
                rel,
                line_idx + 1,
                lines[line_idx],
                "CWE-269",
                "high",
                "iac-iam-wildcard-policy",
                "IAM policy grants wildcard Action on wildcard Resource",
                'An IAM policy statement allows Action "*" on Resource "*", '
                "granting unrestricted privileges (privilege escalation risk).",
                "Scope the policy to the specific actions and resource ARNs required "
                "(principle of least privilege).",
            )
        )
    return out


# -------------------------------------------------------------------------------- Dockerfile
_FROM = re.compile(r"(?i)^\s*FROM\s+(?:--\S+\s+)*(\S+)(?:\s+AS\s+(\S+))?")
_USER = re.compile(r"(?i)^\s*USER\s+(\S+)")
_ROOT_USERS = re.compile(r"^(root|0)(:.*)?$", re.IGNORECASE)


def _scan_docker(engagement_id, repo, rel, lines, code) -> list[Finding]:
    out: list[Finding] = []
    aliases: set[str] = set()
    from_lines: list[int] = []
    for i, line in enumerate(code):
        if not line.strip():
            continue
        fm = _FROM.match(line)
        if fm:
            from_lines.append(i)
            image = fm.group(1)
            if fm.group(2):
                aliases.add(fm.group(2).lower())
            last_seg = image.rsplit("/", 1)[-1]
            untagged = (
                "@" not in image
                and ":" not in last_seg
                and image.lower() not in aliases
                and image.lower() != "scratch"
                and "$" not in image
            )
            if image.lower().endswith(":latest") or untagged:
                rx, cwe, sev, klass, title, desc, rem = _DOCKER_LATEST
                if untagged:
                    title = "Base image has no tag (implicit :latest)"
                    desc = "A Dockerfile FROM names an image without a tag or digest, which resolves to the mutable :latest tag."
                out.append(
                    _finding(engagement_id, repo, rel, i + 1, lines[i], cwe, sev, klass, title, desc, rem)
                )
        for rx, cwe, sev, klass, title, desc, rem in _DOCKER_LINE:
            if rx.search(line):
                out.append(
                    _finding(engagement_id, repo, rel, i + 1, lines[i], cwe, sev, klass, title, desc, rem)
                )
    if not from_lines:
        return out
    # Only the FINAL stage's user matters at runtime: its last USER instruction (if any).
    final = from_lines[-1]
    last_user = None
    for i in range(final, len(code)):
        um = _USER.match(code[i])
        if um:
            last_user = (i, um.group(1))
    if last_user is None:
        out.append(
            _finding(
                engagement_id,
                repo,
                rel,
                final + 1,
                lines[final],
                "CWE-250",
                "medium",
                "iac-docker-no-user",
                "Container runs as root (no USER instruction)",
                "The final build stage never drops privileges with a USER instruction (a USER in an "
                "earlier stage does not carry over), so the container process runs as root.",
                "Add a non-root USER (create a dedicated user and switch to it before CMD/ENTRYPOINT).",
            )
        )
    elif _ROOT_USERS.match(last_user[1].strip("\"'")):
        i = last_user[0]
        out.append(
            _finding(
                engagement_id,
                repo,
                rel,
                i + 1,
                lines[i],
                "CWE-250",
                "medium",
                "iac-docker-root-user",
                "Container explicitly runs as root (USER root)",
                "The final build stage's last USER instruction is root, so the container process runs as root.",
                "Switch to a dedicated non-root USER before CMD/ENTRYPOINT.",
            )
        )
    return out


# -------------------------------------------------------------------------------- Kubernetes
def _k8s_docs(lines: list[str]):
    """Yield (start_idx, end_idx) line spans of each YAML document (split on ``---``)."""
    start = 0
    for i, line in enumerate(lines):
        if re.match(r"^---\s*$", line):
            if i > start:
                yield start, i
            start = i + 1
    if start < len(lines):
        yield start, len(lines)


def _scan_k8s(engagement_id, repo, rel, lines, code) -> list[Finding]:
    out: list[Finding] = []
    for i, line in enumerate(code):
        if not line.strip():
            continue
        for rx, cwe, sev, klass, title, desc, rem in _K8S_LINE:
            if rx.search(line):
                out.append(
                    _finding(engagement_id, repo, rel, i + 1, lines[i], cwe, sev, klass, title, desc, rem)
                )
    for s, e in _k8s_docs(code):
        doc = "\n".join(code[s:e])
        if not _K8S_KIND.search(doc) or "securityContext" in doc:
            continue
        if not re.search(r"(?m)^\s*containers\s*:", doc):
            continue
        ln = s
        for j in range(s, e):
            if re.match(r"^\s*kind\s*:", code[j]):
                ln = j
                break
        out.append(
            _finding(
                engagement_id,
                repo,
                rel,
                ln + 1,
                lines[ln] if lines else "",
                "CWE-250",
                "medium",
                "iac-k8s-missing-securitycontext",
                "Workload defines no securityContext",
                "A Kubernetes workload defines containers but no securityContext, so pods "
                "run with permissive defaults (root, writable rootfs, full capabilities).",
                "Add a securityContext with runAsNonRoot: true, readOnlyRootFilesystem: "
                "true and drop all capabilities.",
            )
        )
    return out


def _scan_file(engagement_id, repo, rel, kind, lines, content) -> list[Finding]:
    if kind == "terraform":
        return _scan_terraform(engagement_id, repo, rel, lines, _strip_comments(lines, "terraform"))
    if kind == "cfn":
        ckind = "cfn-json" if rel.lower().endswith(".json") else "yaml"
        return _scan_cfn(engagement_id, repo, rel, lines, _strip_comments(lines, ckind))
    if kind == "k8s":
        return _scan_k8s(engagement_id, repo, rel, lines, _strip_comments(lines, "yaml"))
    if kind == "docker":
        return _scan_docker(engagement_id, repo, rel, lines, _strip_comments(lines, "docker"))
    return []


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
        dirs[:] = sorted(d for d in dirs if d not in _SKIP_DIRS)
        for fn in sorted(files):
            name = fn.lower()
            ext = os.path.splitext(name)[1]
            is_candidate = (
                ext in (".tf", ".yaml", ".yml", ".json", ".dockerfile")
                or name in ("dockerfile", "containerfile")
                or name.startswith("dockerfile.")
            )
            if not is_candidate:
                continue
            seen += 1
            if seen > max_files:
                return findings
            path = os.path.join(root, fn)
            try:
                with open(path, encoding="utf-8", errors="replace") as fh:
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
