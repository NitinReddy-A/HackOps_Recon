"""SOC 2 evidence report — maps findings to Trust Services Criteria (TSC) common criteria.

This produces *evidence of security-control effectiveness* to support a SOC 2 examination; it
is NOT an attestation (only a licensed CPA firm issues a SOC 2 report). A confirmed finding is
a control *exception*; a finding that retest flipped to Fixed is point-in-time evidence that the
control now operates effectively — the kind of before/after, operating-over-time evidence a
SOC 2 **Type 2** examination looks for (a Type 2 opinion still requires evidence across the
whole review period, which the auditor assembles).
"""

from __future__ import annotations

import re

from ..schemas.finding import State
from .mdsafe import md, md_code, md_join
from .status import is_confirmed, is_fixed, norm_severity, sev_rank, unique_by_id

# Relevant SOC 2 2017 TSC (common criteria) for application security testing.
TSC = {
    "CC6.1": "Logical access security — restrict access to data/functions to authorized users.",
    "CC6.3": "Role-based access — authorize/modify access based on roles and least privilege.",
    "CC6.6": "Boundary protection — protect against threats from outside system boundaries.",
    "CC6.7": "Restrict the transmission/movement of data to authorized users and processes.",
    "CC6.8": "Prevent/detect the introduction of unauthorized or malicious software & inputs.",
    "CC7.1": "Detect and monitor for vulnerabilities and configuration changes.",
    "CC7.2": "Monitor system components for anomalies and indicators of compromise.",
    "CC8.1": "Change management — authorize, design, test, and approve changes (remediation/retest).",
}

# vuln_class -> the primary TSC control it provides evidence for (fallback when a finding has no SOC2 ref).
_CLASS_TSC = {
    "IDOR/BOLA": "CC6.1",
    "BFLA": "CC6.3",
    "EXCESSIVE_DATA": "CC6.1",
    "SQLI": "CC6.8",
    "CMDI": "CC6.8",
    "XSS": "CC6.8",
    "PATH_TRAVERSAL": "CC6.1",
    "OPEN_REDIRECT": "CC6.6",
    "SSRF": "CC6.6",
    "LLM": "CC6.8",
    "security-misconfiguration": "CC7.1",
}


def _controls_for(f) -> set:
    out = set()
    for ref in f.compliance_control_refs:
        m = re.match(r"SOC2:(CC\d\.\d)", ref)
        if m and m.group(1) in TSC:
            out.add(m.group(1))
    if not out:
        c = _CLASS_TSC.get(f.vuln_class)
        if c:
            out.add(c)
    return out


def _sev(f) -> str:
    return norm_severity(f.severity).upper()


def soc2_report(findings, scan, scope) -> str:
    # A finding re-persisted after retest must be counted (and listed) once.
    reported = unique_by_id(f for f in findings if f.state != State.DROPPED)
    by_control: dict[str, list] = {c: [] for c in TSC}
    for f in reported:
        for c in _controls_for(f):
            by_control.setdefault(c, []).append(f)

    fixed = [f for f in reported if is_fixed(f)]
    agent = [f for f in reported if "agent-assessed" in f.tags and not is_fixed(f)]
    open_exc = [f for f in reported if is_confirmed(f) and "agent-assessed" not in f.tags]

    L = ["# SOC 2 control-effectiveness evidence", ""]
    L.append(
        f"*Engagement* **{md(scope.authorization.ticket or 'engagement')}** · "
        f"authorized by **{md(scope.authorization.authorized_by)}**"
    )
    L.append("")
    L.append(
        "> **What this is:** automated, reproducible evidence that application security controls "
        "mapped to the SOC 2 Trust Services Criteria are (or are not) operating effectively. "
        "**What this is not:** a SOC 2 report or attestation — only a licensed CPA firm issues that. "
        "A **Type 2** opinion also requires evidence spanning the full review period; the test + "
        "retest results below are inputs an auditor can rely on, not the opinion itself."
    )
    L.append("")

    # ---- control coverage summary ----
    L.append("## Control coverage summary")
    L.append("")
    L.append("| TSC | Control | Tested | Exceptions (open) | Remediated (retest) |")
    L.append("|-----|---------|-------:|------------------:|--------------------:|")
    for c in sorted(by_control):
        fs = by_control[c]
        if not fs:
            continue
        exc = len([f for f in fs if is_confirmed(f) and "agent-assessed" not in f.tags])
        rem = len([f for f in fs if is_fixed(f)])
        L.append(f"| {c} | {TSC[c]} | {len(fs)} | {exc} | {rem} |")
    L.append("")

    # ---- exceptions ----
    L.append("## Control exceptions (confirmed findings requiring remediation)")
    L.append("")
    if not open_exc:
        L.append("*No open control exceptions — no confirmed findings are currently outstanding.*")
    else:
        for f in sorted(open_exc, key=lambda f: sev_rank(f.severity)):
            ctrls = ", ".join(sorted(_controls_for(f)))
            L.append(
                f"- **[{_sev(f)}] {md(f.title)}** — TSC {ctrls} · {md_join(f.cwe)} · finding {md_code(f.id)}"
            )
            if f.remediation.summary:
                L.append(f"    - *Remediation:* {md(f.remediation.summary)}")
    L.append("")

    # ---- agent-assessed observations (reasoning-based; pending human confirmation) ----
    if agent:
        L.append("## Agent-assessed observations (pending human confirmation)")
        L.append("")
        L.append(
            "> Reasoning-based findings (e.g. business-logic abuse) the agent flagged but no "
            "deterministic oracle can prove. Treat as auditor review items, not confirmed exceptions."
        )
        for f in sorted(agent, key=lambda f: sev_rank(f.severity)):
            ctrls = ", ".join(sorted(_controls_for(f)))
            L.append(
                f"- **[{_sev(f)}] {md(f.title)}** — TSC {ctrls} · finding {md_code(f.id)} (agent-assessed)"
            )
        L.append("")

    # ---- operating effectiveness (retest / Type 2 oriented) ----
    L.append("## Operating effectiveness (retest evidence)")
    L.append("")
    if not fixed:
        L.append(
            "*No retest-confirmed remediations yet. After fixes land, run* `rampart retest` *to "
            "produce before/after evidence that each control now operates effectively.*"
        )
    else:
        for f in fixed:
            ctrls = ", ".join(sorted(_controls_for(f)))
            lr = f.verification.last_retest or {}
            L.append(
                f"- **{md(f.title)}** — TSC {ctrls}: was CONFIRMED vulnerable, now "
                f"**{md(lr.get('result', 'fixed'))}** on retest at {md(lr.get('at', ''))}. "
                "Evidence that the control is operating effectively."
            )
    L.append("")
    L.append("---")
    L.append(
        "*Generated by Rampart. Hand this, the evidence bundle, and the hash-chained audit log to "
        "your auditor as control-testing evidence.*"
    )
    return "\n".join(L)
