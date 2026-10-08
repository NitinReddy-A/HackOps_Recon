"""Map findings onto every compliance framework and render an audit-ready coverage matrix."""
from __future__ import annotations

from ..schemas.finding import State
from .frameworks import ALL_FRAMEWORKS, DOMAIN_CONTROLS, FRAMEWORKS, domains_for


def map_finding(finding) -> dict:
    """Return {framework: sorted[control_id]} the finding provides evidence for.

    Built from the finding's CWE→domain→control mapping, then merged with any explicit
    ``compliance_control_refs`` the finding already carries (those use ``FRAMEWORK:control`` form).
    """
    doms = domains_for(getattr(finding, "cwe", []), getattr(finding, "vuln_class", ""))
    out: dict[str, set] = {fw: set() for fw in ALL_FRAMEWORKS}
    for d in doms:
        for fw, ctrls in DOMAIN_CONTROLS.get(d, {}).items():
            out[fw].update(ctrls)
    # Merge explicit refs like "SOC2:CC6.1", "ISO27001:A.8.24", "PCI-DSS:11.3".
    for ref in getattr(finding, "compliance_control_refs", []) or []:
        if ":" in ref:
            fw, _, ctrl = ref.partition(":")
            fw = {"PCI": "PCI-DSS", "ISO": "ISO27001"}.get(fw, fw)
            if fw in out and ctrl in FRAMEWORKS[fw]["controls"]:
                out[fw].add(ctrl)
    return {fw: sorted(ctrls) for fw, ctrls in out.items() if ctrls}


def coverage(findings, frameworks=None) -> dict:
    """Per-framework control coverage across all reported (non-dropped) findings.

    Returns {framework: {control_id: [finding, ...]}} — a control appears only if a finding maps to it.
    """
    frameworks = frameworks or ALL_FRAMEWORKS
    reported = [f for f in findings if f.state != State.DROPPED]
    out: dict[str, dict] = {fw: {} for fw in frameworks}
    for f in reported:
        mapped = map_finding(f)
        for fw in frameworks:
            for ctrl in mapped.get(fw, []):
                out[fw].setdefault(ctrl, []).append(f)
    return out


def _is_exception(f) -> bool:
    return f.verification.validated and f.state != State.FIXED and "agent-assessed" not in f.tags


def compliance_matrix_report(findings, scope, scan=None, frameworks=None) -> str:
    """Audit-ready, multi-framework control-coverage matrix.

    For each framework, lists every touched control with: how many findings exercised it, how many
    are open exceptions (confirmed & unremediated), and how many were remediated (retest→Fixed).
    """
    frameworks = frameworks or ALL_FRAMEWORKS
    cov = coverage(findings, frameworks)
    reported = [f for f in findings if f.state != State.DROPPED]
    exceptions = [f for f in reported if _is_exception(f)]

    tkt = scope.authorization.ticket or "engagement"
    L = ["# Compliance control-coverage matrix", ""]
    L.append(f"*Engagement* **{tkt}** · authorized by **{scope.authorization.authorized_by}**")
    L.append("")
    L.append("> Every finding is mapped — by CWE — to the control it provides evidence for across "
             f"**{len(frameworks)} frameworks**. This is *evidence of control effectiveness*, not a "
             "certification: the attestation is issued by a CPA firm (SOC 2), an accredited body "
             "(ISO 27001), a QSA (PCI DSS), or a 3PAO (FedRAMP). Hand this plus the hash-chained "
             "audit log and evidence bundle to your assessor.")
    L.append("")

    # ---- headline coverage per framework ----
    L.append("## Frameworks covered")
    L.append("")
    L.append("| Framework | Controls with evidence | Open exceptions |")
    L.append("|-----------|----------------------:|----------------:|")
    for fw in frameworks:
        ctrls = cov.get(fw, {})
        exc = sum(1 for c, fs in ctrls.items() if any(_is_exception(x) for x in fs))
        L.append(f"| {FRAMEWORKS[fw]['title']} | {len(ctrls)} | {exc} |")
    L.append("")

    # ---- per-framework control detail ----
    for fw in frameworks:
        ctrls = cov.get(fw, {})
        if not ctrls:
            continue
        L.append(f"## {FRAMEWORKS[fw]['title']}")
        L.append("")
        L.append("| Control | Description | Findings | Open exceptions | Remediated |")
        L.append("|---------|-------------|---------:|----------------:|-----------:|")
        for ctrl in sorted(ctrls):
            fs = ctrls[ctrl]
            exc = len([f for f in fs if _is_exception(f)])
            rem = len([f for f in fs if f.state == State.FIXED])
            title = FRAMEWORKS[fw]["controls"].get(ctrl, "")
            L.append(f"| {ctrl} | {title} | {len(fs)} | {exc} | {rem} |")
        L.append("")

    # ---- open exceptions, mapped across all frameworks ----
    L.append("## Open control exceptions (confirmed, unremediated)")
    L.append("")
    if not exceptions:
        L.append("*No open control exceptions — no confirmed findings are currently outstanding.*")
    else:
        for f in sorted(exceptions, key=lambda f: f.severity):
            mapped = map_finding(f)
            refs = " · ".join(f"{fw} {','.join(mapped[fw])}" for fw in frameworks if mapped.get(fw))
            L.append(f"- **[{f.severity.upper()}] {f.title}** — {', '.join(f.cwe)} · finding `{f.id}`")
            L.append(f"    - *Controls:* {refs}")
            if f.remediation.summary:
                L.append(f"    - *Remediation:* {f.remediation.summary}")
    L.append("")
    L.append("---")
    L.append("*Generated by Rampart. Control mapping is deterministic (CWE→domain→control) and "
             "fully auditable.*")
    return "\n".join(L)
