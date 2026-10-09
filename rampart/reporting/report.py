"""Report generation: JSON, SARIF, Markdown, compliance, and a self-contained HTML dashboard.

Reports are auto-populated evidence artifacts, not marketing (blueprint section 22). Only
validated findings are presented as confirmed; dropped candidates are shown separately so
the false-positive discipline is visible. Nothing is over-claimed — the tool generates
*evidence of control effectiveness*, never compliance itself.
"""

from __future__ import annotations

import json

from ..schemas.finding import State
from ..version import __version__
from .mdsafe import md, md_code, md_fence, md_join
from .status import (
    SEV_ORDER,
    SEV_RANK,
    is_confirmed,
    is_fixed,
    is_static,
    is_validated,
    norm_severity,
    sev_rank,
)

_SEV_ORDER = SEV_RANK
# Same weights the correlation engine uses for the aggregate risk score.
_SEV_WEIGHT = {"critical": 40, "high": 25, "medium": 10, "low": 3, "info": 1}


def _risk_band(score: int) -> str:
    if score >= 80:
        return "Critical"
    if score >= 55:
        return "High"
    if score >= 30:
        return "Medium"
    return "Low" if score > 0 else "Informational"


_CWE_NAMES = {
    "CWE-16": "Configuration",
    "CWE-20": "Improper Input Validation",
    "CWE-22": "Path Traversal",
    "CWE-77": "Command Injection",
    "CWE-78": "OS Command Injection",
    "CWE-79": "Cross-site Scripting (XSS)",
    "CWE-89": "SQL Injection",
    "CWE-90": "LDAP Injection",
    "CWE-91": "XML Injection",
    "CWE-94": "Code Injection",
    "CWE-95": "Eval Injection",
    "CWE-200": "Exposure of Sensitive Information",
    "CWE-284": "Improper Access Control",
    "CWE-285": "Improper Authorization",
    "CWE-287": "Improper Authentication",
    "CWE-295": "Improper Certificate Validation",
    "CWE-306": "Missing Authentication for Critical Function",
    "CWE-311": "Missing Encryption of Sensitive Data",
    "CWE-319": "Cleartext Transmission of Sensitive Information",
    "CWE-326": "Inadequate Encryption Strength",
    "CWE-327": "Use of a Broken or Risky Cryptographic Algorithm",
    "CWE-347": "Improper Verification of Cryptographic Signature",
    "CWE-352": "Cross-Site Request Forgery (CSRF)",
    "CWE-444": "HTTP Request Smuggling",
    "CWE-502": "Deserialization of Untrusted Data",
    "CWE-522": "Insufficiently Protected Credentials",
    "CWE-538": "Insertion of Sensitive Information into Externally-Accessible File",
    "CWE-601": "Open Redirect",
    "CWE-611": "XML External Entity (XXE)",
    "CWE-614": "Sensitive Cookie Without 'Secure' Attribute",
    "CWE-639": "Authorization Bypass Through User-Controlled Key (IDOR)",
    "CWE-644": "Improper Neutralization of HTTP Headers for Scripting Syntax",
    "CWE-693": "Protection Mechanism Failure",
    "CWE-770": "Allocation of Resources Without Limits or Throttling",
    "CWE-798": "Use of Hard-coded Credentials",
    "CWE-862": "Missing Authorization",
    "CWE-863": "Incorrect Authorization",
    "CWE-915": "Mass Assignment",
    "CWE-918": "Server-Side Request Forgery (SSRF)",
    "CWE-942": "Permissive Cross-domain Policy",
    "CWE-1004": "Sensitive Cookie Without 'HttpOnly' Flag",
    "CWE-1021": "Improper Restriction of Rendered UI Layers (Clickjacking)",
    "CWE-1104": "Use of Unmaintained Third Party Components",
    "CWE-1336": "Server-Side Template Injection",
}


def _sarif_rule(rid: str, f) -> dict:
    """A SARIF reportingDescriptor describing the *rule* (CWE / class), not any one finding."""
    if rid.startswith("CWE-"):
        name = _CWE_NAMES.get(rid)
        text = f"{rid}: {name}" if name else f"{rid} ({f.vuln_class or 'weakness'})"
    else:
        text = f"Rampart check: {rid}"
    rule = {"id": rid, "name": f.vuln_class or rid, "shortDescription": {"text": text}}
    help_uri = next(
        (r for r in (f.references or []) if isinstance(r, str) and r.startswith(("https://", "http://"))),
        "",
    )
    if not help_uri and rid.startswith("CWE-") and rid[4:].isdigit():
        help_uri = f"https://cwe.mitre.org/data/definitions/{rid[4:]}.html"
    if help_uri:  # an empty string is not a valid URI — omit the property instead
        rule["helpUri"] = help_uri
    return rule


def sev_label(sev) -> str:
    """Upper-case severity label that tolerates odd values (unknown -> INFO)."""
    return norm_severity(sev).upper()


_SEV_COLOR = {
    "critical": "#b4232c",
    "high": "#d1495b",
    "medium": "#e08a1e",
    "low": "#3a7ca5",
    "info": "#5b6570",
}


def owasp_tags(f) -> list:
    """All OWASP categories on a finding, across web/API/LLM taxonomies."""
    tags = []
    for key in ("api_2023", "web_2025", "web_2021", "llm_2025"):
        tags.extend(f.owasp.get(key, []))
    return tags


class ReportBuilder:
    def __init__(self, findings, scope, appmodel, scan, budget_snapshot, audit_events=0):
        findings = list(findings)
        for f in findings:  # a malformed stored/LLM-derived severity must never crash a report
            if not (isinstance(f.severity, str) and f.severity in _SEV_ORDER):
                f.severity = norm_severity(f.severity)  # unknown -> "info"; never inflate
        self.findings = sorted(
            findings, key=lambda f: (sev_rank(f.severity), 0 if f.verification.validated else 1)
        )
        self.scope = scope
        self.appmodel = appmodel
        self.scan = scan
        self.budget = budget_snapshot or {}
        self.audit_events = audit_events

    # ------------------------------------------------------------ metrics
    def metrics(self) -> dict:
        confirmed = [f for f in self.findings if is_confirmed(f)]
        fixed = [f for f in self.findings if is_fixed(f)]
        dropped = [f for f in self.findings if f.state == State.DROPPED]
        reported = [f for f in self.findings if f.state != State.DROPPED]
        external = [f for f in reported if "external-scanner" in f.tags]
        by_sev, by_class = {}, {}
        for f in reported:
            if is_fixed(f):
                continue  # remediated: counted under "fixed", not as an open finding
            sev = norm_severity(f.severity)
            by_sev[sev] = by_sev.get(sev, 0) + 1
            by_class[f.vuln_class] = by_class.get(f.vuln_class, 0) + 1
        # White-box (SAST/SCA/IaC) findings are not runtime-validated, so the correlation risk
        # score ignores them; surface their exposure separately instead of reporting "0/100".
        static_open = [f for f in reported if is_static(f) and not is_validated(f) and not is_fixed(f)]
        static_by_sev = {}
        for f in static_open:
            sev = norm_severity(f.severity)
            static_by_sev[sev] = static_by_sev.get(sev, 0) + 1
        static_score = min(100, sum(_SEV_WEIGHT[norm_severity(f.severity)] for f in static_open))
        # validation rate is over Rampart's own oracle-gated candidates (exclude external leads)
        own = [f for f in reported if "external-scanner" not in f.tags]
        total_candidates = len(own) + len(dropped)
        val_rate = (
            (len([f for f in own if f.verification.validated]) / total_candidates)
            if total_candidates
            else 0.0
        )
        return {
            "confirmed": len(confirmed),
            "fixed": len(fixed),
            "reported": len(reported),
            "external_leads": len(external),
            "dropped_candidates": len(dropped),
            "by_severity": by_sev,
            "by_class": by_class,
            "finding_validation_rate": round(val_rate, 3),
            "endpoints_tested": (self.scan or {}).get("endpoints_tested", 0),
            "endpoints_discovered": len(self.appmodel.endpoints) if self.appmodel else 0,
            "classes_tested": (self.scan or {}).get("classes_tested", []),
            "hypotheses": len((self.scan or {}).get("hypotheses", [])),
            "audit_events": self.audit_events,
            "tokens_used": self.budget.get("tokens_used", 0),
            "usd_spent": self.budget.get("usd_spent", 0.0),
            "risk_score": (self.scan or {}).get("correlation", {}).get("risk_score", 0),
            "risk_band": (self.scan or {}).get("correlation", {}).get("risk_band", "Informational"),
            "attack_chains": len((self.scan or {}).get("correlation", {}).get("chains", [])),
            "demonstrated_exploits": len(
                [p for p in (self.scan or {}).get("exploitation", []) if p.get("demonstrated")]
            ),
            "agent_assessed": len(
                [f for f in self.findings if "agent-assessed" in f.tags and f.state != State.DROPPED]
            ),
            "static_findings": len(
                [f for f in self.findings if "sast" in f.tags and f.state != State.DROPPED]
            ),
            "source_correlated": len([f for f in self.findings if "source-correlated" in f.tags]),
            "static_unvalidated": len(static_open),
            "static_by_severity": static_by_sev,
            "static_risk_score": static_score,
            "static_risk_band": _risk_band(static_score),
        }

    # --------------------------------------------------------------- JSON
    def to_json(self) -> str:
        return json.dumps(
            {
                "tool": {"name": "rampart", "version": __version__},
                "engagement": {
                    "ticket": self.scope.authorization.ticket,
                    "owner": self.scope.authorization.owner,
                    "authorized_by": self.scope.authorization.authorized_by,
                },
                "metrics": self.metrics(),
                "findings": [f.to_dict() for f in self.findings],
            },
            indent=2,
            default=str,
        )

    # -------------------------------------------------------------- SARIF
    def to_sarif(self) -> str:
        rules, rule_ids = [], set()
        results = []
        for f in self.findings:
            # Dropped candidates are not findings; Fixed ones are omitted so code scanning closes them.
            if f.state == State.DROPPED or is_fixed(f):
                continue
            rid = (f.cwe[0] if f.cwe else f.vuln_class) or "finding"
            if rid not in rule_ids:
                rule_ids.add(rid)
                rules.append(_sarif_rule(rid, f))
            results.append(f.to_sarif_result(repo_root=(self.scan or {}).get("repo", "")))
        doc = {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Rampart",
                            "version": __version__,
                            "informationUri": "https://rampart.dev",
                            "rules": rules,
                        }
                    },
                    "results": results,
                }
            ],
        }
        return json.dumps(doc, indent=2, default=str)

    # ----------------------------------------------------------- Markdown
    # Every string that can carry target-controlled text goes through ``md`` / ``md_code`` /
    # ``md_fence`` (see mdsafe.py): rendered Markdown passes raw HTML through.
    def to_markdown(self) -> str:
        m = self.metrics()
        auth = self.scope.authorization
        L = []
        L.append(f"# Rampart assessment report — {md(auth.ticket or 'engagement')}")
        L.append("")
        L.append(
            f"*Authorized by* **{md(auth.authorized_by)}** · "
            f"*owner* **{md(auth.owner)}** · tool `rampart {__version__}`"
        )
        L.append("")
        L.append(self._executive_summary_md(m))
        L.append("## Summary")
        L.append("")
        L.append(
            f"- **{m['confirmed']}** confirmed finding(s), independently validated with reproducible proof"
        )
        if m["fixed"]:
            L.append(f"- **{m['fixed']}** finding(s) verified **fixed** by retest (listed separately)")
        L.append(
            f"- **{m['dropped_candidates']}** candidate(s) dropped by the validation gate (false-positive control)"
        )
        L.append(
            f"- Finding-validation rate: **{m['finding_validation_rate'] * 100:.0f}%** of candidates confirmed"
        )
        L.append(f"- Endpoints tested: {m['endpoints_tested']} / {m['endpoints_discovered']} discovered")
        L.append(
            f"- Audit events: {m['audit_events']} (append-only, hash-chained) · "
            f"tokens: {m['tokens_used']} · cost: ${m['usd_spent']}"
        )
        if m["external_leads"]:
            L.append(
                f"- **{m['external_leads']}** external-scanner lead(s) included (unvalidated — "
                "shown separately, not counted as confirmed)"
            )
        L.append(
            f"- **Aggregate risk: {md(m['risk_score'])}/100 ({md(m['risk_band'])})** · "
            f"{m['attack_chains']} attack chain(s) identified"
        )
        if m["static_unvalidated"]:
            L.append(f"- **Static-analysis exposure:** {md(self._static_risk_text(m))}")
        L.append("")
        L.append(self._coverage_md(m))
        L.append(self._chains_md())
        L.append(self._exploitation_md())
        L.append(self._roadmap_md())
        L.append("## Findings")
        for f in self.findings:
            if f.state == State.DROPPED or is_fixed(f):
                continue
            L.extend(self._finding_md(f))
        fixed = [f for f in self.findings if is_fixed(f)]
        if fixed:
            L.append("")
            L.append("## Fixed (verified by retest)")
            L.append("")
            L.append(
                "Previously confirmed findings that a retest no longer reproduces. They are not "
                "counted as confirmed or open."
            )
            for f in fixed:
                L.extend(self._finding_md(f))
        L.append("")
        L.append("---")
        L.append(
            "*Rampart augments, does not replace, expert human pentesters. This report is "
            "evidence of control effectiveness, not a compliance attestation.*"
        )
        return "\n".join(L)

    def _static_risk_text(self, m) -> str:
        counts = ", ".join(
            f"{m['static_by_severity'][s]} {s}" for s in SEV_ORDER if m["static_by_severity"].get(s)
        )
        return (
            f"{m['static_risk_score']}/100 ({m['static_risk_band']}) from "
            f"{m['static_unvalidated']} unvalidated SAST/SCA/IaC finding(s) ({counts}), "
            "not included in the aggregate risk score"
        )

    def _finding_md(self, f) -> list:
        L = ["", f"### [{sev_label(f.severity)}] {md(f.title)}", ""]
        if is_fixed(f):
            badge = "🟢 FIXED (verified by retest)"
        elif "agent-assessed" in f.tags:
            badge = "🤖 AGENT-ASSESSED (human review recommended)"
        elif "external-scanner" in f.tags:
            badge = f"🔎 external lead ({md(f.verification.validator)}, unvalidated)"
        elif f.verification.validated:
            badge = "✅ CONFIRMED (validated)"
        else:
            badge = f"⏳ {md(f.confidence)}"
        L.append(
            f"- **Status:** {badge} · state {md_code(f.state)} · {md_join(f.cwe)} · {md_join(owasp_tags(f))}"
        )
        if f.cvss.vector:
            L.append(
                f"- **CVSS {md(f.cvss.version)}:** {md(f.cvss.base_score)} ({md(f.cvss.severity)}) "
                f"{md_code(f.cvss.vector)}"
            )
        if f.endpoint.get("url"):
            endpoint = f"{f.endpoint.get('method', '')} {f.endpoint['url']}"
            L.append(f"- **Endpoint:** {md_code(endpoint)}")
        L.append(f"- **Description:** {md(f.description)}")
        if f.impact:
            L.append(f"- **Impact:** {md(f.impact)}")
        if f.root_cause:
            L.append(f"- **Root cause:** {md(f.root_cause)}")
        if f.verification.validated:
            L.append(
                f"- **Proof (independent validation, {md(f.verification.reproductions)} reproductions):**"
            )
            for chk in f.verification.false_positive_checks:
                L.append(f"    - {md(chk)}")
        if is_fixed(f):
            lr = f.verification.last_retest or {}
            L.append(f"- **Retest:** {md(lr.get('result', 'fixed'))} at {md(lr.get('at', ''))}")
        if f.reproduction.steps:
            L.append("- **Reproduction:**")
            for i, s in enumerate(f.reproduction.steps, 1):
                L.append(f"    {i}. {md(s)}")
        if f.affected_code and f.affected_code.file:
            loc = f"{f.affected_code.file}:{f.affected_code.start_line}"
            L.append(f"- **Affected code:** {md_code(loc)} (via {md(f.affected_code.detected_by)})")
        if f.remediation.summary or f.remediation.guidance:
            L.append(f"- **Remediation:** {md(f.remediation.summary)}")
            if f.remediation.guidance:
                L.append(f"    - {md(f.remediation.guidance)}")
        if f.compliance_control_refs:
            L.append(f"- **Compliance evidence:** {md_join(f.compliance_control_refs)}")
        if f.remediation.proposed_diff:
            # column-0 fence after the list: literal in every renderer, never parsed as HTML
            L.append("- **Advisory patch (not auto-applied):**")
            L.append("")
            L.extend(md_fence(f.remediation.proposed_diff, "diff"))
        return L

    # -------------------------------------------------------- coverage
    def _coverage_md(self, m) -> str:
        from ..agents import describe_roster

        scan = self.scan or {}
        L = ["## Coverage & methodology", ""]
        classes = m.get("classes_tested") or sorted({f.vuln_class for f in self.findings})
        L.append(f"- **Vulnerability classes tested:** {md_join(classes) or '—'}")
        plan = scan.get("plan") or {}
        if plan.get("order"):
            L.append(f"- **Planner priority:** {md_join(plan['order'])}")
        runs = scan.get("scanner_runs") or []
        if runs:
            parts = []
            for r in runs:
                if r.get("available"):
                    parts.append(f"{md(r.get('scanner'))} ({md(r.get('findings', 0))} leads)")
                else:
                    parts.append(f"{md(r.get('scanner'))} (not installed)")
            L.append(f"- **External OSS scanners:** {', '.join(parts)}")
        probe_log = scan.get("llm_probe_log") or []
        if probe_log:
            confirmed = [p for p in probe_log if p.get("result") == "confirmed"]
            L.append(f"- **OWASP LLM Top-10 probes:** {len(confirmed)}/{len(probe_log)} classes vulnerable")
        L.append("- **Agent pipeline:** " + " → ".join(md(r["role"]) for r in describe_roster()))
        L.append(
            "- **Trust rule:** only findings re-derived by an independent deterministic oracle "
            "are marked *confirmed*; external-scanner results are unvalidated leads."
        )
        L.append("")
        return "\n".join(L)

    # -------------------------------------------------------- executive summary
    def executive_summary(self, m=None) -> str:
        """One-paragraph, plain-English verdict for a decision-maker (plain text, not Markdown)."""
        m = m or self.metrics()
        corr = (self.scan or {}).get("correlation") or {}
        classes = sorted({f.vuln_class for f in self.findings if is_confirmed(f)})
        if not m["confirmed"]:
            if m.get("fixed"):
                text = (
                    f"No open vulnerabilities remain confirmed: {m['fixed']} previously confirmed "
                    "finding(s) were verified fixed by retest."
                )
            else:
                text = (
                    "No vulnerabilities were confirmed. Every candidate was dropped by the "
                    "independent validation gate, so there are no false positives to triage."
                )
            if m.get("static_unvalidated"):
                text += f" Static analysis exposure: {self._static_risk_text(m)}."
            return text
        worst = min(corr.get("chains", []), key=lambda c: sev_rank(c.get("severity")), default=None)
        bits = [
            f"The assessment confirmed {m['confirmed']} vulnerabilit"
            f"{'y' if m['confirmed'] == 1 else 'ies'} across {len(classes)} class(es) "
            f"({', '.join(classes)}), each independently validated with reproducible proof "
            f"(no false positives). Aggregate risk is {m['risk_score']}/100 ({m['risk_band']})."
        ]
        if worst:
            bits.append(
                f'The most serious exposure is "{worst.get("title", "")}" — '
                f"{len(corr.get('chains', []))} attack chain(s) were identified in total."
            )
        if corr.get("roadmap"):
            top = corr["roadmap"][0]
            bits.append(f"Highest-priority fix: {top.get('summary', '')}")
        if m.get("fixed"):
            bits.append(f"{m['fixed']} previously confirmed finding(s) were verified fixed by retest.")
        if m.get("agent_assessed"):
            bits.append(
                f"Additionally, the reasoning agents flagged {m['agent_assessed']} "
                "agent-assessed issue(s) (e.g. business-logic abuse) for human confirmation — "
                "these are reported separately from oracle-confirmed findings."
            )
        if m.get("static_unvalidated"):
            bits.append(f"Static analysis exposure: {self._static_risk_text(m)}.")
        return " ".join(bits)

    def _executive_summary_md(self, m) -> str:
        return "## Executive summary\n\n" + md(self.executive_summary(m)) + "\n"

    # -------------------------------------------------------- chains / roadmap
    def _chains_md(self) -> str:
        corr = (self.scan or {}).get("correlation") or {}
        chains = corr.get("chains") or []
        if not chains:
            return ""
        L = [
            "## Attack chains (kill-chain)",
            "",
            "Confirmed findings composed into realistic multi-step attacks:",
            "",
        ]
        for c in chains:
            tag = " _(agent-assessed — human review)_" if c.get("agent_assessed") else ""
            L.append(f"### [{sev_label(c.get('severity'))}] {md(c.get('title', ''))}{tag}")
            L.append(f"- *Why:* {md(c.get('rationale', ''))}")
            for i, step in enumerate(c.get("steps") or [], 1):
                L.append(f"    {i}. {md(step)}")
            if c.get("contributing"):
                L.append(f"- *Built from:* {md_join(c['contributing'])}")
            L.append("")
        return "\n".join(L)

    def _roadmap_md(self) -> str:
        corr = (self.scan or {}).get("correlation") or {}
        roadmap = corr.get("roadmap") or []
        if not roadmap:
            return ""
        L = ["## Remediation roadmap (prioritized)", ""]
        for i, r in enumerate(roadmap, 1):
            fixes = ""
            if r.get("count"):
                fixes = f" — fixes {md(r['count'])} finding(s): {md_join(r.get('classes'))}"
            L.append(
                f"{i}. **[{sev_label(r.get('severity'))}, {md(r.get('effort', '?'))} effort]** "
                f"{md(r.get('summary', ''))}{fixes}"
            )
            if r.get("guidance"):
                L.append(f"    - {md(r['guidance'])}")
        L.append("")
        return "\n".join(L)

    def _exploitation_md(self) -> str:
        proofs = [p for p in (self.scan or {}).get("exploitation", []) if p.get("demonstrated")]
        if not proofs:
            return ""
        L = [
            "## Exploitation — demonstrated impact",
            "",
            "Bounded, non-destructive follow-on steps that *demonstrate* real impact for confirmed "
            "findings (read-only, scope-gated, request-capped):",
            "",
        ]
        for p in proofs:
            L.append(f"### {md(p.get('title', ''))}")
            L.append(f"- **Technique:** {md(p.get('technique', ''))}")
            for i, s in enumerate(p.get("steps", []), 1):
                L.append(f"    {i}. {md(s)}")
            L.append(f"- **Demonstrated impact:** {md(p.get('impact', ''))}")
            if p.get("samples"):
                L.append(f"- **Evidence:** {md_join(p['samples'][:8])}")
            L.append("")
        return "\n".join(L)

    # -------------------------------------------------------- compliance
    def to_compliance(self) -> str:
        """Full multi-framework control-coverage matrix (SOC 2, ISO 27001, PCI DSS, NIST
        800-53/FedRAMP, HIPAA, GDPR, OWASP ASVS, CIS) — every finding mapped by CWE."""
        from ..compliance import compliance_matrix_report

        return compliance_matrix_report(self.findings, self.scope, self.scan)

    # ---------------------------------------------------------------- SOC 2
    def to_soc2(self) -> str:
        from .soc2 import soc2_report

        return soc2_report(self.findings, self.scan, self.scope)

    # -------------------------------------------------------------- HTML
    def to_html(self) -> str:
        from .html_report import render_html

        return render_html(self)
