"""Report generation: JSON, SARIF, Markdown, compliance, and a self-contained HTML dashboard.

Reports are auto-populated evidence artifacts, not marketing (blueprint section 22). Only
validated findings are presented as confirmed; dropped candidates are shown separately so
the false-positive discipline is visible. Nothing is over-claimed — the tool generates
*evidence of control effectiveness*, never compliance itself.
"""
from __future__ import annotations

import html
import json

from ..version import __version__
from ..schemas.finding import State

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_SEV_COLOR = {"critical": "#b4232c", "high": "#d1495b", "medium": "#e08a1e",
              "low": "#3a7ca5", "info": "#5b6570"}


def owasp_tags(f) -> list:
    """All OWASP categories on a finding, across web/API/LLM taxonomies."""
    tags = []
    for key in ("api_2023", "web_2025", "web_2021", "llm_2025"):
        tags.extend(f.owasp.get(key, []))
    return tags


class ReportBuilder:
    def __init__(self, findings, scope, appmodel, scan, budget_snapshot, audit_events=0):
        self.findings = sorted(findings, key=lambda f: (_SEV_ORDER.get(f.severity, 9),
                                                        0 if f.verification.validated else 1))
        self.scope = scope
        self.appmodel = appmodel
        self.scan = scan
        self.budget = budget_snapshot or {}
        self.audit_events = audit_events

    # ------------------------------------------------------------ metrics
    def metrics(self) -> dict:
        confirmed = [f for f in self.findings if f.verification.validated and f.state != State.DROPPED]
        dropped = [f for f in self.findings if f.state == State.DROPPED]
        reported = [f for f in self.findings if f.state != State.DROPPED]
        external = [f for f in reported if "external-scanner" in f.tags]
        by_sev, by_class = {}, {}
        for f in reported:
            by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
            by_class[f.vuln_class] = by_class.get(f.vuln_class, 0) + 1
        # validation rate is over Rampart's own oracle-gated candidates (exclude external leads)
        own = [f for f in reported if "external-scanner" not in f.tags]
        total_candidates = len(own) + len(dropped)
        val_rate = (len([f for f in own if f.verification.validated]) / total_candidates) if total_candidates else 0.0
        return {
            "confirmed": len(confirmed),
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
        }

    # --------------------------------------------------------------- JSON
    def to_json(self) -> str:
        return json.dumps({
            "tool": {"name": "rampart", "version": __version__},
            "engagement": {
                "ticket": self.scope.authorization.ticket,
                "owner": self.scope.authorization.owner,
                "authorized_by": self.scope.authorization.authorized_by,
            },
            "metrics": self.metrics(),
            "findings": [f.to_dict() for f in self.findings],
        }, indent=2, default=str)

    # -------------------------------------------------------------- SARIF
    def to_sarif(self) -> str:
        rules, rule_ids = [], set()
        results = []
        for f in self.findings:
            if f.state == State.DROPPED:
                continue
            rid = (f.cwe[0] if f.cwe else f.vuln_class) or "finding"
            if rid not in rule_ids:
                rule_ids.add(rid)
                rules.append({"id": rid, "name": f.vuln_class or rid,
                              "shortDescription": {"text": f.title},
                              "helpUri": (f.references[0] if f.references else "")})
            results.append(f.to_sarif_result())
        doc = {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {"driver": {"name": "Rampart", "version": __version__,
                                    "informationUri": "https://rampart.dev", "rules": rules}},
                "results": results,
            }],
        }
        return json.dumps(doc, indent=2, default=str)

    # ----------------------------------------------------------- Markdown
    def to_markdown(self) -> str:
        m = self.metrics()
        L = []
        L.append(f"# Rampart assessment report — {self.scope.authorization.ticket or 'engagement'}")
        L.append("")
        L.append(f"*Authorized by* **{self.scope.authorization.authorized_by}** · "
                 f"*owner* **{self.scope.authorization.owner}** · tool `rampart {__version__}`")
        L.append("")
        L.append(self._executive_summary_md(m))
        L.append("## Summary")
        L.append("")
        L.append(f"- **{m['confirmed']}** confirmed finding(s), independently validated with reproducible proof")
        L.append(f"- **{m['dropped_candidates']}** candidate(s) dropped by the validation gate (false-positive control)")
        L.append(f"- Finding-validation rate: **{m['finding_validation_rate']*100:.0f}%** of candidates confirmed")
        L.append(f"- Endpoints tested: {m['endpoints_tested']} / {m['endpoints_discovered']} discovered")
        L.append(f"- Audit events: {m['audit_events']} (append-only, hash-chained) · "
                 f"tokens: {m['tokens_used']} · cost: ${m['usd_spent']}")
        if m["external_leads"]:
            L.append(f"- **{m['external_leads']}** external-scanner lead(s) included (unvalidated — "
                     "shown separately, not counted as confirmed)")
        L.append(f"- **Aggregate risk: {m['risk_score']}/100 ({m['risk_band']})** · "
                 f"{m['attack_chains']} attack chain(s) identified")
        L.append("")
        L.append(self._coverage_md(m))
        L.append(self._chains_md())
        L.append(self._roadmap_md())
        L.append("## Findings")
        for f in self.findings:
            if f.state == State.DROPPED:
                continue
            L.append("")
            L.append(f"### [{f.severity.upper()}] {f.title}")
            L.append("")
            if "external-scanner" in f.tags:
                badge = f"🔎 external lead ({f.verification.validator}, unvalidated)"
            elif f.verification.validated:
                badge = "✅ CONFIRMED (validated)"
            else:
                badge = f"⏳ {f.confidence}"
            L.append(f"- **Status:** {badge} · state `{f.state}` · {', '.join(f.cwe)} · "
                     f"{', '.join(owasp_tags(f))}")
            if f.cvss.vector:
                L.append(f"- **CVSS {f.cvss.version}:** {f.cvss.base_score} ({f.cvss.severity}) `{f.cvss.vector}`")
            if f.endpoint.get("url"):
                L.append(f"- **Endpoint:** `{f.endpoint.get('method','')} {f.endpoint['url']}`")
            L.append(f"- **Description:** {f.description}")
            if f.impact:
                L.append(f"- **Impact:** {f.impact}")
            if f.root_cause:
                L.append(f"- **Root cause:** {f.root_cause}")
            if f.verification.validated:
                L.append(f"- **Proof (independent validation, {f.verification.reproductions} reproductions):**")
                for chk in f.verification.false_positive_checks:
                    L.append(f"    - {chk}")
            if f.reproduction.steps:
                L.append("- **Reproduction:**")
                for i, s in enumerate(f.reproduction.steps, 1):
                    L.append(f"    {i}. {s}")
            if f.affected_code and f.affected_code.file:
                L.append(f"- **Affected code:** `{f.affected_code.file}:{f.affected_code.start_line}` "
                         f"(via {f.affected_code.detected_by})")
            if f.remediation.summary or f.remediation.guidance:
                L.append(f"- **Remediation:** {f.remediation.summary}")
                if f.remediation.guidance:
                    L.append(f"    - {f.remediation.guidance}")
            if f.remediation.proposed_diff:
                L.append("- **Advisory patch (not auto-applied):**")
                L.append("")
                L.append("    ```diff")
                for line in f.remediation.proposed_diff.splitlines():
                    L.append("    " + line)
                L.append("    ```")
            if f.compliance_control_refs:
                L.append(f"- **Compliance evidence:** {', '.join(f.compliance_control_refs)}")
        L.append("")
        L.append("---")
        L.append("*Rampart augments, does not replace, expert human pentesters. This report is "
                 "evidence of control effectiveness, not a compliance attestation.*")
        return "\n".join(L)

    # -------------------------------------------------------- coverage
    def _coverage_md(self, m) -> str:
        from ..agents import describe_roster
        scan = self.scan or {}
        L = ["## Coverage & methodology", ""]
        classes = m.get("classes_tested") or sorted({f.vuln_class for f in self.findings})
        L.append(f"- **Vulnerability classes tested:** {', '.join(classes) or '—'}")
        plan = scan.get("plan") or {}
        if plan.get("order"):
            L.append(f"- **Planner priority:** {', '.join(plan['order'])}")
        runs = scan.get("scanner_runs") or []
        if runs:
            parts = []
            for r in runs:
                if r.get("available"):
                    parts.append(f"{r['scanner']} ({r.get('findings', 0)} leads)")
                else:
                    parts.append(f"{r['scanner']} (not installed)")
            L.append(f"- **External OSS scanners:** {', '.join(parts)}")
        probe_log = scan.get("llm_probe_log") or []
        if probe_log:
            confirmed = [p for p in probe_log if p["result"] == "confirmed"]
            L.append(f"- **OWASP LLM Top-10 probes:** {len(confirmed)}/{len(probe_log)} classes vulnerable")
        L.append("- **Agent pipeline:** " + " → ".join(r["role"] for r in describe_roster()))
        L.append("- **Trust rule:** only findings re-derived by an independent deterministic oracle "
                 "are marked *confirmed*; external-scanner results are unvalidated leads.")
        L.append("")
        return "\n".join(L)

    # -------------------------------------------------------- executive summary
    def executive_summary(self, m=None) -> str:
        """One-paragraph, plain-English verdict for a decision-maker."""
        m = m or self.metrics()
        corr = (self.scan or {}).get("correlation") or {}
        classes = sorted({f.vuln_class for f in self.findings
                          if f.verification.validated and f.state != State.DROPPED})
        if not m["confirmed"]:
            return ("No vulnerabilities were confirmed. Every candidate was dropped by the "
                    "independent validation gate, so there are no false positives to triage.")
        worst = min(corr.get("chains", []),
                    key=lambda c: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(c["severity"], 4),
                    default=None)
        bits = [f"The assessment confirmed {m['confirmed']} vulnerabilit"
                f"{'y' if m['confirmed'] == 1 else 'ies'} across {len(classes)} class(es) "
                f"({', '.join(classes)}), each independently validated with reproducible proof "
                f"(no false positives). Aggregate risk is {m['risk_score']}/100 ({m['risk_band']})."]
        if worst:
            bits.append(f"The most serious exposure is \"{worst['title']}\" — "
                        f"{len(corr.get('chains', []))} attack chain(s) were identified in total.")
        if corr.get("roadmap"):
            top = corr["roadmap"][0]
            bits.append(f"Highest-priority fix: {top['summary']}")
        return " ".join(bits)

    def _executive_summary_md(self, m) -> str:
        return "## Executive summary\n\n" + self.executive_summary(m) + "\n"

    # -------------------------------------------------------- chains / roadmap
    def _chains_md(self) -> str:
        corr = (self.scan or {}).get("correlation") or {}
        chains = corr.get("chains") or []
        if not chains:
            return ""
        L = ["## Attack chains (kill-chain)", "",
             "Confirmed findings composed into realistic multi-step attacks:", ""]
        for c in chains:
            L.append(f"### [{c['severity'].upper()}] {c['title']}")
            L.append(f"- *Why:* {c['rationale']}")
            for i, step in enumerate(c["steps"], 1):
                L.append(f"    {i}. {step}")
            if c.get("contributing"):
                L.append(f"- *Built from:* {', '.join(c['contributing'])}")
            L.append("")
        return "\n".join(L)

    def _roadmap_md(self) -> str:
        corr = (self.scan or {}).get("correlation") or {}
        roadmap = corr.get("roadmap") or []
        if not roadmap:
            return ""
        L = ["## Remediation roadmap (prioritized)", ""]
        for i, r in enumerate(roadmap, 1):
            fixes = f" — fixes {r['count']} finding(s): {', '.join(r['classes'])}" if r.get("count") else ""
            L.append(f"{i}. **[{r['severity'].upper()}, {r.get('effort','?')} effort]** {r['summary']}{fixes}")
            if r.get("guidance"):
                L.append(f"    - {r['guidance']}")
        L.append("")
        return "\n".join(L)

    # -------------------------------------------------------- compliance
    def to_compliance(self) -> str:
        control_map: dict[str, list] = {}
        for f in self.findings:
            if f.state == State.DROPPED:
                continue
            for ctrl in f.compliance_control_refs:
                control_map.setdefault(ctrl, []).append(f)
        L = ["# Compliance evidence bundle", "",
             "> This maps **validated** findings to control IDs. It is *evidence of control "
             "effectiveness*, not a certification. The attestation is issued by a CPA firm "
             "(SOC 2) or accredited body (ISO 27001).", ""]
        for ctrl in sorted(control_map):
            L.append(f"## {ctrl}")
            for f in control_map[ctrl]:
                status = "validated" if f.verification.validated else f.confidence
                L.append(f"- [{f.severity.upper()}] {f.title} — {status} "
                         f"({', '.join(f.cwe)}) · finding `{f.id}`")
            L.append("")
        return "\n".join(L)

    # -------------------------------------------------------------- HTML
    def to_html(self) -> str:
        from .html_report import render_html
        return render_html(self)
