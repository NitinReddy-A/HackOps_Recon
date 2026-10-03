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
        by_sev = {}
        for f in reported:
            by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
        total_candidates = len(reported) + len(dropped)
        val_rate = (len(confirmed) / total_candidates) if total_candidates else 0.0
        return {
            "confirmed": len(confirmed),
            "reported": len(reported),
            "dropped_candidates": len(dropped),
            "by_severity": by_sev,
            "finding_validation_rate": round(val_rate, 3),
            "endpoints_tested": (self.scan or {}).get("endpoints_tested", 0),
            "endpoints_discovered": len(self.appmodel.endpoints) if self.appmodel else 0,
            "hypotheses": len((self.scan or {}).get("hypotheses", [])),
            "audit_events": self.audit_events,
            "tokens_used": self.budget.get("tokens_used", 0),
            "usd_spent": self.budget.get("usd_spent", 0.0),
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
        L.append("## Summary")
        L.append("")
        L.append(f"- **{m['confirmed']}** confirmed finding(s), independently validated with reproducible proof")
        L.append(f"- **{m['dropped_candidates']}** candidate(s) dropped by the validation gate (false-positive control)")
        L.append(f"- Finding-validation rate: **{m['finding_validation_rate']*100:.0f}%** of candidates confirmed")
        L.append(f"- Endpoints tested: {m['endpoints_tested']} / {m['endpoints_discovered']} discovered")
        L.append(f"- Audit events: {m['audit_events']} (append-only, hash-chained) · "
                 f"tokens: {m['tokens_used']} · cost: ${m['usd_spent']}")
        L.append("")
        L.append("## Findings")
        for f in self.findings:
            if f.state == State.DROPPED:
                continue
            L.append("")
            L.append(f"### [{f.severity.upper()}] {f.title}")
            L.append("")
            badge = "✅ CONFIRMED (validated)" if f.verification.validated else f"⏳ {f.confidence}"
            L.append(f"- **Status:** {badge} · state `{f.state}` · {', '.join(f.cwe)} · "
                     f"{', '.join(f.owasp.get('api_2023', []) + f.owasp.get('web_2025', []))}")
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
