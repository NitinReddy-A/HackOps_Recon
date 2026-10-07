"""Multi-agent orchestration for the reasoning layer (business logic, auth flows, novel abuse).

This is the part no deterministic oracle can do: it reasons about the application's *intended*
behaviour. A planner proposes objectives; an explorer agent runs a bounded ReAct loop (every
action is a GET through the policy choke-point — gated, audited, read-only); an adversarial
critic tries to DISPROVE each candidate with a control probe. Survivors become **agent-assessed**
findings — a tier that is explicitly BELOW oracle-`confirmed` and flagged for human review,
because the conclusion rests on reasoning, not mathematical proof. The safety invariants are
untouched: the brain proposes, deterministic code disposes, and nothing here is ever marked
`confirmed`.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from ..runner import ProbeRunner
from ..schemas.finding import Finding, Remediation, Reproduction, State, Verification


@dataclass
class AgentResult:
    findings: list = field(default_factory=list)
    transcript: list = field(default_factory=list)
    objectives: list = field(default_factory=list)


class AgentOrchestrator:
    def __init__(self, pipeline, evidence_store, session_manager, host, port, scheme,
                 target_url, appmodel, brain, application="target",
                 max_steps=6, max_objectives=4, max_total_actions=40):
        self.pipeline = pipeline
        self.evidence = evidence_store
        self.sessions = session_manager
        self.host, self.port, self.scheme = host, port, scheme
        self.target_url = target_url
        self.appmodel = appmodel
        self.brain = brain
        self.application = application
        self.max_steps = max_steps
        self.max_objectives = max_objectives
        self.max_total_actions = max_total_actions
        self._actions = 0

    def _runner(self, role):
        return ProbeRunner(self.pipeline, self.evidence, self.pipeline.engagement_id,
                           self.host, self.port, self.scheme, actor_role=role,
                           actor_profile="agent", phase="test")

    def _slim_endpoints(self):
        return [{"method": e.method, "path": e.path,
                 "params": [p.get("name") for p in (e.parameters or [])]}
                for e in self.appmodel.endpoints][:40]

    def _run_action(self, runner, act, history, evidence):
        """Execute one agent-proposed action (GET only) through the gated pipeline."""
        if self._actions >= self.max_total_actions:
            history.append({"note": "action budget exhausted", "executed": False})
            return
        method = str((act or {}).get("method", "GET")).upper()
        path = (act or {}).get("path")
        if not path:
            return
        self._actions += 1
        if method != "GET":   # the reasoning agent is read-only; writes need the Tier-2 approval path
            history.append({"action": {"method": method, "path": path},
                            "status": None, "note": "non-GET not permitted for the reasoning agent",
                            "executed": False})
            return
        r = runner.get(path, session=(act.get("session") if act else None),
                       query=(act.get("query") if act else None) or {}, payload_class="boundary-probe",
                       rationale="agent exploration", summary="agent probe")
        if r.evidence:
            evidence.extend(r.evidence)
        history.append({"action": {"method": "GET", "path": path, "query": (act or {}).get("query") or {}},
                        "status": r.status, "body": (r.body or "")[:600], "executed": r.executed})

    # -------------------------------------------------------------- explore
    def _explore(self, objective, confirmed_summary):
        runner = self._runner("agent-explorer")
        history: list = []
        evidence: list = []
        for _ in range(self.max_steps):
            d = self.brain.decide({"mode": "explore", "objective": objective,
                                   "endpoints": self._slim_endpoints(),
                                   "confirmed": confirmed_summary, "history": history})
            if d.get("conclude"):
                return d["conclude"], history, evidence
            if d.get("action"):
                self._run_action(runner, d["action"], history, evidence)
            if d.get("stop") or (not d.get("action") and not d.get("conclude")):
                break
        return None, history, evidence

    # -------------------------------------------------------------- critique
    def _critique(self, candidate, history, evidence):
        runner = self._runner("agent-critic")
        c1 = self.brain.decide({"mode": "critique", "phase": "propose-control",
                                "candidate": candidate, "history": history})
        if c1.get("action"):
            self._run_action(runner, c1["action"], history, evidence)
        c2 = self.brain.decide({"mode": "critique", "phase": "verdict",
                                "candidate": candidate, "history": history})
        verdict = c2.get("verdict") or c1.get("verdict") or "refuted"
        reason = c2.get("reason") or c1.get("reason") or "critic gave no reason"
        return verdict == "stands", reason

    # -------------------------------------------------------------- finding
    def _finding(self, cand, reason, evidence) -> Finding:
        f = Finding(
            engagement_id=self.pipeline.engagement_id,
            title=cand.get("title", "Agent-assessed logic flaw"),
            vuln_class=cand.get("vuln_class", "business-logic"),
            severity=cand.get("severity", "medium"),
            confidence="firm",                       # NOT 'confirmed' — reasoning, not proof
            state=State.EVIDENCE_FOUND,
            cwe=cand.get("cwe", ["CWE-840"]),         # CWE-840 Business Logic Errors
            owasp={"web_2025": ["A04:2021-Insecure Design"]},
            asset={"type": "web", "application": self.application,
                   "environment": "authorized", "target": self.target_url},
            endpoint={"method": "GET", "url": self.target_url + cand.get("endpoint_path", ""),
                      "auth_required": False},
            description=cand.get("description", ""),
            impact=cand.get("impact", ""),
            root_cause=cand.get("root_cause", ""),
            reproduction=Reproduction(prerequisites=["Reasoned by the business-logic agent"],
                                      steps=cand.get("steps", []), deterministic=False),
            remediation=Remediation(summary=cand.get("remediation_summary", "Enforce the intended business rule server-side."),
                                    type="code_patch", guidance=cand.get("remediation_guidance", ""),
                                    effort="medium"),
            references=["https://owasp.org/www-community/vulnerabilities/Business_logic_vulnerability"],
            compliance_control_refs=["SOC2:CC8.1"],
            dedupe_key=f"{self.application}:agent:{cand.get('title','logic')}",
            tags=["agent-assessed", "business-logic", "needs-human-review"],
            verification=Verification(
                method="agent-assessed", validated=False, validator="agent-critic",
                independent_reproduction=False, reproductions=0,
                false_positive_checks=[f"critic verdict: {reason}",
                                       "AGENT-ASSESSED — reasoning-based; human confirmation recommended "
                                       "(not an oracle-proven finding)"],
                confidence_score=0.6),
        )
        f.evidence.extend(evidence[:12])
        f.assert_consistent()
        return f

    # -------------------------------------------------------------- run
    def run(self, confirmed_findings=None) -> AgentResult:
        result = AgentResult()
        if not self.brain.can_reason():
            return result   # deterministic brain cannot do logic reasoning — honestly produce nothing
        confirmed_summary = [{"title": f.title, "class": f.vuln_class}
                             for f in (confirmed_findings or []) if f.verification.validated][:20]
        plan = self.brain.decide({"mode": "plan", "endpoints": self._slim_endpoints(),
                                  "confirmed": confirmed_summary})
        objectives = [o for o in (plan.get("objectives") or []) if isinstance(o, str)][: self.max_objectives]
        result.objectives = objectives
        for obj in objectives:
            cand, history, evidence = self._explore(obj, confirmed_summary)
            entry = {"objective": obj, "candidate": cand, "steps": len(history)}
            if cand:
                kept, reason = self._critique(cand, history, evidence)
                entry["verdict"] = "agent-assessed" if kept else "refuted-by-critic"
                entry["reason"] = reason
                if kept:
                    result.findings.append(self._finding(cand, reason, evidence))
            result.transcript.append(entry)
        return result
