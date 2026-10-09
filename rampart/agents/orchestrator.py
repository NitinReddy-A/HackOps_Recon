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

import re
from dataclasses import dataclass, field

from ..runner import ProbeRunner
from ..schemas.audit import AuditEvent
from ..schemas.finding import Finding, Remediation, Reproduction, State, Verification
from ..schemas.toolcall import Decision
from ..util import scrub_secrets
from .harness import DecisionGuard, vet_action

_SEVERITIES = ("critical", "high", "medium", "low", "info")
_SEV_ALIASES = {"informational": "info", "moderate": "medium", "crit": "critical", "none": "info"}
_CWE = re.compile(r"^CWE-\d{1,5}$")


def _text(v, default: str = "", limit: int = 4000) -> str:
    """LLM-supplied prose -> a bounded string (anything else -> default)."""
    if isinstance(v, str):
        v = v.strip()
        return v[:limit] if v else default
    return default


def _severity(v) -> str:
    if not isinstance(v, str):
        return "medium"
    v = v.strip().lower()
    v = _SEV_ALIASES.get(v, v)
    return v if v in _SEVERITIES else "medium"


def _cwes(v, default) -> list:
    if isinstance(v, str):
        v = [v]
    if not isinstance(v, list):
        return list(default)
    out = []
    for c in v:
        if isinstance(c, str) and _CWE.match(c.strip().upper()) and c.strip().upper() not in out:
            out.append(c.strip().upper())
    return out[:5] or list(default)


def _steps(v) -> list:
    if isinstance(v, str):
        v = [v]
    if not isinstance(v, list):
        return []
    return [s.strip()[:500] for s in v if isinstance(s, str) and s.strip()][:20]


@dataclass
class AgentResult:
    findings: list = field(default_factory=list)
    transcript: list = field(default_factory=list)
    objectives: list = field(default_factory=list)
    coverage: dict = field(default_factory=dict)  # objective -> outcome (no objective silently missed)
    harness_stats: dict = field(default_factory=dict)


class AgentOrchestrator:
    def __init__(
        self,
        pipeline,
        evidence_store,
        session_manager,
        host,
        port,
        scheme,
        target_url,
        appmodel,
        brain,
        application="target",
        max_steps=6,
        max_objectives=4,
        max_total_actions=40,
    ):
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
        return ProbeRunner(
            self.pipeline,
            self.evidence,
            self.pipeline.engagement_id,
            self.host,
            self.port,
            self.scheme,
            actor_role=role,
            actor_profile="agent",
            phase="test",
        )

    def _slim_endpoints(self):
        return [
            {"method": e.method, "path": e.path, "params": [p.get("name") for p in (e.parameters or [])]}
            for e in self.appmodel.endpoints
        ][:40]

    def _refuse(self, role, act, reason, history):
        """Record a harness-level refusal: in the agent's history AND in the audit chain."""
        act = act if isinstance(act, dict) else {}
        method = str(act.get("method", "GET")).upper()[:16]
        path = str(act.get("path", ""))[:512]
        q = act.get("query") if isinstance(act.get("query"), dict) else {}
        history.append(
            {
                "action": {"method": method, "path": path},
                "status": None,
                "note": f"refused by the agent harness: {reason}",
                "executed": False,
            }
        )
        try:
            self.pipeline.audit.append(
                AuditEvent(
                    engagement_id=self.pipeline.engagement_id,
                    phase="test",
                    actor={"type": "agent", "agent_role": role, "profile": "agent"},
                    action={
                        "class_tier": 1,
                        "tool": "http",
                        "method": method,
                        "target_host": self.host,
                        "resolved_ip": "",
                        "path": path,
                        "params_redacted": {str(k)[:64]: str(v)[:256] for k, v in list(q.items())[:20]},
                        "use_session": None,
                        "payload_class": "boundary-probe",
                        "payload_hash": None,
                    },
                    policy_decision={
                        "decision": Decision.DENY,
                        "checks": {"agent_containment": "fail"},
                        "reason": f"agent-harness containment: {reason}",
                    },
                    intent={"rationale_summary": "agent-proposed action refused before execution"},
                    execution={"status": "blocked"},
                    budget=self.pipeline.budget.snapshot(),
                )
            )
        except Exception:  # noqa: BLE001 - auditing a refusal must never let the action through
            pass

    def _run_action(self, runner, act, history, evidence, role="agent-explorer"):
        """Execute one agent-proposed action (GET only) through the gated pipeline."""
        if self._actions >= self.max_total_actions:
            history.append({"note": "action budget exhausted", "executed": False})
            return
        if not isinstance(act, dict):
            return
        method = str(act.get("method", "GET")).upper()
        path = act.get("path")
        if not path:
            return
        self._actions += 1
        if method != "GET":  # the reasoning agent is read-only; writes need the Tier-2 approval path
            self._refuse(role, act, "non-GET not permitted for the reasoning agent", history)
            return
        why = vet_action(act, getattr(self.pipeline, "scope", None))
        if why:
            self._refuse(role, act, why, history)
            return
        query = {str(k): ("" if v is None else str(v)) for k, v in (act.get("query") or {}).items()}
        session = act.get("session") if isinstance(act.get("session"), str) else None
        r = runner.get(
            path,
            session=session,
            query=query,
            payload_class="boundary-probe",
            rationale="agent exploration",
            summary="agent probe",
        )
        if r.evidence:
            evidence.extend(r.evidence)
        history.append(
            {
                "action": {"method": "GET", "path": path, "query": query},
                "status": r.status,
                # target data goes to the model: scrub secret-looking substrings first
                "body": scrub_secrets((r.body or "")[:4000])[:600],
                "executed": r.executed,
            }
        )

    # -------------------------------------------------------------- explore
    def _explore(self, objective, confirmed_summary, guard):
        runner = self._runner("agent-explorer")
        history: list = []
        evidence: list = []
        guard.reset_loop_memory()
        outcome = "no-finding"
        for _ in range(self.max_steps):
            d, status = guard.decide(
                {
                    "mode": "explore",
                    "objective": objective,
                    "endpoints": self._slim_endpoints(),
                    "confirmed": confirmed_summary,
                    "history": history,
                }
            )
            if status == "invalid":
                self._audit_rejected(guard, "agent-explorer", history)
                history.append({"note": "stopped: invalid agent decision after repair"})
                outcome = "stopped-invalid"
                break
            if status == "repeat":
                history.append({"note": "stopped: agent repeated an action (no progress / loop)"})
                outcome = "stuck"
                break
            if d.get("conclude"):
                return d["conclude"], history, evidence, "concluded"
            if d.get("action"):
                self._run_action(runner, d["action"], history, evidence, "agent-explorer")
            if d.get("stop") or (not d.get("action") and not d.get("conclude")):
                break
        else:
            outcome = "max-steps"
        return None, history, evidence, outcome

    # -------------------------------------------------------------- critique
    def _audit_rejected(self, guard, role, history):
        rejected = getattr(guard, "last_rejected", None)
        guard.last_rejected = None
        action = rejected.get("action") if isinstance(rejected, dict) else None
        if isinstance(action, dict) and self._actions < self.max_total_actions:
            self._actions += 1
            self._refuse(role, action, "invalid/out-of-bounds action proposal", history)

    def _critique(self, candidate, history, evidence, guard=None):
        """Adversarial critic. Its decisions pass the same DecisionGuard validation as the explorer's
        (schema check, one repair, loop detection), and its control probe the same containment."""
        runner = self._runner("agent-critic")
        guard = guard or DecisionGuard(self.brain)
        c1, s1 = guard.decide(
            {"mode": "critique", "phase": "propose-control", "candidate": candidate, "history": history}
        )
        if s1 == "invalid":
            self._audit_rejected(guard, "agent-critic", history)
        elif s1 == "repeat":
            history.append({"note": "critic control repeated an earlier action — not executed"})
        elif c1.get("action"):
            self._run_action(runner, c1["action"], history, evidence, "agent-critic")
        c2, s2 = guard.decide(
            {"mode": "critique", "phase": "verdict", "candidate": candidate, "history": history}
        )
        if s2 == "invalid":
            self._audit_rejected(guard, "agent-critic", history)
        v2 = c2.get("verdict") if s2 != "invalid" else None
        v1 = c1.get("verdict") if s1 != "invalid" else None
        verdict = v2 or v1 or "refuted"  # no valid verdict -> fail closed (drop the candidate)
        reason = _text(c2.get("reason") if s2 != "invalid" else None) or _text(
            c1.get("reason") if s1 != "invalid" else None, "critic gave no valid verdict"
        )
        return verdict == "stands", reason[:1000]

    # -------------------------------------------------------------- finding
    def _finding(self, cand, reason, evidence) -> Finding:
        # Every field below comes from model output: clamp/validate it (never trust its types).
        cand = cand if isinstance(cand, dict) else {}
        title = _text(cand.get("title"), "Agent-assessed logic flaw", 200)
        ep_path = _text(cand.get("endpoint_path"), "", 512)
        if not ep_path.startswith("/") or "://" in ep_path or ep_path.startswith("//"):
            ep_path = ""
        f = Finding(
            engagement_id=self.pipeline.engagement_id,
            title=title,
            vuln_class=_text(cand.get("vuln_class"), "business-logic", 64),
            severity=_severity(cand.get("severity")),
            confidence="firm",  # NOT 'confirmed' — reasoning, not proof
            state=State.EVIDENCE_FOUND,
            cwe=_cwes(cand.get("cwe"), ["CWE-840"]),  # CWE-840 Business Logic Errors
            owasp={"web_2025": ["A04:2021-Insecure Design"]},
            asset={
                "type": "web",
                "application": self.application,
                "environment": "authorized",
                "target": self.target_url,
            },
            endpoint={
                "method": "GET",
                "url": self.target_url + ep_path,
                "auth_required": False,
            },
            description=_text(cand.get("description")),
            impact=_text(cand.get("impact")),
            root_cause=_text(cand.get("root_cause")),
            reproduction=Reproduction(
                prerequisites=["Reasoned by the business-logic agent"],
                steps=_steps(cand.get("steps")),
                deterministic=False,
            ),
            remediation=Remediation(
                summary=_text(
                    cand.get("remediation_summary"), "Enforce the intended business rule server-side.", 1000
                ),
                type="code_patch",
                guidance=_text(cand.get("remediation_guidance")),
                effort="medium",
            ),
            references=["https://owasp.org/www-community/vulnerabilities/Business_logic_vulnerability"],
            compliance_control_refs=["SOC2:CC8.1"],
            dedupe_key=f"{self.application}:agent:{title}",
            tags=["agent-assessed", "business-logic", "needs-human-review"],
            verification=Verification(
                method="agent-assessed",
                validated=False,
                validator="agent-critic",
                independent_reproduction=False,
                reproductions=0,
                false_positive_checks=[
                    f"critic verdict: {reason}",
                    "AGENT-ASSESSED — reasoning-based; human confirmation recommended "
                    "(not an oracle-proven finding)",
                ],
                confidence_score=0.6,
            ),
        )
        f.evidence.extend(evidence[:12])
        f.assert_consistent()
        return f

    # -------------------------------------------------------------- run
    def run(self, confirmed_findings=None) -> AgentResult:
        result = AgentResult()
        if not self.brain.can_reason():
            return result  # deterministic brain cannot do logic reasoning — honestly produce nothing
        confirmed_summary = [
            {"title": f.title, "class": f.vuln_class}
            for f in (confirmed_findings or [])
            if f.verification.validated
        ][:20]
        guard = DecisionGuard(self.brain)
        try:
            plan = self.brain.decide(
                {"mode": "plan", "endpoints": self._slim_endpoints(), "confirmed": confirmed_summary}
            )
        except Exception:  # noqa: BLE001 - a planning failure yields no objectives, not a crash
            plan = None
        raw_objectives = plan.get("objectives") if isinstance(plan, dict) else None
        if not isinstance(raw_objectives, list):
            raw_objectives = []
        objectives = []
        for o in raw_objectives:
            if isinstance(o, str) and o.strip() and o.strip()[:300] not in objectives:
                objectives.append(o.strip()[:300])
        objectives = objectives[: self.max_objectives]
        result.objectives = objectives
        for obj in objectives:
            try:
                cand, history, evidence, outcome = self._explore(obj, confirmed_summary, guard)
                entry = {"objective": obj, "steps": len(history), "outcome": outcome}
                if cand:
                    kept, reason = self._critique(cand, history, evidence, guard)
                    outcome = "agent-assessed" if kept else "refuted-by-critic"
                    entry["outcome"] = outcome
                    entry["reason"] = reason
                    if kept:
                        result.findings.append(self._finding(cand, reason, evidence))
            except Exception as exc:  # noqa: BLE001 - one objective must not sink the run
                outcome = "error"
                entry = {"objective": obj, "outcome": "error", "error": str(exc)}
            result.coverage[obj] = outcome
            result.transcript.append(entry)
        result.harness_stats = dict(guard.stats)
        return result
