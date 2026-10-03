"""Supervisor — the phase state machine (blueprint sections 9, 10).

Deterministic control flow with mandatory order and gates: recon -> map -> hypothesize ->
test -> validate. The supervisor is the only component that decides "what to test next",
always subject to the policy engine. It keeps a PTT-like plan (the hypothesis list with
status) as auditable working memory rather than a free-text scratchpad.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from ..runner import ProbeRunner
from ..scanners import security_headers_check
from ..schemas.finding import State
from ..util import gen_id, now_iso
from .test_worker import BolaIdorWorker


@dataclass
class ScanResult:
    findings: list = field(default_factory=list)
    hypotheses: list = field(default_factory=list)
    phase_log: list = field(default_factory=list)
    endpoints_tested: int = 0


class Supervisor:
    def __init__(self, pipeline, evidence_store, session_manager, validator, intel, appmodel,
                 host, port, scheme, target_url, application):
        self.pipeline = pipeline
        self.evidence = evidence_store
        self.sessions = session_manager
        self.validator = validator
        self.intel = intel
        self.appmodel = appmodel
        self.host = host
        self.port = port
        self.scheme = scheme
        self.target_url = target_url
        self.application = application

    def _log(self, result, phase, msg):
        result.phase_log.append({"ts": now_iso(), "phase": phase, "msg": msg})

    def _runner(self, phase, role="test-worker"):
        return ProbeRunner(self.pipeline, self.evidence, self.pipeline.engagement_id,
                           self.host, self.port, self.scheme, actor_role=role,
                           actor_profile="bola-idor", phase=phase)

    def run(self) -> ScanResult:
        result = ScanResult()

        # Phase: recon / liveness (Tier 0)
        recon = self._runner("recon")
        live = recon.get("/", session=None, payload_class="benign-read",
                         rationale="liveness probe", summary="liveness")
        self._log(result, "recon", f"liveness GET / -> {live.status if live.executed else 'blocked'}")

        # Phase: map (already built) — record surface
        ownable = self.appmodel.ownable_endpoints()
        self._log(result, "map", f"{len(self.appmodel.endpoints)} endpoints, {len(ownable)} ownable, "
                                 f"{len(self.appmodel.principals)} seeded principals")

        # Phase: built-in safe checks (security misconfiguration)
        headers_runner = self._runner("test")
        header_findings = security_headers_check(headers_runner, "/", self.target_url, self.application)
        for f in header_findings:
            result.findings.append(f)
        self._log(result, "test", f"security-headers check produced {len(header_findings)} finding(s)")

        # Phase: hypotheses (LLM proposes / deterministic fallback)
        hyps = self.intel.propose_hypotheses(self.appmodel.to_dict())
        for h in hyps:
            h.setdefault("id", gen_id("hyp"))
            h["status"] = "planned"
        result.hypotheses = hyps
        self._log(result, "hypothesize", f"{len(hyps)} hypothesis(es) proposed by {self.intel.name}")

        # Phase: test + validate (each hypothesis)
        worker = BolaIdorWorker(self._runner("test"), application=self.application, environment="authorized")
        for h in hyps:
            result.endpoints_tested += 1
            finding = worker.investigate(h, self.target_url)
            if finding is None:
                h["status"] = "blocked"
                self._log(result, "test", f"[{h['id']}] blocked by policy")
                continue
            if finding.state != State.EVIDENCE_FOUND:
                h["status"] = "no-signal"
                finding.state = State.DROPPED
                finding.status = "dropped"
                result.findings.append(finding)
                self._log(result, "test", f"[{h['id']}] no cross-account signal -> dropped")
                continue

            # GATE: independent validation (separate component, clean state)
            self._log(result, "validate", f"[{h['id']}] evidence found; handing to independent validator")
            validated = self.validator.validate(finding, h)
            h["status"] = "validated" if validated else "dropped-by-validator"
            h["finding_id"] = finding.id
            if validated:
                self._draft_narrative(finding, h)
            result.findings.append(finding)
            self._log(result, "validate",
                      f"[{h['id']}] validator verdict: {'CONFIRMED' if validated else 'dropped'} "
                      f"({finding.verification.reproductions} reproductions)")

        return result

    def _draft_narrative(self, finding, hyp):
        """Reporter role: draft prose from VALIDATED evidence only (never invents evidence)."""
        narr = self.intel.draft_finding_narrative({
            "endpoint_method": hyp["endpoint_method"],
            "endpoint_path": hyp["endpoint_path"],
            "object_type": hyp["object_type"],
        })
        finding.description = narr.get("description", finding.description)
        finding.impact = narr.get("impact", finding.impact)
        finding.root_cause = narr.get("root_cause", finding.root_cause)
        finding.remediation.summary = narr.get("remediation_summary", finding.remediation.summary)
        finding.remediation.guidance = narr.get("remediation_guidance", finding.remediation.guidance)
