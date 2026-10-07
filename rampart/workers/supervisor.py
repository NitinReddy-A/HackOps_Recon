"""Supervisor — the phase state machine (blueprint sections 9, 10).

Deterministic control flow with mandatory order and gates: recon -> map -> hypothesize ->
test -> validate. The supervisor is the only component that decides "what to test next",
always subject to the policy engine. It keeps a PTT-like plan (the hypothesis list with
status) as auditable working memory rather than a free-text scratchpad.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from ..agents import run_planner
from ..runner import ProbeRunner
from ..scanners import misconfig_checks, security_headers_check, sensitive_files_check
from ..schemas.finding import State
from ..util import gen_id, now_iso
from .test_worker import BolaIdorWorker
from .web_worker import WEB_CLASSES, WebWorker


@dataclass
class ScanResult:
    findings: list = field(default_factory=list)
    hypotheses: list = field(default_factory=list)
    phase_log: list = field(default_factory=list)
    endpoints_tested: int = 0
    classes_tested: list = field(default_factory=list)
    scanner_runs: list = field(default_factory=list)
    plan: dict = field(default_factory=dict)
    correlation: object = None
    exploit_proofs: list = field(default_factory=list)


class Supervisor:
    # Classes that send writes/active probes — only tested when --active is set.
    ACTIVE_CLASSES = {"MASS_ASSIGNMENT", "GRAPHQL", "XXE"}

    def __init__(self, pipeline, evidence_store, session_manager, validator, intel, appmodel,
                 host, port, scheme, target_url, application, scanners=None, active=False):
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
        self.scanners = scanners or []
        self.active = active

    def _log(self, result, phase, msg):
        result.phase_log.append({"ts": now_iso(), "phase": phase, "msg": msg})

    def _runner(self, phase, role="test-worker", profile="supervisor"):
        return ProbeRunner(self.pipeline, self.evidence, self.pipeline.engagement_id,
                           self.host, self.port, self.scheme, actor_role=role,
                           actor_profile=profile, phase=phase)

    def _worker_for(self, vuln_class):
        if vuln_class in WEB_CLASSES:
            return WebWorker(self._runner("test", profile=vuln_class),
                             application=self.application, environment="authorized")
        if vuln_class == "IDOR/BOLA":
            return BolaIdorWorker(self._runner("test", profile="bola-idor"),
                                  application=self.application, environment="authorized")
        return None

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

        # Phase: built-in safe checks (security misconfiguration — observation IS the oracle)
        misc_runner = self._runner("test", profile="misconfig")
        misc_findings = security_headers_check(misc_runner, "/", self.target_url, self.application)
        misc_findings += misconfig_checks(misc_runner, self.appmodel, self.target_url,
                                          self.application, self.sessions)
        misc_findings += sensitive_files_check(misc_runner, self.target_url, self.application)
        result.findings.extend(misc_findings)
        self._log(result, "test", f"built-in misconfiguration checks produced {len(misc_findings)} finding(s)")

        # Phase: hypotheses — access-control (LLM/deterministic) + input-fuzzing (deterministic enum)
        appmodel_d = self.appmodel.to_dict()
        hyps = list(self.intel.propose_hypotheses(appmodel_d))
        hyps += list(self.intel.propose_web_hypotheses(appmodel_d))
        if not self.active:
            hyps = [h for h in hyps if h.get("vuln_class") not in self.ACTIVE_CLASSES]
        for h in hyps:
            h.setdefault("id", gen_id("hyp"))
            h["status"] = "planned"
        result.hypotheses = hyps
        classes = sorted({h["vuln_class"] for h in hyps})
        result.classes_tested = classes
        self._log(result, "hypothesize",
                  f"{len(hyps)} hypothesis(es) across {len(classes)} class(es) [{', '.join(classes)}] "
                  f"via {self.intel.name}")

        # Phase: plan — the planner agent prioritises classes (reasoning backend; deterministic fallback)
        plan = run_planner(self.intel, appmodel_d, result.scanner_runs, classes)
        result.plan = plan
        order = {c: i for i, c in enumerate(plan.get("order", classes))}
        hyps.sort(key=lambda h: order.get(h["vuln_class"], 99))
        self._log(result, "plan", f"planner order: {', '.join(plan.get('order', classes))}")

        # Phase: test + validate (each hypothesis routed to its worker + independent oracle)
        for h in hyps:
            result.endpoints_tested += 1
            worker = self._worker_for(h["vuln_class"])
            if worker is None:
                h["status"] = "no-worker"
                self._log(result, "test", f"[{h['id']}] no worker for class {h['vuln_class']} -> skipped")
                continue
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
                self._log(result, "test", f"[{h['id']}] no initial signal -> dropped")
                continue

            # GATE: independent validation (separate component, clean state)
            validated = self.validator.validate(finding, h)
            h["status"] = "validated" if validated else "dropped-by-validator"
            h["finding_id"] = finding.id
            if validated and finding.vuln_class == "IDOR/BOLA":
                self._draft_narrative(finding, h)
            result.findings.append(finding)
            self._log(result, "validate",
                      f"[{h['id']}:{h['vuln_class']}] {'CONFIRMED' if validated else 'dropped'} "
                      f"({finding.verification.reproductions} reproductions)")

        # Phase: external OSS scanner adapters (graceful — skipped if the tool is not installed)
        for adapter in self.scanners:
            run_info = {"scanner": adapter.name, "available": False, "findings": 0, "note": ""}
            try:
                if not adapter.is_available():
                    run_info["note"] = adapter.install_hint
                    self._log(result, "scan", f"{adapter.name}: not installed — skipped ({adapter.install_hint})")
                else:
                    run_info["available"] = True
                    sfindings = adapter.run(self.appmodel, self.target_url, self.application)
                    for f in sfindings:
                        f.engagement_id = self.pipeline.engagement_id
                    result.findings.extend(sfindings)
                    run_info["findings"] = len(sfindings)
                    self._log(result, "scan", f"{adapter.name}: {len(sfindings)} finding(s) ingested")
            except Exception as exc:  # noqa: BLE001 - a flaky external tool must never break the run
                run_info["note"] = f"error: {exc}"
                self._log(result, "scan", f"{adapter.name}: error ({exc}) — skipped")
            result.scanner_runs.append(run_info)

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
