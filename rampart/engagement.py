"""Engagement — the top-level facade that wires the deterministic + reasoning components.

Lifecycle: parse & validate the SECURITY.md scope (R1 gate, fail-closed) -> set up the
audit log / budget / session manager / executor / policy pipeline -> build the application
model -> run the supervisor (scan) -> optionally remediate (advisory) -> retest -> report.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from urllib.parse import urlparse

from .appmodel import build_model
from .audit import AuditLog
from .evidence import EvidenceStore
from .executor import HttpExecutor, SessionManager, FileSecretsProvider
from .executor.session import LoginConfig
from .intelligence import get_provider
from .policy import PolicyPipeline
from .policy.allowlist import default_resolver
from .policy.budget import BudgetTracker
from .reporting import ReportBuilder
from .remediation import Remediator
from .schemas.scope import EngagementScope, ScopeError
from .store import RunStore
from .validation import Validator
from .workers import Supervisor


@dataclass
class EngagementConfig:
    scope_file: str
    target: str
    work_dir: str = ".rampart"
    secrets_file: str = ""
    openapi: str = ""
    appmodel_seed: str = ""
    login_path: str = "/api/login"
    token_json_path: str = "token"
    intel: str = "deterministic"
    application: str = "target"
    repo: str = ""
    scanners: str = ""              # comma list of external adapters, e.g. "nuclei,semgrep" or "all"
    crawl: bool = False             # discover endpoints/params by crawling (no OpenAPI needed)
    crawl_max_pages: int = 40
    crawl_max_depth: int = 3
    exploit: bool = False           # demonstrate bounded, non-destructive impact for confirmed findings
    agents: bool = False            # run the multi-agent reasoning layer (business-logic / auth flows)
    oob: bool = False               # run the OOB collaborator for blind SSRF/XXE detection
    browser: bool = False           # run the optional headless-browser DOM-XSS pass ([browser] extra)
    llm_chat_path: str = "/chat"
    llm_input_field: str = "message"
    llm_output_field: str = "reply"
    llm_canary: str = ""
    approver: object = None
    resolver: object = None


class Engagement:
    def __init__(self, config: EngagementConfig):
        self.cfg = config
        self.scope = EngagementScope.from_file(config.scope_file)
        errs = self.scope.validate()
        if errs:
            raise ScopeError("scope contract failed validation (R1 gate, fail-closed):\n  - "
                             + "\n  - ".join(errs))

        u = urlparse(config.target)
        self.scheme = u.scheme or "http"
        self.host = u.hostname or "127.0.0.1"
        self.port = u.port or (443 if self.scheme == "https" else 80)
        self.target_url = f"{self.scheme}://{self.host}:{self.port}"

        # confirm the target itself is inside the authorized scope before doing anything
        if self.scope.host_scope(self.host) is None:
            raise ScopeError(f"target host {self.host!r} is not in the SECURITY.md scope")

        self.resolver = config.resolver or default_resolver
        self.store = RunStore(config.work_dir)
        self.audit = AuditLog(self.store.audit_path)
        self.evidence = EvidenceStore(self.store.evidence_dir)
        self.budget = BudgetTracker(self.scope.limits)

        secrets_path = config.secrets_file or os.path.join(os.path.dirname(config.scope_file), "secrets.json")
        self.secrets = FileSecretsProvider(secrets_path)
        login = LoginConfig(scheme=self.scheme, host=self.host, port=self.port,
                            path=config.login_path, token_json_path=config.token_json_path)
        self.sessions = SessionManager(self.scope, self.secrets, login, self.resolver, audit_log=self.audit)
        self.executor = HttpExecutor(self.sessions)
        self.pipeline = PolicyPipeline(self.scope, self.audit, self.budget, self.executor,
                                       resolver=self.resolver, approver=config.approver)

        self.intel = get_provider(config.intel, budget=self.budget)
        self.appmodel = build_model(self.scope, openapi_path=config.openapi or None,
                                    seed_path=config.appmodel_seed or None, intel=self.intel)
        self.validator = Validator(self.pipeline, self.evidence, self.sessions,
                                   self.host, self.port, self.scheme)
        from .scanners.adapters import build_adapters
        self.scanner_adapters = build_adapters(config.scanners, repo=config.repo)
        self.supervisor = Supervisor(self.pipeline, self.evidence, self.sessions, self.validator,
                                     self.intel, self.appmodel, self.host, self.port, self.scheme,
                                     self.target_url, config.application, scanners=self.scanner_adapters)

    # --------------------------------------------------------------- recon
    def recon(self):
        """Optional crawl to discover endpoints/params and fingerprint tech (scope-gated)."""
        self.recon_tech = []
        self.recon_pages = 0
        if not self.cfg.crawl:
            return
        from .recon import Crawler, merge_into_model
        from .runner import ProbeRunner
        runner = ProbeRunner(self.pipeline, self.evidence, self.pipeline.engagement_id,
                             self.host, self.port, self.scheme,
                             actor_role="mapper", actor_profile="crawler", phase="recon")
        crawler = Crawler(runner, self.scope, self.host, self.port, self.scheme,
                          max_pages=self.cfg.crawl_max_pages, max_depth=self.cfg.crawl_max_depth)
        crawl = crawler.crawl(["/"])
        added = merge_into_model(self.appmodel, crawl)
        self.recon_tech = crawl.tech
        self.recon_pages = crawl.pages_visited
        return {"pages": crawl.pages_visited, "added_endpoints": added, "tech": crawl.tech}

    # ------------------------------------------------------- correlation
    def _correlate(self, findings):
        from dataclasses import asdict
        from .correlation import correlate
        corr = correlate(findings, self.appmodel.to_dict(), getattr(self, "recon_tech", []))
        return corr, asdict(corr)

    # --------------------------------------------------------------- scan
    def run_scan(self):
        self.recon()
        result = self.supervisor.run()
        if self.cfg.oob:
            result.findings = result.findings + self.run_oob()
        if self.cfg.browser:
            result.findings = result.findings + self.run_browser()
        corr, corr_dict = self._correlate(result.findings)
        result.correlation = corr
        exploit_dicts = []
        if self.cfg.exploit:
            from dataclasses import asdict
            from .exploitation import ChainExecutor
            ex = ChainExecutor(self.pipeline, self.evidence, self.sessions,
                               self.host, self.port, self.scheme, self.target_url)
            result.exploit_proofs = ex.demonstrate(result.findings, result.hypotheses)
            exploit_dicts = [asdict(p) for p in result.exploit_proofs]
        agent_transcript = []
        if self.cfg.agents:
            ares = self.run_agents(confirmed_findings=result.findings)
            result.findings = result.findings + ares.findings
            agent_transcript = ares.transcript
        self.store.save_appmodel(self.appmodel)
        self.store.save_hypotheses(result.hypotheses)
        self.store.save_findings(result.findings)
        self.store.save_scan({
            "correlation": corr_dict,
            "exploitation": exploit_dicts,
            "agent_transcript": agent_transcript,
            "endpoints_tested": result.endpoints_tested,
            "hypotheses": result.hypotheses,
            "phase_log": result.phase_log,
            "classes_tested": result.classes_tested,
            "scanner_runs": result.scanner_runs,
            "plan": result.plan,
            "recon_tech": getattr(self, "recon_tech", []),
            "recon_pages": getattr(self, "recon_pages", 0),
            "budget": self.budget.snapshot(),
            "intel_provider": self.intel.name,
        })
        return result

    # ----------------------------------------------------------- browser
    def run_browser(self):
        """Optional headless-browser pass for DOM XSS (needs the [browser] extra + Chromium).

        Trust boundary: the browser issues its OWN requests (outside the policy pipeline), so it
        is only ever pointed at the already in-scope, authorized target URL."""
        from .browser import PlaywrightDriver, available, run_dom_xss_oracle
        if not available():
            return []
        from .schemas.finding import CVSS, Finding, Reproduction, State, Verification
        from .util import now_iso
        driver = PlaywrightDriver()
        findings = []
        for ep in self.appmodel.endpoints:
            if (ep.method or "GET").upper() != "GET":
                continue
            for p in (ep.parameters or []):
                if p.get("in") != "query" or not p.get("name"):
                    continue
                v = run_dom_xss_oracle(driver, self.target_url, ep.path, p["name"])
                if not v.validated:
                    continue
                f = Finding(
                    engagement_id=self.pipeline.engagement_id,
                    title=f"DOM-based XSS in '{p['name']}' on GET {ep.path}",
                    vuln_class="XSS", severity="high", confidence="confirmed", state=State.VALIDATED,
                    cwe=["CWE-79"], owasp={"web_2025": ["A03:2025-Injection"]},
                    cvss=CVSS(version="4.0", base_score=7.1, severity="high",
                              vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:L/VA:N/SC:L/SI:L/SA:N"),
                    asset={"type": "web", "application": self.cfg.application,
                           "environment": "authorized", "target": self.target_url},
                    endpoint={"method": "GET", "url": f"{self.target_url}{ep.path}",
                              "parameters": [{"name": p["name"], "in": "query"}], "auth_required": False},
                    description=(f"The '{p['name']}' parameter is written into the DOM by client-side "
                                 "JavaScript without sanitisation; injected script executes in the browser."),
                    impact="Script execution in the victim's browser session (session theft / account takeover).",
                    root_cause="Client-side code writes untrusted input into a dangerous DOM sink (e.g. innerHTML).",
                    reproduction=Reproduction(prerequisites=["A headless browser"],
                                              steps=[f"Load {ep.path}?{p['name']}=<payload>",
                                                     "Observe the injected script execute in the DOM"],
                                              deterministic=True),
                    references=["https://owasp.org/www-community/attacks/DOM_Based_XSS",
                                "https://cwe.mitre.org/data/definitions/79.html"],
                    compliance_control_refs=["SOC2:CC6.8", "ISO27001:A.8.26"],
                    dedupe_key=f"{self.cfg.application}:GET:{ep.path}:{p['name']}:dom-xss",
                    tags=["xss", "dom", "browser-confirmed"],
                    verification=Verification(method="headless-browser-execution", validated=True,
                                              validated_at=now_iso(),
                                              validator="browser-oracle", independent_reproduction=True,
                                              reproductions=v.reproductions,
                                              false_positive_checks=v.reasons + v.false_positive_checks,
                                              confidence_score=0.95))
                f.assert_consistent()
                findings.append(f)
        return findings

    # --------------------------------------------------------------- OOB
    def run_oob(self, timeout: float = 3.0):
        """Start a loopback OOB collaborator and confirm blind SSRF via out-of-band callbacks."""
        from .oob import OOBCollaborator, blind_ssrf_scan
        from .runner import ProbeRunner
        collaborator = OOBCollaborator()
        collaborator.start()
        try:
            runner = ProbeRunner(self.pipeline, self.evidence, self.pipeline.engagement_id,
                                 self.host, self.port, self.scheme, actor_role="oob-worker",
                                 actor_profile="blind-ssrf", phase="test")
            return blind_ssrf_scan(runner, collaborator, self.appmodel, self.target_url,
                                   self.cfg.application, timeout=timeout)
        finally:
            collaborator.stop()

    # ------------------------------------------------------------ agents
    def run_agents(self, brain=None, confirmed_findings=None):
        """Run the multi-agent reasoning layer. Returns an AgentResult (agent-assessed findings
        are tiered below oracle-'confirmed'). With the deterministic provider the brain cannot
        reason and this honestly returns nothing; pass a brain (e.g. MockBrain) or use an LLM intel."""
        from .agents import AgentBrain, AgentOrchestrator
        brain = brain or AgentBrain(self.intel)
        orch = AgentOrchestrator(self.pipeline, self.evidence, self.sessions, self.host, self.port,
                                 self.scheme, self.target_url, self.appmodel, brain,
                                 application=self.cfg.application)
        if confirmed_findings is None:
            confirmed_findings = self.store.load_findings()
        return orch.run([f for f in confirmed_findings if f.verification.validated])

    # --------------------------------------------------------------- LLM
    def run_llm(self):
        """Assess an authorized LLM endpoint against the OWASP LLM Top 10.

        Prompts are gated POSTs through the same policy pipeline; the model's reply is data
        checked by a deterministic marker/canary oracle, never executed."""
        from .runner import ProbeRunner
        from .llm import LLMAssessment, LLMClient
        runner = ProbeRunner(self.pipeline, self.evidence, self.pipeline.engagement_id,
                             self.host, self.port, self.scheme,
                             actor_role="llm-worker", actor_profile="llm", phase="test")
        client = LLMClient(runner, self.cfg.llm_chat_path, self.cfg.llm_input_field,
                           self.cfg.llm_output_field)
        assessment = LLMAssessment(client, canary=self.cfg.llm_canary,
                                   application=self.cfg.application, target_url=self.target_url,
                                   engagement_id=self.pipeline.engagement_id)
        res = assessment.run()
        _corr, corr_dict = self._correlate(res.findings)
        self.store.save_findings(res.findings)
        self.store.save_scan({
            "correlation": corr_dict,
            "endpoints_tested": len(res.probe_log),
            "hypotheses": [],
            "classes_tested": ["LLM"],
            "llm_probe_log": res.probe_log,
            "phase_log": [{"phase": "llm", "msg": f"{p['id']}: {p['result']}"} for p in res.probe_log],
            "budget": self.budget.snapshot(),
            "intel_provider": self.intel.name,
        })
        return res

    # -------------------------------------------------------- remediation
    def remediate(self):
        if not self.cfg.repo:
            return []
        remediator = Remediator(self.cfg.repo, self.intel, self.store.artifacts_dir)
        findings = self.store.load_findings()
        touched = []
        for f in findings:
            if f.vuln_class == "IDOR/BOLA" and f.verification.validated:
                otype = f.endpoint.get("object_type") or "Order"
                remediator.propose(f, otype)
                from .schemas.finding import State
                f.state = State.FIX_PROPOSED
                touched.append(f)
        self.store.save_findings(findings)
        return touched

    # ------------------------------------------------------------- retest
    def retest(self):
        findings = self.store.load_findings()
        hyps = {h.get("finding_id"): h for h in self.store.load_hypotheses() if h.get("finding_id")}
        results = []
        for f in findings:
            if f.vuln_class == "IDOR/BOLA" and f.verification.validated and f.id in hyps:
                outcome = self.validator.retest(f, hyps[f.id])
                results.append((f, outcome))
        self.store.save_findings(findings)
        return results

    # ------------------------------------------------------------- report
    def report(self, formats):
        findings = self.store.load_findings()
        scan = self.store.load_scan()
        appmodel = self.store.load_appmodel() or self.appmodel
        ok, _msg = self.audit.verify_chain()
        audit_count = len(self.audit.read_all())
        rb = ReportBuilder(findings, self.scope, appmodel, scan,
                           scan.get("budget", self.budget.snapshot()), audit_events=audit_count)
        written = {}
        renderers = {
            "json": ("report.json", rb.to_json),
            "sarif": ("report.sarif", rb.to_sarif),
            "md": ("report.md", rb.to_markdown),
            "markdown": ("report.md", rb.to_markdown),
            "html": ("report.html", rb.to_html),
            "compliance": ("compliance.md", rb.to_compliance),
            "soc2": ("soc2.md", rb.to_soc2),
        }
        for fmt in formats:
            if fmt not in renderers:
                continue
            name, fn = renderers[fmt]
            path = os.path.join(self.store.reports_dir, name)
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(fn())
            written[fmt] = path
        return written, rb, ok
