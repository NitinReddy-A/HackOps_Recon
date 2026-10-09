"""Engagement — the top-level facade that wires the deterministic + reasoning components.

Lifecycle: parse & validate the rampart.scope.yaml scope (R1 gate, fail-closed) -> set up the
audit log / budget / session manager / executor / policy pipeline -> build the application
model -> run the supervisor (scan) -> optionally remediate (advisory) -> retest -> report.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from urllib.parse import urlparse

from .appmodel import build_model
from .audit import AuditLog
from .evidence import EvidenceStore
from .executor import FileSecretsProvider, HttpExecutor, SessionManager
from .executor.session import LoginConfig
from .intelligence import get_provider
from .policy import PolicyPipeline
from .policy.allowlist import default_resolver
from .policy.budget import BudgetTracker
from .remediation import Remediator
from .reporting import ReportBuilder
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
    scanners: str = ""  # comma list of external adapters, e.g. "nuclei,semgrep" or "all"
    crawl: bool = False  # discover endpoints/params by crawling (no OpenAPI needed)
    crawl_max_pages: int = 40
    crawl_max_depth: int = 3
    exploit: bool = False  # demonstrate bounded, non-destructive impact for confirmed findings
    agents: bool = False  # run the multi-agent reasoning layer (business-logic / auth flows)
    oob: bool = False  # run the OOB collaborator for blind SSRF/XXE detection
    browser: bool = False  # run the optional headless-browser DOM-XSS pass ([browser] extra)
    grpc: bool = False  # probe a gRPC endpoint (server reflection exposure; [grpc] extra)
    infra: bool = False  # live infrastructure / exposed-services scan (scope-gated TCP)
    authz: bool = False  # deeper auth checks (weak JWT secret, expiry-not-enforced)
    bizlogic: bool = False  # deterministic business-logic checks (economic/parameter tampering)
    api_scan: bool = False  # deeper API checks (HTTP verb tampering, GraphQL depth)
    # --- scan stages (separation of concerns; a "mode" sets these) ---
    do_dast: bool = True  # black-box HTTP testing (the oracle classes + misconfig)
    do_sast: bool = False  # white-box source scanning (native AST + adapters)
    do_sca: bool = False  # dependency + secret scanning
    do_iac: bool = False  # white-box IaC / cloud-config scanning (Terraform/CFN/K8s/Docker)
    sca_online: bool = False  # match pinned deps against OSV.dev (operator opt-in; sends names)
    parallel: int = 0  # orchestrator worker cap (0 = scope.limits.max_concurrent_workers)
    active: bool = False  # allow gated write/active probes (mass assignment, GraphQL, …)
    store_url: str = ""  # multi-tenant store, e.g. sqlite:///runs.db or postgresql://…
    sast_since: str = ""  # diff-aware SAST: scan only .py files changed vs this git ref
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
            raise ScopeError(
                "scope contract failed validation (R1 gate, fail-closed):\n  - " + "\n  - ".join(errs)
            )

        u = urlparse(config.target)
        self.scheme = u.scheme or "http"
        self.host = u.hostname or "127.0.0.1"
        self.port = u.port or (443 if self.scheme == "https" else 80)
        self.target_url = f"{self.scheme}://{self.host}:{self.port}"

        # confirm the target itself is inside the authorized scope before doing anything
        if self.scope.host_scope(self.host) is None:
            raise ScopeError(f"target host {self.host!r} is not in the rampart.scope.yaml scope")

        self.resolver = config.resolver or default_resolver
        if config.store_url:
            from .store import SqlRunStore

            self.store = SqlRunStore(
                config.store_url, config.work_dir, engagement=self.scope.authorization.ticket or "engagement"
            )
        else:
            self.store = RunStore(config.work_dir)
        self.audit = AuditLog(self.store.audit_path)
        self.evidence = EvidenceStore(self.store.evidence_dir)
        self.budget = BudgetTracker(self.scope.limits)

        secrets_path = config.secrets_file or os.path.join(os.path.dirname(config.scope_file), "secrets.json")
        self.secrets = FileSecretsProvider(secrets_path)
        login = LoginConfig(
            scheme=self.scheme,
            host=self.host,
            port=self.port,
            path=config.login_path,
            token_json_path=config.token_json_path,
        )
        self.sessions = SessionManager(self.scope, self.secrets, login, self.resolver, audit_log=self.audit)
        self.executor = HttpExecutor(self.sessions)
        # --active authorises gated write/active probes (Tier-2) on the in-scope target.
        effective_approver = config.approver
        if effective_approver is None and config.active:
            effective_approver = lambda req, dec: {"granted": True, "approver_user_id": "cli:--active"}
        self.pipeline = PolicyPipeline(
            self.scope,
            self.audit,
            self.budget,
            self.executor,
            resolver=self.resolver,
            approver=effective_approver,
        )

        self.intel = get_provider(config.intel, budget=self.budget)
        self.appmodel = build_model(
            self.scope,
            openapi_path=config.openapi or None,
            seed_path=config.appmodel_seed or None,
            intel=self.intel,
        )
        self.validator = Validator(
            self.pipeline, self.evidence, self.sessions, self.host, self.port, self.scheme
        )
        from .scanners.adapters import build_adapters

        self.scanner_adapters = build_adapters(config.scanners, repo=config.repo)
        self.supervisor = Supervisor(
            self.pipeline,
            self.evidence,
            self.sessions,
            self.validator,
            self.intel,
            self.appmodel,
            self.host,
            self.port,
            self.scheme,
            self.target_url,
            config.application,
            scanners=self.scanner_adapters,
            active=config.active,
            max_workers=(config.parallel or None),
        )

    # --------------------------------------------------------------- recon
    def recon(self):
        """Optional crawl to discover endpoints/params and fingerprint tech (scope-gated)."""
        self.recon_tech = []
        self.recon_pages = 0
        if not self.cfg.crawl:
            return
        from .recon import Crawler, merge_into_model
        from .runner import ProbeRunner

        runner = ProbeRunner(
            self.pipeline,
            self.evidence,
            self.pipeline.engagement_id,
            self.host,
            self.port,
            self.scheme,
            actor_role="mapper",
            actor_profile="crawler",
            phase="recon",
        )
        crawler = Crawler(
            runner,
            self.scope,
            self.host,
            self.port,
            self.scheme,
            max_pages=self.cfg.crawl_max_pages,
            max_depth=self.cfg.crawl_max_depth,
        )
        crawl = crawler.crawl(["/"])
        added = merge_into_model(self.appmodel, crawl)
        self.recon_tech = crawl.tech
        self.recon_pages = crawl.pages_visited
        return {"pages": crawl.pages_visited, "added_endpoints": added, "tech": crawl.tech}

    # ------------------------------------------------------------- SAST
    def run_sast(self):
        """White-box source scan (native AST sink patterns). Diff-aware when --since is set."""
        from .sast import scan_source

        only = None
        if self.cfg.sast_since:
            from .sast.scanner import changed_py_files

            only = changed_py_files(self.cfg.repo, self.cfg.sast_since)
            if only is not None and not only:
                return []  # nothing changed vs the base ref
        return scan_source(self.cfg.repo, self.pipeline.engagement_id, only_files=only)

    def run_sca(self):
        """Software Composition Analysis: secrets + dependency inventory, and — when the operator
        opts in with --sca-online — full OSV advisory matching with concrete upgrade remediation."""
        from .sast import scan_dependencies, scan_secrets

        findings = scan_secrets(self.cfg.repo, self.pipeline.engagement_id) + scan_dependencies(
            self.cfg.repo, self.pipeline.engagement_id
        )
        if self.cfg.sca_online:
            from .sca import scan_sca

            # The operator opted into external SCA network, so also fetch EPSS/KEV exploit intel.
            findings += scan_sca(self.cfg.repo, self.pipeline.engagement_id, online=True, intel_online=True)
        return findings

    def run_iac(self):
        """White-box IaC / cloud-config scan (Terraform, CloudFormation, Kubernetes, Dockerfile)."""
        from .iac import scan_iac

        return scan_iac(self.cfg.repo, engagement_id=self.pipeline.engagement_id)

    def run_grpc(self):
        """Probe the target as a gRPC endpoint for server-reflection exposure (CWE-200).

        Trust boundary: like the headless browser, the gRPC channel issues its OWN requests
        outside the HTTP policy pipeline, so it is only ever pointed at the in-scope target."""
        from .grpc_scan import available, scan_grpc

        if not available():
            return []
        grpc_scheme = "grpcs" if self.scheme in ("https", "grpcs") else "grpc"
        # --active enables per-RPC checks: unauthenticated method invocation (read-ish methods only,
        # with a negative control). Reflection + method enumeration + plaintext check run regardless.
        return scan_grpc(
            self.host, self.port, grpc_scheme, self.cfg.application, self.target_url, active=self.cfg.active
        )

    def run_infra(self):
        """Live, scope-gated, non-destructive infrastructure / exposed-services scan.

        Probes sensitive service ports on the authorized host (TCP connect + passive banner),
        defence-in-depth gated by the resolver + scope IP allowlist. Trust boundary: it opens its
        OWN sockets outside the HTTP policy pipeline, so it only ever targets the in-scope host."""
        from .infra import SENSITIVE_SERVICES, scan_infra

        ports = sorted(set(SENSITIVE_SERVICES) | {443, 8443, self.port})
        return scan_infra(
            self.host,
            ports,
            engagement_id=self.pipeline.engagement_id,
            target_url=self.target_url,
            application=self.cfg.application,
            resolver=self.resolver,
            scope=self.scope,
        )

    def run_authz(self):
        """Deeper authentication checks (weak JWT HMAC secret, expiry-not-enforced) on protected GETs."""
        from .authz import authz_scan
        from .runner import ProbeRunner

        runner = ProbeRunner(
            self.pipeline,
            self.evidence,
            self.pipeline.engagement_id,
            self.host,
            self.port,
            self.scheme,
            actor_role="authz-worker",
            actor_profile="authz",
            phase="test",
        )
        return authz_scan(
            runner, self.appmodel, self.target_url, self.cfg.application, self.pipeline.engagement_id
        )

    def run_bizlogic(self):
        """Deterministic business-logic checks (economic/parameter tampering, workflow-step-skip)."""
        from .bizlogic import bizlogic_scan
        from .runner import ProbeRunner

        runner = ProbeRunner(
            self.pipeline,
            self.evidence,
            self.pipeline.engagement_id,
            self.host,
            self.port,
            self.scheme,
            actor_role="bizlogic-worker",
            actor_profile="bizlogic",
            phase="test",
        )
        return bizlogic_scan(
            runner, self.appmodel, self.target_url, self.cfg.application, self.pipeline.engagement_id
        )

    def run_apiscan(self):
        """Deeper API checks (HTTP method/verb tampering, GraphQL depth)."""
        from .apiscan import api_scan
        from .runner import ProbeRunner

        runner = ProbeRunner(
            self.pipeline,
            self.evidence,
            self.pipeline.engagement_id,
            self.host,
            self.port,
            self.scheme,
            actor_role="api-worker",
            actor_profile="api-scan",
            phase="test",
        )
        return api_scan(
            runner, self.appmodel, self.target_url, self.cfg.application, self.pipeline.engagement_id
        )

    def _correlate_sast_dast(self, findings):
        """Link runtime-confirmed DAST findings to a source location sharing the CWE —
        'proven at runtime AND located in source' is the highest-confidence result."""
        sast = [f for f in findings if "sast" in f.tags and f.affected_code]
        if not sast:
            return
        by_cwe = {}
        for s in sast:
            for c in s.cwe:
                by_cwe.setdefault(c, []).append(s)
        for f in findings:
            if "sast" in f.tags or not f.verification.validated:
                continue
            for c in f.cwe:
                match = by_cwe.get(c)
                if not match:
                    continue
                s = match[0]
                if not (f.affected_code and getattr(f.affected_code, "file", "")):
                    f.affected_code = s.affected_code
                if "source-correlated" not in f.tags:
                    f.tags.append("source-correlated")
                    f.verification.false_positive_checks.append(
                        f"source-correlated: same {c} located at {s.affected_code.file}:"
                        f"{s.affected_code.start_line} (confirmed at runtime AND present in source)"
                    )
                break

    # ------------------------------------------------------- correlation
    def _correlate(self, findings):
        from dataclasses import asdict

        from .correlation import correlate

        corr = correlate(findings, self.appmodel.to_dict(), getattr(self, "recon_tech", []))
        return corr, asdict(corr)

    # --------------------------------------------------------------- scan
    def run_scan(self):
        from .workers.supervisor import ScanResult

        self.recon()
        # Black-box DAST stage (the oracle classes + misconfig + external scanners).
        if self.cfg.do_dast:
            result = self.supervisor.run()
        else:
            result = ScanResult()
            result.phase_log.append({"phase": "dast", "msg": "skipped (stage disabled)"})
        # White-box stages (source + dependencies/secrets + IaC) feed the same finding set.
        self.sast_findings = []
        if self.cfg.do_sast:
            self.sast_findings += self.run_sast()
        if self.cfg.do_sca:
            self.sast_findings += self.run_sca()
        if self.cfg.do_iac:
            self.sast_findings += self.run_iac()
        if self.sast_findings:
            result.findings = result.findings + self.sast_findings
            if "SAST" not in result.classes_tested:
                result.classes_tested = list(result.classes_tested) + ["SAST"]
        if self.cfg.oob:
            result.findings = result.findings + self.run_oob()
        if self.cfg.browser:
            result.findings = result.findings + self.run_browser()
        if self.cfg.grpc:
            gfindings = self.run_grpc()
            result.findings = result.findings + gfindings
            if gfindings and "gRPC" not in result.classes_tested:
                result.classes_tested = list(result.classes_tested) + ["gRPC"]
        # Deeper opt-in stages: API verb-tampering, business logic, deep auth, and live infra.
        for flag, runner_fn, label in (
            (self.cfg.api_scan, self.run_apiscan, "API-SCAN"),
            (self.cfg.bizlogic, self.run_bizlogic, "BUSINESS-LOGIC"),
            (self.cfg.authz, self.run_authz, "AUTHZ"),
            (self.cfg.infra, self.run_infra, "INFRA"),
        ):
            if not flag:
                continue
            extra = runner_fn()
            result.findings = result.findings + extra
            if extra and label not in result.classes_tested:
                result.classes_tested = list(result.classes_tested) + [label]
        # correlate (includes SAST<->DAST correlation below)
        self._correlate_sast_dast(result.findings)
        corr, corr_dict = self._correlate(result.findings)
        result.correlation = corr
        exploit_dicts = []
        if self.cfg.exploit:
            from dataclasses import asdict

            from .exploitation import ChainExecutor

            ex = ChainExecutor(
                self.pipeline,
                self.evidence,
                self.sessions,
                self.host,
                self.port,
                self.scheme,
                self.target_url,
            )
            result.exploit_proofs = ex.demonstrate(result.findings, result.hypotheses)
            exploit_dicts = [asdict(p) for p in result.exploit_proofs]
        agent_transcript, agent_coverage, agent_harness = [], {}, {}
        if self.cfg.agents:
            ares = self.run_agents(confirmed_findings=result.findings)
            result.findings = result.findings + ares.findings
            agent_transcript = ares.transcript
            agent_coverage = ares.coverage
            agent_harness = ares.harness_stats
        self.store.save_appmodel(self.appmodel)
        self.store.save_hypotheses(result.hypotheses)
        self.store.save_findings(result.findings)
        self.store.save_scan(
            {
                "correlation": corr_dict,
                "exploitation": exploit_dicts,
                "agent_transcript": agent_transcript,
                "agent_coverage": agent_coverage,
                "agent_harness": agent_harness,
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
            }
        )
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
            for p in ep.parameters or []:
                if p.get("in") != "query" or not p.get("name"):
                    continue
                v = run_dom_xss_oracle(driver, self.target_url, ep.path, p["name"])
                if not v.validated:
                    continue
                f = Finding(
                    engagement_id=self.pipeline.engagement_id,
                    title=f"DOM-based XSS in '{p['name']}' on GET {ep.path}",
                    vuln_class="XSS",
                    severity="high",
                    confidence="confirmed",
                    state=State.VALIDATED,
                    cwe=["CWE-79"],
                    owasp={"web_2025": ["A03:2025-Injection"]},
                    cvss=CVSS(
                        version="4.0",
                        base_score=7.1,
                        severity="high",
                        vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:L/VA:N/SC:L/SI:L/SA:N",
                    ),
                    asset={
                        "type": "web",
                        "application": self.cfg.application,
                        "environment": "authorized",
                        "target": self.target_url,
                    },
                    endpoint={
                        "method": "GET",
                        "url": f"{self.target_url}{ep.path}",
                        "parameters": [{"name": p["name"], "in": "query"}],
                        "auth_required": False,
                    },
                    description=(
                        f"The '{p['name']}' parameter is written into the DOM by client-side "
                        "JavaScript without sanitisation; injected script executes in the browser."
                    ),
                    impact="Script execution in the victim's browser session (session theft / account takeover).",
                    root_cause="Client-side code writes untrusted input into a dangerous DOM sink (e.g. innerHTML).",
                    reproduction=Reproduction(
                        prerequisites=["A headless browser"],
                        steps=[
                            f"Load {ep.path}?{p['name']}=<payload>",
                            "Observe the injected script execute in the DOM",
                        ],
                        deterministic=True,
                    ),
                    references=[
                        "https://owasp.org/www-community/attacks/DOM_Based_XSS",
                        "https://cwe.mitre.org/data/definitions/79.html",
                    ],
                    compliance_control_refs=["SOC2:CC6.8", "ISO27001:A.8.26"],
                    dedupe_key=f"{self.cfg.application}:GET:{ep.path}:{p['name']}:dom-xss",
                    tags=["xss", "dom", "browser-confirmed"],
                    verification=Verification(
                        method="headless-browser-execution",
                        validated=True,
                        validated_at=now_iso(),
                        validator="browser-oracle",
                        independent_reproduction=True,
                        reproductions=v.reproductions,
                        false_positive_checks=v.reasons + v.false_positive_checks,
                        confidence_score=0.95,
                    ),
                )
                f.assert_consistent()
                findings.append(f)

        # Stored XSS (write-half): store a canary payload, then render the display page and detect
        # execution. Writes require --active; render is out-of-pipeline (in-scope URL only).
        if self.cfg.active:
            import secrets as _secrets

            from .browser import run_stored_xss_oracle
            from .browser.engine import _canary_payload
            from .runner import ProbeRunner

            store_hints = ("comment", "post", "message", "review", "feedback", "guestbook", "note")
            runner = ProbeRunner(
                self.pipeline,
                self.evidence,
                self.pipeline.engagement_id,
                self.host,
                self.port,
                self.scheme,
                actor_role="browser-stored",
                actor_profile="stored-xss",
                phase="test",
            )
            for ep in self.appmodel.endpoints:
                if (ep.method or "GET").upper() not in ("POST", "PUT"):
                    continue
                if not any(h in ep.path.lower() for h in store_hints):
                    continue
                token = "RAMPART_STORED_" + _secrets.token_hex(6)
                payload = _canary_payload(token)
                w = runner.post(
                    ep.path,
                    {"text": payload, "comment": payload, "message": payload, "body": payload},
                    payload_class="boundary-probe",
                    rationale="stored-XSS: persist a canary payload",
                    summary="stored-xss write",
                )
                read_url = f"{self.target_url}{ep.path}"
                v = run_stored_xss_oracle(driver, bool(w.executed), read_url, token)
                if not v.validated:
                    continue
                f = Finding(
                    engagement_id=self.pipeline.engagement_id,
                    title=f"Stored XSS via {ep.method} {ep.path}",
                    vuln_class="XSS",
                    severity="high",
                    confidence="confirmed",
                    state=State.VALIDATED,
                    cwe=["CWE-79"],
                    owasp={"web_2025": ["A03:2025-Injection"]},
                    cvss=CVSS(
                        version="4.0",
                        base_score=8.2,
                        severity="high",
                        vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:L/VA:N/SC:H/SI:L/SA:N",
                    ),
                    asset={
                        "type": "web",
                        "application": self.cfg.application,
                        "environment": "authorized",
                        "target": self.target_url,
                    },
                    endpoint={"method": ep.method, "url": read_url, "auth_required": False},
                    description=(
                        f"A payload stored via {ep.method} {ep.path} is rendered unescaped and "
                        "executes in every viewer's browser (stored XSS)."
                    ),
                    impact="Persistent script execution against all viewers — mass session theft / account takeover.",
                    root_cause="Stored user input is rendered without output encoding.",
                    reproduction=Reproduction(
                        prerequisites=["A headless browser"],
                        steps=[
                            f"POST a script payload to {ep.path}",
                            "Load the display page; observe execution",
                        ],
                        deterministic=True,
                    ),
                    references=[
                        "https://owasp.org/www-community/attacks/xss/",
                        "https://cwe.mitre.org/data/definitions/79.html",
                    ],
                    compliance_control_refs=["SOC2:CC6.8", "ISO27001:A.8.26"],
                    dedupe_key=f"{self.cfg.application}:{ep.method}:{ep.path}:stored-xss",
                    tags=["xss", "stored", "browser-confirmed"],
                    verification=Verification(
                        method="headless-browser-execution",
                        validated=True,
                        validated_at=now_iso(),
                        validator="browser-oracle",
                        independent_reproduction=True,
                        reproductions=v.reproductions,
                        false_positive_checks=v.reasons + v.false_positive_checks,
                        confidence_score=0.95,
                    ),
                )
                f.assert_consistent()
                findings.append(f)
        return findings

    # --------------------------------------------------------------- OOB
    def run_oob(self, timeout: float = 3.0):
        """Start a loopback OOB collaborator and confirm blind SSRF via out-of-band callbacks."""
        from .oob import OOBCollaborator, blind_ssrf_scan, blind_xxe_scan
        from .runner import ProbeRunner

        collaborator = OOBCollaborator()
        collaborator.start()
        try:
            runner = ProbeRunner(
                self.pipeline,
                self.evidence,
                self.pipeline.engagement_id,
                self.host,
                self.port,
                self.scheme,
                actor_role="oob-worker",
                actor_profile="blind-ssrf",
                phase="test",
            )
            out = blind_ssrf_scan(
                runner, collaborator, self.appmodel, self.target_url, self.cfg.application, timeout=timeout
            )
            # XXE uses POST (external entity → collaborator) — only when writes are authorized (--active)
            if self.cfg.active:
                out += blind_xxe_scan(
                    runner,
                    collaborator,
                    self.appmodel,
                    self.target_url,
                    self.cfg.application,
                    timeout=timeout,
                )
            return out
        finally:
            collaborator.stop()

    # ------------------------------------------------------------ agents
    def run_agents(self, brain=None, confirmed_findings=None):
        """Run the multi-agent reasoning layer. Returns an AgentResult (agent-assessed findings
        are tiered below oracle-'confirmed'). With the deterministic provider the brain cannot
        reason and this honestly returns nothing; pass a brain (e.g. MockBrain) or use an LLM intel."""
        from .agents import AgentBrain, AgentOrchestrator

        brain = brain or AgentBrain(self.intel)
        orch = AgentOrchestrator(
            self.pipeline,
            self.evidence,
            self.sessions,
            self.host,
            self.port,
            self.scheme,
            self.target_url,
            self.appmodel,
            brain,
            application=self.cfg.application,
        )
        if confirmed_findings is None:
            confirmed_findings = self.store.load_findings()
        return orch.run([f for f in confirmed_findings if f.verification.validated])

    # --------------------------------------------------------------- LLM
    def run_llm(self):
        """Assess an authorized LLM endpoint against the OWASP LLM Top 10.

        Prompts are gated POSTs through the same policy pipeline; the model's reply is data
        checked by a deterministic marker/canary oracle, never executed."""
        from .llm import LLMAssessment, LLMClient
        from .runner import ProbeRunner

        runner = ProbeRunner(
            self.pipeline,
            self.evidence,
            self.pipeline.engagement_id,
            self.host,
            self.port,
            self.scheme,
            actor_role="llm-worker",
            actor_profile="llm",
            phase="test",
        )
        client = LLMClient(
            runner, self.cfg.llm_chat_path, self.cfg.llm_input_field, self.cfg.llm_output_field
        )
        assessment = LLMAssessment(
            client,
            canary=self.cfg.llm_canary,
            application=self.cfg.application,
            target_url=self.target_url,
            engagement_id=self.pipeline.engagement_id,
        )
        res = assessment.run()
        _corr, corr_dict = self._correlate(res.findings)
        self.store.save_findings(res.findings)
        self.store.save_scan(
            {
                "correlation": corr_dict,
                "endpoints_tested": len(res.probe_log),
                "hypotheses": [],
                "classes_tested": ["LLM"],
                "llm_probe_log": res.probe_log,
                "phase_log": [{"phase": "llm", "msg": f"{p['id']}: {p['result']}"} for p in res.probe_log],
                "budget": self.budget.snapshot(),
                "intel_provider": self.intel.name,
            }
        )
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
    def report_builder(self) -> ReportBuilder:
        """Build a ReportBuilder from the persisted run — the single source every surface (CLI,
        SDK, MCP, PR comment) renders from, so they all produce identical output."""
        findings = self.store.load_findings()
        scan = self.store.load_scan()
        appmodel = self.store.load_appmodel() or self.appmodel
        audit_count = len(self.audit.read_all())
        return ReportBuilder(
            findings,
            self.scope,
            appmodel,
            scan,
            scan.get("budget", self.budget.snapshot()),
            audit_events=audit_count,
        )

    def report(self, formats):
        ok, _msg = self.audit.verify_chain()
        rb = self.report_builder()
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
