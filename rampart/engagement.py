"""Engagement — the top-level facade that wires the deterministic + reasoning components.

Lifecycle: parse & validate the rampart.scope.yaml scope (R1 gate, fail-closed) -> set up the
audit log / budget / session manager / executor / policy pipeline -> build the application
model -> run the supervisor (scan) -> optionally remediate (advisory) -> retest -> report.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from urllib.parse import urlparse, urlsplit

from .appmodel import build_model
from .audit import AuditLog
from .evidence import EvidenceStore
from .executor import FileSecretsProvider, HttpExecutor, SessionManager
from .executor.credentials import DictSecretsProvider
from .executor.session import LoginConfig
from .intelligence import get_provider
from .policy import PolicyPipeline
from .policy.allowlist import default_resolver
from .policy.budget import BudgetTracker
from .remediation import Remediator
from .reporting import ReportBuilder
from .reporting.status import is_dropped, is_validated
from .runner import ProbeStats
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
    deep: bool = False  # finding-driven escalation: a validated finding spawns bounded deep-scan follow-ups
    escalate_max_depth: int = 2  # how many escalation hops (0 disables, same as deep=False)
    escalate_max_total: int = 24  # cap on follow-up tests across the whole run
    escalate_max_per_finding: int = 6  # cap on follow-ups from any single finding
    store_url: str = ""  # multi-tenant store, e.g. sqlite:///runs.db or postgresql://…
    sast_since: str = ""  # diff-aware SAST: scan only .py files changed vs this git ref
    llm_chat_path: str = "/chat"
    llm_input_field: str = "message"
    llm_output_field: str = "reply"
    llm_canary: str = ""
    oob_collaborator_url: str = ""  # externally reachable OOB collaborator base URL (remote targets)
    # White-box only (sast/sca/iac without --target): validate the scope contract but never
    # contact a target — every network stage is skipped and the executor refuses all requests.
    offline: bool = False
    approver: object = None
    resolver: object = None


HTTP_SCHEMES = ("http", "https")
GRPC_SCHEMES = ("grpc", "grpcs")
REPORT_FORMATS = {
    "json": ("report.json", "to_json"),
    "sarif": ("report.sarif", "to_sarif"),
    "md": ("report.md", "to_markdown"),
    "markdown": ("report.md", "to_markdown"),
    "html": ("report.html", "to_html"),
    "compliance": ("compliance.md", "to_compliance"),
    "soc2": ("soc2.md", "to_soc2"),
}

# Stages that contact the target (skipped entirely in offline / white-box-only mode).
_NETWORK_STAGES = (
    "crawl",
    "oob",
    "browser",
    "grpc",
    "infra",
    "authz",
    "bizlogic",
    "api_scan",
    "exploit",
    "agents",
)


def normalize_formats(formats) -> list[str]:
    """Lower-case, de-duplicate and validate report formats (a comma string or a list).

    Raises ``ValueError`` listing the valid formats on an unknown one."""
    if isinstance(formats, str):
        formats = formats.split(",")
    out = []
    for f in formats or []:
        f = str(f).strip().lower()
        if not f:
            continue
        if f not in REPORT_FORMATS:
            raise ValueError(f"unknown report format {f!r} (valid: {', '.join(sorted(REPORT_FORMATS))})")
        if f not in out:
            out.append(f)
    return out


def parse_target(target: str, allow_grpc: bool = False) -> tuple[str, str, int]:
    """Parse and validate a target base URL -> (scheme, host, port). Raises ScopeError.

    A scheme is mandatory (``127.0.0.1:8080`` is refused rather than silently becoming port 80),
    the host must be non-empty and the port must be 1-65535. ``grpc://``/``grpcs://`` are only
    accepted for the gRPC probe and then require an explicit port."""
    raw = str(target or "").strip()
    if not raw:
        raise ScopeError("no target given")
    allowed = HTTP_SCHEMES + (GRPC_SCHEMES if allow_grpc else ())
    try:
        u = urlparse(raw)
    except ValueError as exc:
        raise ScopeError(f"target {raw!r} is not a valid URL: {exc}") from None
    scheme = (u.scheme or "").lower()
    if scheme not in allowed or not u.netloc:
        raise ScopeError(
            f"target {raw!r} must be an absolute URL with a scheme ({' or '.join(allowed)}), "
            "e.g. http://127.0.0.1:8080"
        )
    host = (u.hostname or "").lower()
    if not host:
        raise ScopeError(f"target {raw!r} has no hostname")
    try:
        port = u.port
    except ValueError:
        raise ScopeError(f"target {raw!r} has an invalid port (must be 1-65535)") from None
    if port is None:
        if scheme in GRPC_SCHEMES:
            raise ScopeError(f"gRPC target {raw!r} needs an explicit port (e.g. grpc://host:50051)")
        port = 443 if scheme == "https" else 80
    if not 1 <= port <= 65535:
        raise ScopeError(f"target {raw!r} has an invalid port {port} (must be 1-65535)")
    return scheme, host, port


def has_stored_run(work_dir: str) -> bool:
    """True if ``work_dir`` holds a stored run (findings.json or scan.json). Creates nothing."""
    return any(os.path.isfile(os.path.join(work_dir or "", n)) for n in ("findings.json", "scan.json"))


def stored_run_target(work_dir: str) -> str:
    """The target URL recorded in ``<work_dir>/scan.json`` ("" if absent/unreadable)."""
    try:
        with open(os.path.join(work_dir or "", "scan.json"), encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return ""
    t = data.get("target") if isinstance(data, dict) else ""
    return t if isinstance(t, str) else ""


class _OfflineExecutor:
    """Executor for white-box-only runs: refuses every request (defence in depth)."""

    def __init__(self, sessions):
        self.sessions = sessions

    def execute(self, action, resolved_ip):  # noqa: ARG002
        raise RuntimeError("offline (white-box) mode: network requests are disabled")


class Engagement:
    def __init__(self, config: EngagementConfig):
        self.cfg = config
        self.scope = EngagementScope.from_file(config.scope_file)
        errs = self.scope.validate()
        if errs:
            raise ScopeError(
                "scope contract failed validation (R1 gate, fail-closed):\n  - " + "\n  - ".join(errs)
            )

        self.offline = bool(config.offline)
        if self.offline and not str(config.target or "").strip():
            # white-box only: no target at all (sast/sca/iac without --target). With a target, an
            # offline run still validates it against the scope below, but never contacts it.
            self.scheme, self.host, self.port, self.target_url = "", "", 0, ""
        else:
            grpc_only = bool(config.grpc) and not config.do_dast
            self.scheme, self.host, self.port = parse_target(config.target, allow_grpc=grpc_only)
            netloc_host = f"[{self.host}]" if ":" in self.host else self.host  # IPv6 literal
            self.target_url = f"{self.scheme}://{netloc_host}:{self.port}"
            # confirm the target itself (host AND port) is inside the authorized scope first
            hs = self.scope.host_scope(self.host)
            if hs is None:
                raise ScopeError(f"target host {self.host!r} is not in the rampart.scope.yaml scope")
            if self.port not in hs.ports:
                raise ScopeError(
                    f"target port {self.port} is not authorized for {self.host!r} by the scope "
                    f"(allowed ports: {hs.ports})"
                )
        if config.repo and not os.path.isdir(config.repo):
            raise ScopeError(f"--repo {config.repo!r} is not an existing directory")

        self.resolver = config.resolver or default_resolver
        if config.store_url:
            from .store import SqlRunStore

            self.store = SqlRunStore(
                config.store_url, config.work_dir, engagement=self.scope.authorization.ticket or "engagement"
            )
        else:
            self.store = RunStore(config.work_dir)
        self.audit = AuditLog(self.store.audit_path)
        # a corrupt/tampered log must fail at startup (AuditLogCorrupt), not on the first request
        self.audit.ensure_appendable()
        self.evidence = EvidenceStore(self.store.evidence_dir)
        # the work-dir KILL file engages the kill switch (checked on every request / LLM call)
        self.budget = BudgetTracker.for_work_dir(self.scope.limits, config.work_dir)

        self.secrets = self._secrets_provider(config, self.scope)
        login = LoginConfig(
            scheme=self.scheme or "http",
            host=self.host,
            port=self.port,
            path=config.login_path,
            token_json_path=config.token_json_path,
        )
        self.sessions = SessionManager(self.scope, self.secrets, login, self.resolver, audit_log=self.audit)
        self.executor = _OfflineExecutor(self.sessions) if self.offline else HttpExecutor(self.sessions)
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
        # every seeded-account login goes through the policy choke-point (scope + budget + audit)
        self.sessions.attach_pipeline(self.pipeline)
        self.probe_stats = ProbeStats()
        self.pipeline.probe_stats = self.probe_stats
        self._stage_log: list = []

        self.intel = get_provider(config.intel, budget=self.budget)  # ValueError on an unknown name
        try:
            self.appmodel = build_model(
                self.scope,
                openapi_path=config.openapi or None,
                seed_path=config.appmodel_seed or None,
                intel=self.intel,
            )
        except FileNotFoundError:
            raise
        except (ValueError, TypeError, AttributeError, KeyError) as exc:
            what = "malformed JSON" if isinstance(exc, json.JSONDecodeError) else type(exc).__name__
            raise ValueError(f"could not load --openapi / --appmodel-seed ({what}): {exc}") from None
        self.validator = Validator(
            self.pipeline, self.evidence, self.sessions, self.host, self.port, self.scheme
        )
        from .scanners.adapters import build_adapters

        self.scanner_adapters = build_adapters(
            config.scanners, repo=config.repo, scope=self.scope, active=config.active
        )
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
            escalate=config.deep,
            escalation_caps={
                "max_depth": config.escalate_max_depth,
                "max_total": config.escalate_max_total,
                "max_per_finding": config.escalate_max_per_finding,
            },
        )

    @staticmethod
    def _secrets_provider(config, scope):
        """Test-account secrets. An explicit --secrets file must exist; otherwise secrets.json next
        to the scope is used when present, and a black-box scope with no test_accounts needs none."""
        if config.secrets_file:
            return FileSecretsProvider(config.secrets_file)
        default = os.path.join(os.path.dirname(os.path.abspath(config.scope_file)), "secrets.json")
        if os.path.exists(default) or scope.test_accounts:
            return FileSecretsProvider(default)  # raises FileNotFoundError naming the expected path
        return DictSecretsProvider({})

    # ------------------------------------------------------------ status
    def intel_status(self) -> dict:
        """What the reasoning backend actually did (surfaced in scan.json, the CLI and MCP)."""
        intel = self.intel
        name = getattr(intel, "name", "deterministic")
        degraded = bool(getattr(intel, "degraded", False))
        calls = int(getattr(intel, "calls", 0) or 0)
        effective = name
        if degraded and name != "deterministic":
            effective = (
                f"{name} (degraded: deterministic fallback)"
                if not calls
                else f"{name} (partially degraded: deterministic fallback for some calls)"
            )
        return {
            "requested": self.cfg.intel,
            "provider": name,
            "effective": effective,
            "degraded": degraded,
            "degraded_reasons": list(getattr(intel, "degraded_reasons", []) or []),
            "notes": list(getattr(intel, "notes", []) or []),
            "calls": calls,
        }

    def budget_status(self) -> dict:
        snap = self.budget.snapshot()
        snap["denied_total"] = self.budget.denied_total()
        return snap

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
    def _note(self, phase: str, msg: str) -> None:
        """Queue a phase-log entry from a stage that runs outside the supervisor."""
        from .util import now_iso

        self._stage_log.append({"ts": now_iso(), "phase": phase, "msg": msg})

    def run_sast(self):
        """White-box source scan (native AST sink patterns). Diff-aware when --since is set."""
        from .sast import scan_source
        from .sast import scanner as sast_scanner

        only = None
        if self.cfg.sast_since:
            only = sast_scanner.changed_py_files(self.cfg.repo, self.cfg.sast_since)
            status = getattr(sast_scanner.changed_py_files, "last_status", "")
            if only is None:
                why = {
                    "invalid-ref": f"since: ref {self.cfg.sast_since!r} invalid",
                    "not-a-git-repo": "since: --repo is not a git work tree",
                    "git-unavailable": "since: git unavailable",
                }.get(status, f"since: {status or 'diff unavailable'}")
                self._note("sast", f"warning: {why} → full scan")
            elif not only:
                self._note("sast", f"since {self.cfg.sast_since}: no .py files changed — SAST skipped")
                return []  # nothing changed vs the base ref
            else:
                self._note("sast", f"since {self.cfg.sast_since}: scanning {len(only)} changed .py file(s)")
        findings = scan_source(self.cfg.repo, self.pipeline.engagement_id, only_files=only)
        for n in list(getattr(sast_scanner, "last_scan_notes", []) or []):
            self._note("sast", n)
        self._note("sast", f"native SAST: {len(findings)} finding(s)")
        return findings

    def run_sca(self):
        """Software Composition Analysis: secrets + dependency inventory, and — when the operator
        opts in with --sca-online — full OSV advisory matching with concrete upgrade remediation."""
        from .sast import scan_dependencies, scan_secrets
        from .sast import secrets as sast_secrets

        findings = scan_secrets(self.cfg.repo, self.pipeline.engagement_id)
        for n in list(getattr(sast_secrets, "last_scan_notes", []) or []):
            self._note("sca", n)
        deps = scan_dependencies(self.cfg.repo, self.pipeline.engagement_id)
        self._note(
            "sca", f"secrets: {len(findings)} finding(s) · dependency inventory: {len(deps)} finding(s)"
        )
        findings += deps
        if self.cfg.sca_online:
            from .sca import enrich as sca_enrich
            from .sca import parsers as sca_parsers
            from .sca import scan_sca
            from .sca import scanner as sca_scanner

            # The operator opted into external SCA network, so also fetch EPSS/KEV exploit intel.
            osv = scan_sca(self.cfg.repo, self.pipeline.engagement_id, online=True, intel_online=True)
            for mod, attr in (
                (sca_scanner, "last_scan_notes"),
                (sca_parsers, "last_collect_notes"),
                (sca_enrich, "last_enrich_notes"),
            ):
                for n in list(getattr(mod, attr, []) or []):
                    self._note("sca", n)
            self._note("sca", f"OSV advisory matching: {len(osv)} finding(s)")
            findings += osv
        return findings

    def run_iac(self):
        """White-box IaC / cloud-config scan (Terraform, CloudFormation, Kubernetes, Dockerfile)."""
        from .iac import scan_iac

        findings = scan_iac(self.cfg.repo, engagement_id=self.pipeline.engagement_id)
        self._note("iac", f"IaC scan: {len(findings)} finding(s)")
        return findings

    def _outcome(self, phase: str, out):
        """Log a side-channel engine's ScanOutcome (skip reason + notes) and return its findings."""
        from .infra.sidechannel import skip_reason_of

        why = skip_reason_of(out)
        if why:
            self._note(phase, why)
        for n in list(getattr(out, "notes", []) or []):
            self._note(phase, n)
        return list(out or [])

    def run_grpc(self):
        """Probe the target as a gRPC endpoint for server-reflection exposure (CWE-200).

        Trust boundary: the gRPC channel issues its OWN requests outside the HTTP policy pipeline,
        so scan_grpc re-checks the scope (host, scoped port, resolved IPs) and audits + budgets
        every RPC through a side-channel guard."""
        from .grpc_scan import available, install_hint, scan_grpc
        from .infra.sidechannel import ScanOutcome

        if not available():
            return self._outcome("grpc", ScanOutcome(skip_reason=f"grpc: skipped — {install_hint}"))
        grpc_scheme = "grpcs" if self.scheme in ("https", "grpcs") else "grpc"
        # --active enables per-RPC checks: unauthenticated method invocation (read-ish methods only,
        # with a negative control). Reflection + method enumeration + plaintext check run regardless.
        out = scan_grpc(
            self.host,
            self.port,
            grpc_scheme,
            self.cfg.application,
            self.target_url,
            active=self.cfg.active,
            engagement_id=self.pipeline.engagement_id,
            scope=self.scope,
            resolver=self.resolver,
            audit=self.audit,
            budget=self.budget,
        )
        return self._outcome("grpc", out)

    def run_infra(self):
        """Live, scope-gated, non-destructive infrastructure / exposed-services scan.

        Probes the catalogued sensitive service ports that the scope authorizes for the target
        host (TCP connect + passive banner), gated by the resolver + scope IP allowlist and
        audited + budgeted per connection. Trust boundary: it opens its OWN sockets outside the
        HTTP policy pipeline, so it only ever targets the in-scope host and scoped ports."""
        from .infra import scan_infra

        out = scan_infra(
            self.host,
            None,  # every catalogued port, intersected with the scope's ports for this host
            engagement_id=self.pipeline.engagement_id,
            target_url=self.target_url,
            application=self.cfg.application,
            resolver=self.resolver,
            scope=self.scope,
            audit=self.audit,
            budget=self.budget,
        )
        return self._outcome("infra", out)

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
            runner,
            self.appmodel,
            self.target_url,
            self.cfg.application,
            self.pipeline.engagement_id,
            active=self.cfg.active,
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
    def _completeness(self, result) -> None:
        """Mark ``result`` incomplete when the run could not actually assess the target.

        A DAST/HTTP run in which no request was executed (target down, or every request blocked
        by policy) or a killed run must never read as a clean "0 findings" result."""
        if self.offline or not result.complete:
            return
        if self.budget.killed:
            result.mark_incomplete(f"kill switch engaged: {self.budget.kill_reason}")
            return
        c = self.cfg
        if not (c.do_dast or c.crawl or c.authz or c.bizlogic or c.api_scan or c.oob):
            return
        st = self.probe_stats.snapshot()
        if st["executed"]:
            return
        if st["errors"]:
            result.mark_incomplete(f"target unreachable: {st['last_error'] or 'no request completed'}")
        elif st["blocked"]:
            result.mark_incomplete(f"all requests blocked by policy (last: {st['last_blocked']})")
        elif c.do_dast:
            result.mark_incomplete("no request was executed against the target")

    def scan_summary(self, result) -> dict:
        """The scan.json status block shared by every run type."""
        return {
            "status": "complete" if result.complete else "incomplete",
            "incomplete_reason": result.incomplete_reason,
            "target": self.target_url,
            "offline": self.offline,
            "repo": os.path.abspath(self.cfg.repo) if self.cfg.repo else "",
            "requests": self.probe_stats.snapshot(),
            "budget": self.budget_status(),
            "intel": self.intel_status(),
            "intel_provider": self.intel_status()["effective"],
            # surfaces an opt-in Postgres->SQLite fallback (empty for the normal path) so the
            # report/caller can see that evidence did not land in the configured store.
            "store_warnings": list(getattr(self.store, "warnings", []) or []),
        }

    def run_scan(self):
        from .workers.supervisor import ScanResult

        self._stage_log = []
        self.recon_tech, self.recon_pages = [], 0
        self.browser_discovered = 0
        cfg = self.cfg
        if self.offline:
            wanted = [n for n in _NETWORK_STAGES if getattr(cfg, n, False)]
            if cfg.do_dast or wanted:
                self._note(
                    "offline",
                    "white-box only (no --target): skipped network stage(s) "
                    + ", ".join((["dast"] if cfg.do_dast else []) + wanted),
                )
        else:
            self.recon()
            # JS/SPA route discovery (needs --browser + Playwright): harvest endpoints from the
            # rendered DOM + fetch/XHR activity and merge them BEFORE the DAST stage, so the normal
            # oracles then test SPA/client-rendered routes like any crawled endpoint.
            if cfg.browser:
                self.browser_discovery()
        # Black-box DAST stage (the oracle classes + misconfig + external scanners).
        if cfg.do_dast and not self.offline:
            result = self.supervisor.run()
        else:
            result = ScanResult()
            result.phase_log.append({"phase": "dast", "msg": "skipped (stage disabled)"})
            if self.scanner_adapters:
                # white-box adapters (semgrep, bandit, gitleaks, trivy fs, ...) still run; tools
                # that send traffic to the target are skipped when DAST is off
                self.supervisor.run_adapters(result, allow_target_network=False)
        # White-box stages (source + dependencies/secrets + IaC) feed the same finding set.
        self.sast_findings = []
        if cfg.repo:
            if cfg.do_sast:
                self.sast_findings += self.run_sast()
            if cfg.do_sca or cfg.sca_online:
                self.sast_findings += self.run_sca()
            if cfg.do_iac:
                self.sast_findings += self.run_iac()
        elif cfg.do_sast or cfg.do_sca or cfg.do_iac or cfg.sca_online:
            self._note("sast", "white-box stages skipped: no --repo given")
        if self.sast_findings:
            result.findings = result.findings + self.sast_findings
            if "SAST" not in result.classes_tested:
                result.classes_tested = list(result.classes_tested) + ["SAST"]

        network_ok = not self.offline and result.complete
        if not self.offline and not result.complete:
            wanted = [n for n in _NETWORK_STAGES if getattr(cfg, n, False) and n != "crawl"]
            if wanted:
                self._note("scan", "target unreachable — skipped " + ", ".join(wanted))
        if network_ok and cfg.oob:
            result.findings = result.findings + self.run_oob()
        if network_ok and cfg.browser:
            result.findings = result.findings + self.run_browser()
        if network_ok and cfg.grpc:
            gfindings = self.run_grpc()
            result.findings = result.findings + gfindings
            if gfindings and "gRPC" not in result.classes_tested:
                result.classes_tested = list(result.classes_tested) + ["gRPC"]
        # Deeper opt-in stages: API verb-tampering, business logic, deep auth, and live infra.
        for flag, runner_fn, label in (
            (cfg.api_scan, self.run_apiscan, "API-SCAN"),
            (cfg.bizlogic, self.run_bizlogic, "BUSINESS-LOGIC"),
            (cfg.authz, self.run_authz, "AUTHZ"),
            (cfg.infra, self.run_infra, "INFRA"),
        ):
            if not flag or not network_ok:
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
        if network_ok and cfg.exploit:
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
        if network_ok and cfg.agents:
            ares = self.run_agents(confirmed_findings=result.findings)
            result.findings = result.findings + ares.findings
            agent_transcript = ares.transcript
            agent_coverage = ares.coverage
            agent_harness = ares.harness_stats

        self._completeness(result)
        intel = self.intel_status()
        if intel["degraded"]:
            self._note(
                "intel",
                f"warning: {intel['provider']} degraded → deterministic fallback ("
                + "; ".join(intel["degraded_reasons"] or ["unknown reason"])
                + ")",
            )
        for n in intel["notes"]:
            self._note("intel", n)
        denied = self.budget.denied_total()
        if denied:
            self._note(
                "budget", f"warning: {denied} request/LLM call(s) denied by the budget: {self.budget.denials}"
            )
        if not result.complete:
            self._note("scan", f"INCOMPLETE: {result.incomplete_reason}")
        result.phase_log.extend(self._stage_log)

        self.store.save_appmodel(self.appmodel)
        self.store.save_hypotheses(result.hypotheses)
        self.store.save_findings(result.findings)
        summary = {
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
            "browser_discovered": getattr(self, "browser_discovered", 0),
        }
        summary.update(self.scan_summary(result))
        self.store.save_scan(summary)
        return result

    # ------------------------------------------------- browser discovery
    def browser_discovery(self):
        """Optional JS/SPA route discovery (needs the [browser] extra + Chromium).

        Renders the target in the headless browser, harvests endpoints from the POST-JS DOM
        (anchors + form actions) and from the page's fetch/XHR/document network activity, then
        merges them into the application model with the SAME ``merge_into_model`` the crawler uses
        — so the normal oracles then test these SPA/client-rendered routes like any other endpoint.

        Scope-gated: the browser's own sub-requests are route-guarded by the scope (``allow``) and
        each is audited + budgeted (``on_request``), exactly like :meth:`run_browser`. A clean skip
        (with skip_reason noted) when the extra/Chromium is absent — never raises."""
        self.browser_discovered = 0
        if not self.cfg.browser:
            return None
        from .browser import (
            PlaywrightDriver,
            audited_on_request,
            browser_discover,
            browser_skip_reason,
        )
        from .infra.sidechannel import SideChannelGuard
        from .recon import merge_into_model

        why = browser_skip_reason()
        if why:
            self._note("browser", why)
            return None
        allow = self._browser_allow()
        guard = SideChannelGuard(
            audit=self.audit,
            budget=self.budget,
            engagement_id=self.pipeline.engagement_id,
            tool="browser",
            actor_role="browser-discover",
        )
        on_request = audited_on_request(guard)
        crawl = browser_discover(PlaywrightDriver(), self.target_url, allow=allow, on_request=on_request)
        added = merge_into_model(self.appmodel, crawl)
        self.browser_discovered = added
        self._note(
            "browser",
            f"JS/SPA route discovery: rendered {crawl.pages_visited} page(s), "
            f"added {added} endpoint(s) to the application model",
        )
        return {"pages": crawl.pages_visited, "added_endpoints": added}

    # ----------------------------------------------------------- browser
    def run_browser(self):
        """Optional headless-browser pass for DOM XSS (needs the [browser] extra + Chromium).

        Trust boundary: the browser issues its OWN requests (outside the policy pipeline), so it
        is only ever pointed at the already in-scope, authorized target URL."""
        from .browser import PlaywrightDriver, audited_on_request, browser_skip_reason, run_dom_xss_oracle
        from .infra.sidechannel import SideChannelGuard

        why = browser_skip_reason()
        if why:
            self._note("browser", why)
            return []
        from .schemas.finding import CVSS, Finding, Reproduction, State, Verification
        from .util import now_iso

        # The browser's own sub-requests are route-guarded by the scope (allow) and every one is
        # audited + budgeted (on_request), like the HTTP pipeline does for Rampart's own probes.
        allow = self._browser_allow()
        guard = SideChannelGuard(
            audit=self.audit,
            budget=self.budget,
            engagement_id=self.pipeline.engagement_id,
            tool="browser",
            actor_role="browser-worker",
        )
        on_request = audited_on_request(guard)
        driver = PlaywrightDriver()
        findings = []
        for ep in self.appmodel.endpoints:
            if (ep.method or "GET").upper() != "GET":
                continue
            if self.scope.path_excluded(ep.path):
                continue
            for p in ep.parameters or []:
                if p.get("in") != "query" or not p.get("name"):
                    continue
                v = run_dom_xss_oracle(
                    driver, self.target_url, ep.path, p["name"], allow=allow, on_request=on_request
                )
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
                if self.scope.path_excluded(ep.path):
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
                v = run_stored_xss_oracle(
                    driver, bool(w.executed), read_url, token, allow=allow, on_request=on_request
                )
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

    def _browser_allow(self):
        """Request predicate for the headless browser: the same host/port/IP + scheme/path/method
        scope checks the policy pipeline applies (falls back to same-origin on any setup error).
        Non-network URLs (about:, data:, blob:) are allowed; everything else fails closed."""
        from .browser import same_origin_allow
        from .policy import allowlist, scope_validator
        from .schemas.toolcall import ToolAction

        try:
            scope, resolver = self.scope, self.resolver
        except Exception:  # noqa: BLE001
            return same_origin_allow(self.target_url)

        def allow(url: str, method: str = "GET") -> bool:
            try:
                u = urlsplit(url or "")
                if not u.scheme or u.scheme in ("about", "data", "blob", "javascript"):
                    return True
                if u.scheme not in HTTP_SCHEMES or not u.hostname:
                    return False
                port = u.port or (443 if u.scheme == "https" else 80)
                action = ToolAction(
                    method=str(method or "GET").upper(),
                    target_host=u.hostname.lower(),
                    port=port,
                    scheme=u.scheme,
                    path=u.path or "/",
                )
                if not allowlist.check(scope, action, resolver).ok:
                    return False
                return scope_validator.check(scope, action).ok
            except Exception:  # noqa: BLE001 - fail closed
                return False

        return allow

    # --------------------------------------------------------------- OOB
    def run_oob(self, timeout: float = 3.0):
        """Start a loopback OOB collaborator and confirm blind SSRF via out-of-band callbacks."""
        from .oob import OOBCollaborator, blind_ssrf_scan, blind_xxe_scan, oob_skip_reason
        from .runner import ProbeRunner

        public = (self.cfg.oob_collaborator_url or "").strip()
        listen_port = 0
        if public:
            try:
                listen_port = urlsplit(public).port or 0
            except ValueError:
                self._note("oob", f"oob: skipped — invalid --oob-collaborator-url {public!r}")
                return []
        collaborator = OOBCollaborator(port=listen_port, public_url=public)
        why = oob_skip_reason(self.target_url, collaborator)
        if why:
            self._note("oob", why)
            return []
        try:
            collaborator.start()
        except OSError as exc:
            self._note("oob", f"oob: skipped — collaborator could not listen on port {listen_port}: {exc}")
            return []
        self._note(
            "oob",
            f"collaborator listening on 127.0.0.1:{collaborator.port} (advertised {collaborator.base_url})",
        )
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
            out = self._outcome(
                "oob",
                blind_ssrf_scan(
                    runner,
                    collaborator,
                    self.appmodel,
                    self.target_url,
                    self.cfg.application,
                    timeout=timeout,
                ),
            )
            # XXE uses POST (external entity → collaborator) — only when writes are authorized (--active)
            if self.cfg.active:
                out += self._outcome(
                    "oob",
                    blind_xxe_scan(
                        runner,
                        collaborator,
                        self.appmodel,
                        self.target_url,
                        self.cfg.application,
                        timeout=timeout,
                    ),
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
        from .workers.supervisor import ScanResult

        status = ScanResult()
        counts = getattr(res, "counts", {}) or {}
        if self.budget.killed:
            status.mark_incomplete(f"kill switch engaged: {self.budget.kill_reason}")
        elif not counts.get("executed", 0):
            st = self.probe_stats.snapshot()
            if st["errors"] or counts.get("error"):
                status.mark_incomplete(
                    f"target unreachable: {st['last_error'] or 'no probe reply could be evaluated'}"
                )
            elif st["blocked"] and not st["executed"]:
                status.mark_incomplete(f"all requests blocked by policy (last: {st['last_blocked']})")
            else:
                status.mark_incomplete(
                    "no probe reply could be evaluated (check --chat-path / --output-field)"
                )
        res.complete = status.complete
        res.incomplete_reason = status.incomplete_reason
        _corr, corr_dict = self._correlate(res.findings)
        self.store.save_findings(res.findings)
        phase_log = []
        for pr in res.probe_log:
            msg = f"{pr['id']}: {pr['result']}"
            if pr.get("note"):
                msg += f" ({pr['note']})"
            phase_log.append({"phase": "llm", "msg": msg})
        if not status.complete:
            phase_log.append({"phase": "scan", "msg": f"INCOMPLETE: {status.incomplete_reason}"})
        summary = {
            "correlation": corr_dict,
            "endpoints_tested": len(res.probe_log),
            "hypotheses": [],
            "classes_tested": ["LLM"],
            "llm_probe_log": res.probe_log,
            "llm_counts": counts,
            "phase_log": phase_log,
        }
        summary.update(self.scan_summary(status))
        self.store.save_scan(summary)
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
    NOT_RETESTABLE = "not retestable (re-run a scan)"

    def _retest_baseline(self, f, hyp) -> str:
        """Health control for a "Fixed" verdict: a benign GET of the finding's endpoint must be
        executed and answered without a 5xx. Returns "" when healthy, else why it is not."""
        import re

        from .runner import ProbeRunner

        path = str(hyp.get("endpoint_path") or "")
        if not path:
            try:
                path = urlsplit((f.endpoint or {}).get("url") or "").path
            except ValueError:
                path = ""
        obj = hyp.get("attacker_object") if isinstance(hyp.get("attacker_object"), dict) else {}
        path = re.sub(r"\{[^}/]+\}", str(obj.get("id") or "1"), path or "/")
        query = {}
        param = hyp.get("selector_param")
        if isinstance(param, str) and param and "{" + param + "}" not in str(hyp.get("endpoint_path") or ""):
            query[param] = str(hyp.get("base_value") or "1")
        runner = ProbeRunner(
            self.pipeline,
            self.evidence,
            self.pipeline.engagement_id,
            self.host,
            self.port,
            self.scheme,
            actor_role="validator",
            actor_profile="retest-baseline",
            phase="retest",
        )
        out = runner.get(
            path,
            session=None,
            query=query,
            payload_class="benign-read",
            rationale="retest baseline: is the endpoint healthy enough for 'Fixed' to mean anything?",
            capture=False,
            summary="retest baseline",
        )
        if not out.executed:
            return f"baseline GET {path} not executed ({out.blocked_reason or 'blocked'})"
        if out.status is None or int(out.status) >= 500:
            return f"baseline GET {path} -> HTTP {out.status} (target unhealthy; 'Fixed' cannot be trusted)"
        return ""

    def retest(self):
        """Replay EVERY validated finding that has a stored hypothesis + a registered oracle
        through the validator's class-agnostic retest, against the (possibly patched) target.

        Returns ``[(finding, outcome)]`` where outcome is ``"Fixed"``, ``"still-vulnerable"``,
        ``"Regression"``, ``"inconclusive"`` (the target could not give a meaningful answer — the
        finding's state is left unchanged) or :attr:`NOT_RETESTABLE` (misconfiguration,
        sensitive-file, static/SAST, external and browser findings have no oracle-replayable
        hypothesis; re-run a scan to re-check them). Never raises on a network/session error."""
        from .executor.session import SessionError
        from .validation.registry import get_oracle

        findings = self.store.load_findings()
        hyps = {h.get("finding_id"): h for h in self.store.load_hypotheses() if h.get("finding_id")}
        results = []
        for f in findings:
            if not is_validated(f) or is_dropped(f):
                continue
            hyp = hyps.get(f.id)
            if hyp is None or get_oracle(f.vuln_class) is None:
                results.append((f, self.NOT_RETESTABLE))
                continue
            prior = (f.state, f.status, dict(f.verification.last_retest or {}))
            try:
                outcome = self.validator.retest(f, hyp)
                if outcome == "Fixed":
                    # An oracle that merely stopped firing proves nothing if the endpoint itself is
                    # down / erroring (maintenance page, 5xx): require a healthy baseline answer
                    # before believing "Fixed"; otherwise restore the finding and report inconclusive.
                    why = self._retest_baseline(f, hyp)
                    if why:
                        from .util import now_iso

                        f.state, f.status = prior[0], prior[1]
                        f.verification.last_retest = {
                            "result": "inconclusive",
                            "at": now_iso(),
                            "reason": why,
                        }
                        outcome = "inconclusive"
            except (OSError, SessionError) as exc:
                from .util import now_iso

                f.verification.last_retest = {
                    "result": "inconclusive",
                    "at": now_iso(),
                    "error": f"{type(exc).__name__}: {exc}",
                }
                outcome = "inconclusive"
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

    def audit_status(self) -> tuple[bool, str, int]:
        """(intact, message, events). An empty/missing log is NOT intact ("no events") — it proves
        nothing; the CLI, MCP and SDK all use this one rule."""
        ok, msg = self.audit.verify_chain()
        return ok, msg, len(self.audit.read_all())

    def report(self, formats):
        """Render ``formats`` (a comma string or a list; case-insensitive) into the reports dir.

        Returns ``(written, report_builder, audit_chain_ok)``. Raises ``ValueError`` on an
        unknown format (listing the valid ones) before anything is written."""
        formats = normalize_formats(formats)
        ok, self.audit_message, _n = self.audit_status()
        rb = self.report_builder()
        written = {}
        for fmt in formats:
            name, attr = REPORT_FORMATS[fmt]
            path = os.path.join(self.store.reports_dir, name)
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(getattr(rb, attr)())
            written[fmt] = path
        return written, rb, ok
