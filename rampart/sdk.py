"""The Rampart Python SDK — a small, stable public surface over the engagement engine.

It's a thin wrapper: everything still runs through the same :class:`~rampart.engagement.Engagement`
facade the CLI, the MCP server, and the GitHub Action use, so a scan from code produces identical
results to one from the terminal.

    from rampart import Rampart

    r = Rampart(
        scope="rampart.scope.yaml",
        target="http://127.0.0.1:8080",
        openapi="openapi.json",
        seed="appmodel_seed.json",
    )
    result = r.scan()

    print(result.summary())
    for f in result.confirmed:
        print(f.severity, f.title)

    # Use it as a gate in a test or a CI script:
    assert not result.failed(on="high")

    # Render reports in memory, or write them to disk:
    sarif = result.to_sarif()
    result.save(["html", "json", "sarif"])
"""

from __future__ import annotations

from .engagement import Engagement, EngagementConfig
from .schemas.finding import State

_SEV_ORDER = ["info", "low", "medium", "high", "critical"]


def _sev_rank(sev: str) -> int:
    try:
        return _SEV_ORDER.index(sev)
    except ValueError:
        return 0


class Rampart:
    """A configured, ready-to-run assessment.

    Pass the scope contract and target, plus any of the optional capabilities as keyword
    arguments. Call :meth:`scan` for an application assessment or :meth:`llm_test` for the
    OWASP LLM Top 10. For the full, everything-on run use ``full=True`` (the SDK equivalent of
    ``rampart pipeline``); note that ``sca_online`` stays off unless you ask for it, because it
    sends dependency names to an external service.
    """

    def __init__(
        self,
        scope: str,
        target: str,
        *,
        work_dir: str = ".rampart",
        application: str = "target",
        openapi: str = "",
        seed: str = "",
        repo: str = "",
        secrets: str = "",
        intel: str = "deterministic",
        full: bool = False,
        crawl: bool = False,
        exploit: bool = False,
        agents: bool = False,
        oob: bool = False,
        browser: bool = False,
        grpc: bool = False,
        infra: bool = False,
        authz: bool = False,
        bizlogic: bool = False,
        api_scan: bool = False,
        sast: bool = False,
        sca: bool = False,
        iac: bool = False,
        sca_online: bool = False,
        active: bool = False,
        parallel: int = 0,
        scanners: str = "",
        store_url: str = "",
        since: str = "",
        login_path: str = "/api/login",
        token_path: str = "token",
        approver=None,
        resolver=None,
    ):
        if full:
            # Mirror `rampart pipeline`: turn on the safe, aggressive stages. External network
            # SCA (sca_online) stays an explicit opt-in.
            crawl = exploit = agents = oob = active = True
            sast = sca = iac = grpc = infra = authz = bizlogic = api_scan = True
        self.config = EngagementConfig(
            scope_file=scope,
            target=target,
            work_dir=work_dir,
            application=application,
            openapi=openapi,
            appmodel_seed=seed,
            repo=repo,
            secrets_file=secrets,
            intel=intel,
            crawl=crawl,
            exploit=exploit,
            agents=agents,
            oob=oob,
            browser=browser,
            grpc=grpc,
            infra=infra,
            authz=authz,
            bizlogic=bizlogic,
            api_scan=api_scan,
            do_sast=sast,
            do_sca=sca,
            do_iac=iac,
            sca_online=sca_online,
            active=active,
            parallel=parallel,
            scanners=scanners,
            store_url=store_url,
            sast_since=since,
            login_path=login_path,
            token_json_path=token_path,
            approver=approver,
            resolver=resolver,
        )
        self._engagement: Engagement | None = None

    @classmethod
    def from_config(cls, config: EngagementConfig) -> Rampart:
        """Build from a raw :class:`EngagementConfig` when you need a field the kwargs don't expose."""
        obj = cls.__new__(cls)
        obj.config = config
        obj._engagement = None
        return obj

    @property
    def engagement(self) -> Engagement:
        """The underlying engagement (constructed lazily; raises ScopeError if scope is invalid)."""
        if self._engagement is None:
            self._engagement = Engagement(self.config)
        return self._engagement

    def scan(self) -> ScanResult:
        """Run the application assessment and return a :class:`ScanResult`."""
        eng = self.engagement
        raw = eng.run_scan()
        return ScanResult(raw.findings, eng)

    def llm_test(
        self,
        *,
        chat_path: str = "/chat",
        input_field: str = "message",
        output_field: str = "reply",
        canary: str = "",
    ) -> ScanResult:
        """Assess an authorized LLM endpoint against the OWASP LLM Top 10."""
        self.config.llm_chat_path = chat_path
        self.config.llm_input_field = input_field
        self.config.llm_output_field = output_field
        self.config.llm_canary = canary
        eng = self.engagement
        res = eng.run_llm()
        return ScanResult(res.findings, eng)

    def retest(self) -> list:
        """Replay stored findings against the (possibly patched) target. Returns (finding, outcome)."""
        return self.engagement.retest()

    def save(self, formats) -> dict:
        """Write report files for the last run; returns {format: path}."""
        written, _rb, _ok = self.engagement.report(list(formats))
        return written


class ScanResult:
    """The outcome of a scan, with convenient views and report renderers.

    Iterating or ``len()``-ing a result gives every finding. The useful slices are
    :attr:`confirmed` (oracle-proven), :attr:`agent_assessed`, and :attr:`dropped`.
    """

    def __init__(self, findings: list, engagement: Engagement):
        self.findings = list(findings)
        self._engagement = engagement
        self._rb = None

    # --- views ---
    @property
    def confirmed(self) -> list:
        """Findings an independent oracle proved (``validated`` and not dropped)."""
        return [f for f in self.findings if f.verification.validated and f.state != State.DROPPED]

    @property
    def agent_assessed(self) -> list:
        """Reasoned-but-unproven findings — review these by hand."""
        return [f for f in self.findings if "agent-assessed" in f.tags and f.state != State.DROPPED]

    @property
    def dropped(self) -> list:
        """Candidates the false-positive gate removed."""
        return [f for f in self.findings if f.state == State.DROPPED]

    def by_severity(self) -> dict:
        """{severity: [confirmed findings]} for the five severity levels."""
        out: dict[str, list] = {s: [] for s in _SEV_ORDER}
        for f in self.confirmed:
            out.setdefault(f.severity, []).append(f)
        return out

    def at_or_above(self, severity: str) -> list:
        """Confirmed findings at or above a severity (e.g. ``"high"``)."""
        threshold = _sev_rank(severity)
        return [f for f in self.confirmed if _sev_rank(f.severity) >= threshold]

    def failed(self, on: str = "high") -> bool:
        """True if any confirmed finding is at or above ``on`` — the CI/test gate."""
        return bool(self.at_or_above(on))

    def summary(self) -> str:
        """A one-line human summary."""
        c = self.confirmed
        counts = dict.fromkeys(_SEV_ORDER, 0)
        for f in c:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        parts = [f"{counts[s]} {s}" for s in reversed(_SEV_ORDER) if counts.get(s)]
        head = f"{len(c)} confirmed"
        if parts:
            head += " (" + ", ".join(parts) + ")"
        agent = len(self.agent_assessed)
        if agent:
            head += f", {agent} agent-assessed"
        head += f", {len(self.dropped)} dropped by the false-positive gate"
        return head

    # --- reports (rendered from the same ReportBuilder the CLI uses) ---
    @property
    def _builder(self):
        if self._rb is None:
            self._rb = self._engagement.report_builder()
        return self._rb

    def to_json(self) -> str:
        return self._builder.to_json()

    def to_sarif(self) -> str:
        return self._builder.to_sarif()

    def to_markdown(self) -> str:
        return self._builder.to_markdown()

    def to_html(self) -> str:
        return self._builder.to_html()

    def to_compliance(self) -> str:
        return self._builder.to_compliance()

    def to_soc2(self) -> str:
        return self._builder.to_soc2()

    def save(self, formats) -> dict:
        """Write report files to the engagement's work dir; returns {format: path}."""
        written, _rb, _ok = self._engagement.report(list(formats))
        return written

    def __len__(self) -> int:
        return len(self.findings)

    def __iter__(self):
        return iter(self.findings)

    def __repr__(self) -> str:
        return f"<ScanResult: {self.summary()}>"
