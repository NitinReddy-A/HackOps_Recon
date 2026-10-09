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

    # Use it as a gate in a test or a CI script (an incomplete run — target unreachable or
    # every request blocked — also fails the gate):
    assert result.complete, result.incomplete_reason
    assert not result.failed(on="high")

    # Render reports in memory, or write them to disk:
    sarif = result.to_sarif()
    result.save(["html", "json", "sarif"])
"""

from __future__ import annotations

from .engagement import Engagement, EngagementConfig
from .reporting.status import SEV_RANK, is_confirmed, norm_severity, sev_rank
from .schemas.finding import State

_SEV_ORDER = ["info", "low", "medium", "high", "critical"]


def _threshold(severity: str) -> int:
    """The rank of a user-supplied severity (case-insensitive). Unknown -> ValueError."""
    s = severity.strip().lower() if isinstance(severity, str) else ""
    if s not in SEV_RANK:
        raise ValueError(f"unknown severity {severity!r} (use one of: {', '.join(reversed(_SEV_ORDER))})")
    return SEV_RANK[s]


class Rampart:
    """A configured, ready-to-run assessment.

    Pass the scope contract and target, plus any of the optional capabilities as keyword
    arguments. Call :meth:`scan` for an application assessment or :meth:`llm_test` for the
    OWASP LLM Top 10. For the full, everything-on run use ``full=True`` (the SDK equivalent of
    ``rampart pipeline``); note that ``sca_online`` stays off unless you ask for it, because it
    sends dependency names to an external service, and ``active`` (gated write/state-changing
    probes) also stays off unless you pass ``active=True`` explicitly.
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
        oob_collaborator_url: str = "",
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
            # Mirror `rampart pipeline`: turn on every read-only stage. Gated write probes
            # (active) and external network SCA (sca_online) stay explicit opt-ins.
            crawl = exploit = agents = oob = True
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
            oob_collaborator_url=oob_collaborator_url,
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
        return ScanResult(
            raw.findings,
            eng,
            complete=getattr(raw, "complete", True),
            incomplete_reason=getattr(raw, "incomplete_reason", ""),
        )

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
        return ScanResult(
            res.findings,
            eng,
            complete=getattr(res, "complete", True),
            incomplete_reason=getattr(res, "incomplete_reason", ""),
        )

    def retest(self) -> list:
        """Replay stored validated findings against the (possibly patched) target.

        Returns ``[(finding, outcome)]``; outcome is ``"Fixed"``, ``"still-vulnerable"``,
        ``"Regression"``, ``"inconclusive"`` or ``"not retestable (re-run a scan)"``."""
        return self.engagement.retest()

    def save(self, formats) -> dict:
        """Write report files for the last run (``"html,json"`` or ``["html", "json"]``,
        case-insensitive); returns {format: path}. Unknown formats raise ValueError."""
        written, _rb, _ok = self.engagement.report(formats)
        return written


class ScanResult:
    """The outcome of a scan, with convenient views and report renderers.

    Iterating or ``len()``-ing a result gives every finding. The useful slices are
    :attr:`confirmed` (oracle-proven), :attr:`agent_assessed`, and :attr:`dropped`.

    :attr:`complete` is False (with :attr:`incomplete_reason`) when the run could not actually
    assess the target — it was unreachable, every request was blocked by policy, or the kill
    switch fired. An incomplete result **fails** :meth:`failed` regardless of severity, so a
    broken deploy can never pass a gate as "0 findings".
    """

    def __init__(
        self, findings: list, engagement: Engagement, complete: bool = True, incomplete_reason: str = ""
    ):
        self.findings = list(findings)
        self._engagement = engagement
        self._rb = None
        self.complete = bool(complete)
        self.incomplete_reason = incomplete_reason or ""

    # --- views ---
    @property
    def confirmed(self) -> list:
        """Findings an independent oracle proved and that are still open (validated, and not
        Dropped or Fixed by a retest) — the same rule every report and gate uses."""
        return [f for f in self.findings if is_confirmed(f)]

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
            out[norm_severity(f.severity)].append(f)
        return out

    def at_or_above(self, severity: str) -> list:
        """Confirmed findings at or above a severity (``"high"``, case-insensitive).

        Raises ``ValueError`` for an unknown severity."""
        threshold = _threshold(severity)
        return [f for f in self.confirmed if sev_rank(f.severity) <= threshold]

    def failed(self, on: str = "high") -> bool:
        """The CI/test gate: True if any confirmed finding is at or above ``on``
        (case-insensitive; unknown severity -> ``ValueError``) **or the run was incomplete**
        (target unreachable / all requests blocked / kill switch — see :attr:`complete`)."""
        hits = self.at_or_above(on)  # validates ``on`` even for an incomplete run
        return (not self.complete) or bool(hits)

    def summary(self) -> str:
        """A one-line human summary."""
        c = self.confirmed
        counts = dict.fromkeys(_SEV_ORDER, 0)
        for f in c:
            counts[norm_severity(f.severity)] += 1
        parts = [f"{counts[s]} {s}" for s in reversed(_SEV_ORDER) if counts.get(s)]
        head = f"{len(c)} confirmed"
        if parts:
            head += " (" + ", ".join(parts) + ")"
        agent = len(self.agent_assessed)
        if agent:
            head += f", {agent} agent-assessed"
        head += f", {len(self.dropped)} dropped by the false-positive gate"
        if not self.complete:
            head += f" — INCOMPLETE: {self.incomplete_reason}"
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
        """Write report files to the engagement's work dir; ``formats`` is a comma string or a
        list (case-insensitive). Returns {format: path}; unknown formats raise ValueError."""
        written, _rb, _ok = self._engagement.report(formats)
        return written

    def __len__(self) -> int:
        return len(self.findings)

    def __iter__(self):
        return iter(self.findings)

    def __repr__(self) -> str:
        return f"<ScanResult: {self.summary()}>"
