"""The independent false-positive gate (blueprint sections 4, 21).

Separation of duties: the Validator is a DIFFERENT component from the worker that proposed
the candidate. It receives only the structured hypothesis facts (which endpoint, which
seeded principals/objects/parameter) — never the worker's reasoning — looks up the oracle
for the finding's class in the registry, and re-derives the proof itself from a clean state.
Only the Validator may set ``confidence = confirmed``; a class with no registered oracle can
never be confirmed (fail-closed).
"""
from __future__ import annotations

from ..runner import ProbeRunner
from ..schemas.finding import Finding, State, Verification
from ..util import now_iso
from .registry import get_oracle


class Validator:
    def __init__(self, pipeline, evidence_store, session_manager, host, port, scheme="http"):
        self.pipeline = pipeline
        self.evidence = evidence_store
        self.sessions = session_manager
        self.host = host
        self.port = port
        self.scheme = scheme

    def _runner(self, phase: str, profile: str = "validator") -> ProbeRunner:
        return ProbeRunner(self.pipeline, self.evidence, self.pipeline.engagement_id,
                           self.host, self.port, self.scheme,
                           actor_role="validator", actor_profile=profile, phase=phase)

    def validate(self, finding: Finding, hyp: dict, reproductions: int = 2) -> bool:
        oracle = get_oracle(finding.vuln_class)
        if oracle is None:
            # No independent oracle for this class — cannot confirm (fail-closed).
            finding.state = State.DROPPED
            finding.status = "dropped"
            finding.confidence = "tentative"
            finding.verification = Verification(
                method="no-oracle", validated=False, validated_at=now_iso(),
                validator="validator", false_positive_checks=[f"no oracle registered for {finding.vuln_class!r}"],
                confidence_score=0.0)
            finding.assert_consistent()
            return False

        runner = self._runner("validate", profile=finding.vuln_class)
        verdict = oracle(runner, self.sessions, hyp, reproductions)
        finding.evidence.extend(verdict.evidence)

        if verdict.validated:
            finding.state = State.VALIDATED
            finding.confidence = "confirmed"
            finding.status = "open"
            finding.verification = Verification(
                method="active-exploit-replay",
                validated=True,
                validated_at=now_iso(),
                validator="validator",   # a component distinct from the discoverer
                independent_reproduction=True,
                reproductions=verdict.reproductions,
                false_positive_checks=verdict.reasons + verdict.false_positive_checks,
                confidence_score=0.95,
                last_retest={"result": "still-vulnerable", "at": now_iso()},
            )
        else:
            finding.state = State.DROPPED
            finding.confidence = "tentative"
            finding.status = "dropped"
            finding.verification = Verification(
                method="active-exploit-replay", validated=False, validated_at=now_iso(),
                validator="validator", independent_reproduction=False,
                reproductions=verdict.reproductions,
                false_positive_checks=verdict.reasons + verdict.false_positive_checks,
                confidence_score=0.0,
            )
        finding.assert_consistent()
        return verdict.validated

    def retest(self, finding: Finding, hyp: dict, reproductions: int = 2) -> str:
        """Replay the stored reproduction against the (possibly patched) target.

        Returns 'Fixed' if the oracle no longer fires, 'Regression'/'still-vulnerable' otherwise.
        """
        oracle = get_oracle(finding.vuln_class)
        if oracle is None:
            return "still-vulnerable"
        runner = self._runner("retest", profile=finding.vuln_class)
        verdict = oracle(runner, self.sessions, hyp, reproductions)
        finding.verification.last_retest = {
            "result": "still-vulnerable" if verdict.validated else "fixed",
            "at": now_iso(),
            "reproductions": verdict.reproductions,
            "controls": verdict.controls,
        }
        if not verdict.validated:
            finding.state = State.FIXED
            finding.status = "fixed"
            return "Fixed"
        if finding.state == State.FIXED:
            finding.state = State.REGRESSION
            finding.status = "open"
            return "Regression"
        finding.state = State.VALIDATED
        return "still-vulnerable"
