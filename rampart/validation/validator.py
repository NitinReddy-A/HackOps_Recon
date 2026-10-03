"""The independent false-positive gate (blueprint sections 4, 21).

Separation of duties: the Validator is a DIFFERENT component from the Test Worker that
proposed the candidate. It receives only the structured hypothesis facts (which endpoint,
which seeded principals/objects) — never the worker's reasoning — and re-derives the proof
itself from a clean state. Only the Validator may set ``confidence = confirmed``.
"""
from __future__ import annotations

from ..runner import ProbeRunner
from ..schemas.finding import Finding, State, Verification
from ..util import now_iso
from .oracle import run_bola_oracle


class Validator:
    def __init__(self, pipeline, evidence_store, session_manager, host, port, scheme="http"):
        self.pipeline = pipeline
        self.evidence = evidence_store
        self.sessions = session_manager
        self.host = host
        self.port = port
        self.scheme = scheme

    def _runner(self, phase: str) -> ProbeRunner:
        return ProbeRunner(self.pipeline, self.evidence, self.pipeline.engagement_id,
                           self.host, self.port, self.scheme,
                           actor_role="validator", actor_profile="bola-idor", phase=phase)

    def validate(self, finding: Finding, hyp: dict, reproductions: int = 2) -> bool:
        runner = self._runner("validate")
        verdict = run_bola_oracle(runner, self.sessions, hyp, reproductions=reproductions, fresh_sessions=True)

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
                # the full proof: affirmative oracle checks + negative controls + reproductions
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
                reproductions=verdict.reproductions, false_positive_checks=verdict.false_positive_checks,
                confidence_score=0.0,
            )
        finding.assert_consistent()
        return verdict.validated

    def retest(self, finding: Finding, hyp: dict, reproductions: int = 2) -> str:
        """Replay the stored reproduction against the (possibly patched) target.

        Returns 'Fixed' if the oracle no longer fires, 'Regression'/'still-vulnerable' otherwise.
        """
        runner = self._runner("retest")
        verdict = run_bola_oracle(runner, self.sessions, hyp, reproductions=reproductions, fresh_sessions=True)
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
        # was previously Fixed and fires again -> Regression; else still open
        if finding.state == State.FIXED:
            finding.state = State.REGRESSION
            finding.status = "open"
            return "Regression"
        finding.state = State.VALIDATED
        return "still-vulnerable"
