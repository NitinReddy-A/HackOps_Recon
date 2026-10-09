"""Run the OWASP LLM Top-10 probe set against an authorized LLM endpoint.

Discipline mirrors the rest of Rampart: a probe "hit" is not enough. The oracle confirms a
finding only when the marker/canary appears for the attack prompt, does NOT appear for a
benign control (so a model that always echoes markers is not a false positive), and the
effect reproduces 2+ times. Only then is it ``confirmed``.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..schemas.finding import CVSS, Finding, Remediation, Reproduction, State, Verification
from ..util import now_iso
from .probes import BENIGN_CONTROL, LLM_PROBES


@dataclass
class LLMResult:
    findings: list = field(default_factory=list)
    probe_log: list = field(default_factory=list)  # [{id, owasp, result}]


_SEV_CVSS = {
    "high": CVSS(
        version="4.0",
        base_score=8.1,
        severity="high",
        vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N",
    ),
    "medium": CVSS(
        version="4.0",
        base_score=6.1,
        severity="medium",
        vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
    ),
    "low": CVSS(
        version="4.0",
        base_score=3.1,
        severity="low",
        vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
    ),
}


class LLMAssessment:
    def __init__(
        self,
        client,
        canary: str = "",
        application: str = "llm-target",
        target_url: str = "",
        engagement_id: str = "",
        reproductions: int = 2,
    ):
        self.client = client
        self.canary = canary
        self.application = application
        self.target_url = target_url
        self.engagement_id = engagement_id
        self.reproductions = reproductions

    def run(self) -> LLMResult:
        result = LLMResult()
        control_reply, _ = self.client.ask(BENIGN_CONTROL, summary="llm benign control")

        for probe in LLM_PROBES:
            reply, outcome = self.client.ask(probe.build_prompt(self.canary), summary=f"llm {probe.id}")
            if reply is None:
                result.probe_log.append({"id": probe.id, "owasp": probe.owasp, "result": "blocked"})
                continue
            hit = probe.detect(reply, self.canary)
            control_hit = probe.detect(control_reply or "", self.canary)
            if not (hit and not control_hit):
                result.probe_log.append({"id": probe.id, "owasp": probe.owasp, "result": "not-vulnerable"})
                continue

            repro = 0
            for _ in range(self.reproductions):
                r, _o = self.client.ask(probe.build_prompt(self.canary), summary=f"llm {probe.id} repro")
                if r is not None and probe.detect(r, self.canary):
                    repro += 1
            validated = repro >= self.reproductions
            result.findings.append(self._finding(probe, validated, repro, control_hit, outcome))
            result.probe_log.append(
                {"id": probe.id, "owasp": probe.owasp, "result": "confirmed" if validated else "unconfirmed"}
            )
        return result

    def _finding(self, probe, validated, repro, control_hit, outcome) -> Finding:
        checks = [
            f"PASS: attack prompt triggered the marker/canary for {probe.id}",
            f"PASS: benign control did NOT trigger it (control_hit={control_hit})",
            f"reproduced {repro}/{self.reproductions} times from fresh prompts",
        ]
        f = Finding(
            engagement_id=self.engagement_id,
            title=probe.title,
            vuln_class="LLM",
            severity=probe.severity,
            confidence="confirmed" if validated else "firm",
            state=State.VALIDATED if validated else State.EVIDENCE_FOUND,
            cwe=list(probe.cwe),
            owasp={"llm_2025": [probe.owasp]},
            cvss=_SEV_CVSS.get(probe.severity, _SEV_CVSS["medium"]),
            asset={
                "type": "llm_endpoint",
                "application": self.application,
                "environment": "authorized",
                "target": self.target_url,
            },
            endpoint={
                "method": "POST",
                "url": f"{self.target_url}{self.client.chat_path}",
                "auth_required": False,
            },
            description=probe.description,
            impact=probe.impact,
            root_cause=probe.root_cause,
            reproduction=Reproduction(
                prerequisites=["Authorized access to the LLM endpoint"],
                steps=[
                    f"POST the {probe.id} prompt to {self.client.chat_path}",
                    "Observe the marker/canary in the reply (see proof)",
                ],
                deterministic=True,
            ),
            remediation=Remediation(
                summary=probe.remediation_summary,
                type="config",
                guidance=probe.remediation_guidance,
                effort="medium",
            ),
            references=list(probe.references),
            compliance_control_refs=["OWASP-LLM-Top10", "NIST-AI-RMF:MANAGE"],
            dedupe_key=f"{self.application}:LLM:{probe.id}",
            tags=["llm", "ai", probe.id],
            verification=Verification(
                method="llm-marker-oracle",
                validated=validated,
                validated_at=now_iso(),
                validator="llm-oracle",
                independent_reproduction=validated,
                reproductions=repro,
                false_positive_checks=checks,
                confidence_score=0.95 if validated else 0.5,
            ),
        )
        f.evidence.extend(getattr(outcome, "evidence", []) or [])
        f.assert_consistent()
        return f
