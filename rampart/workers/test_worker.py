"""Test Worker — the ``bola-idor`` class profile (blueprint sections 10, 31).

The worker turns a hypothesis into a *candidate* finding backed by initial evidence. It
does NOT decide validity — it hands the candidate (structured facts only) to the independent
Validator. Everything it does is a Tier-1 read on seeded accounts/objects.
"""

from __future__ import annotations

from ..executor.differ import contains_signature
from ..schemas.finding import CVSS, Finding, Reproduction, State

# A defensible CVSS 4.0 for authenticated object-level authorization bypass (CWE-639).
_IDOR_CVSS = CVSS(
    version="4.0",
    base_score=8.7,
    vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
    severity="high",
    v31_fallback={"base_score": 7.7, "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"},
)


class BolaIdorWorker:
    profile = "bola-idor"

    def __init__(self, runner, application: str = "target", environment: str = "authorized"):
        self.runner = runner
        self.application = application
        self.environment = environment

    def investigate(self, hyp: dict, target_url: str) -> Finding | None:
        """Gather candidate evidence for one BOLA/IDOR hypothesis.

        Returns a Finding in state EVIDENCE_FOUND if the cross-account probe shows signal,
        else a CANDIDATE (dropped later if the validator disagrees), or None if blocked.
        """
        atk = hyp["attacker_principal"]
        vic = hyp["victim_principal"]
        vic_obj = hyp["victim_object"]
        atk_obj = hyp["attacker_object"]
        param = hyp["selector_param"]
        path_probe = hyp["endpoint_path"].replace("{" + param + "}", str(vic_obj["id"]))
        path_own = hyp["endpoint_path"].replace("{" + param + "}", str(atk_obj["id"]))

        baseline = self.runner.get(
            path_own,
            session=atk,
            payload_class="benign-read",
            rationale="worker baseline: attacker reads own object",
            hypothesis_id=hyp.get("id"),
            summary="worker baseline",
        )
        probe = self.runner.get(
            path_probe,
            session=atk,
            payload_class="boundary-probe",
            rationale="worker probe: attacker reads victim object",
            hypothesis_id=hyp.get("id"),
            summary="worker probe",
        )
        if not probe.executed:
            return None

        signal = (
            probe.status == 200
            and contains_signature(probe.body, vic_obj.get("signature", ""))
            and probe.body != baseline.body
        )

        concrete_url = f"{target_url}{path_probe}"
        finding = Finding(
            engagement_id=self.runner.engagement_id,
            title=f"IDOR/BOLA on {hyp['endpoint_method']} {hyp['endpoint_path']} exposes other users' {hyp['object_type']}s",
            vuln_class="IDOR/BOLA",
            severity="high",
            confidence="firm" if signal else "tentative",
            state=State.EVIDENCE_FOUND if signal else State.CANDIDATE,
            cwe=hyp.get("cwe", ["CWE-639"]),
            owasp={"web_2025": ["A01:2025-Broken Access Control"], "api_2023": ["API1:2023-BOLA"]},
            asvs={"requirement": "V4.1.3", "level": 2},
            cvss=_IDOR_CVSS,
            asset={
                "type": "api_endpoint",
                "application": self.application,
                "environment": self.environment,
                "target": target_url,
            },
            endpoint={
                "method": hyp["endpoint_method"],
                "url": concrete_url,
                "parameters": [{"name": param, "in": "path"}],
                "auth_required": True,
                "roles_tested": [atk, vic],
                "object_type": hyp["object_type"],
            },
            reproduction=Reproduction(
                prerequisites=[
                    f"Valid session for seeded '{atk}'",
                    f"Known id for '{vic}'s {hyp['object_type']}",
                ],
                steps=[
                    f"Authenticate as seeded '{atk}', capture bearer token",
                    f"GET {path_probe} (owned by '{vic}') with '{atk}'s token",
                    "Observe 200 with the victim's object body",
                ],
                deterministic=True,
            ),
            references=[
                "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
                "https://cwe.mitre.org/data/definitions/639.html",
            ],
            compliance_control_refs=["SOC2:CC7.1", "ISO27001:A.8.8", "PCI-DSS:11.3"],
            dedupe_key=f"{self.application}:{hyp['endpoint_method']}:{hyp['endpoint_path']}:CWE-639",
            tags=["idor", "bola", "access-control"],
        )
        finding.evidence.extend(baseline.evidence + probe.evidence)
        return finding
