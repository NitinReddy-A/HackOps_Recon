"""The machine-readable finding — a SARIF-exportable superset (blueprint section 14).

``confidence == "confirmed"`` REQUIRES ``verification.validated is True`` with independent
replay evidence. That coupling is the trust primitive separating this from a raw scanner
alert. The finding lifecycle (section 21) is enforced by the states below.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field

from ..util import gen_id, now_iso


class State:
    CANDIDATE = "Candidate"          # LLM hypothesis exists; no evidence
    INVESTIGATING = "Investigating"  # worker running Tier 0/1 probes
    EVIDENCE_FOUND = "EvidenceFound"  # a deterministic oracle fired; bundle assembled
    VALIDATED = "Validated"          # GATE passed: independent re-derivation from clean state
    REPORTED = "Reported"
    FIX_PROPOSED = "FixProposed"
    RETEST = "Retest"
    FIXED = "Fixed"
    REGRESSION = "Regression"
    DROPPED = "Dropped"              # gate failed / demoted


SEVERITIES = ("info", "low", "medium", "high", "critical")
CONFIDENCES = ("tentative", "firm", "confirmed")


@dataclass
class Evidence:
    type: str                        # http_request|http_response|response_diff|screenshot|note
    summary: str
    storage_uri: str = ""
    sha256: str = ""
    redacted: bool = True


@dataclass
class CVSS:
    version: str = "4.0"
    base_score: float = 0.0
    vector: str = ""
    severity: str = "info"
    v31_fallback: dict = field(default_factory=dict)


@dataclass
class Reproduction:
    prerequisites: list = field(default_factory=list)
    steps: list = field(default_factory=list)
    deterministic: bool = True


@dataclass
class AffectedCode:
    detected_by: str = ""
    repo: str = ""
    file: str = ""
    start_line: int = 0
    end_line: int = 0
    snippet: str = ""
    commit: str = ""


@dataclass
class Remediation:
    summary: str = ""
    type: str = "code_patch"
    guidance: str = ""
    proposed_diff: str = ""          # advisory only — never auto-applied (R7)
    effort: str = "low"
    fix_status: str = "proposed"     # proposed|applied
    tests_run: bool = False
    tests_passed: bool | None = None
    pr_ref: str = ""


@dataclass
class Verification:
    method: str = ""                 # e.g. active-exploit-replay
    validated: bool = False
    validated_at: str = ""
    validator: str = ""              # a component DIFFERENT from the discoverer (separation of duties)
    independent_reproduction: bool = False
    reproductions: int = 0
    false_positive_checks: list = field(default_factory=list)
    confidence_score: float = 0.0
    last_retest: dict = field(default_factory=dict)


@dataclass
class Finding:
    engagement_id: str
    title: str
    vuln_class: str = ""
    severity: str = "info"
    severity_source: str = "cvss"
    confidence: str = "tentative"
    status: str = "open"
    state: str = State.CANDIDATE
    cwe: list = field(default_factory=list)
    owasp: dict = field(default_factory=dict)
    asvs: dict = field(default_factory=dict)
    cvss: CVSS = field(default_factory=CVSS)
    asset: dict = field(default_factory=dict)
    endpoint: dict = field(default_factory=dict)
    description: str = ""
    impact: str = ""
    evidence: list = field(default_factory=list)
    reproduction: Reproduction = field(default_factory=Reproduction)
    affected_code: AffectedCode | None = None
    root_cause: str = ""
    remediation: Remediation = field(default_factory=Remediation)
    references: list = field(default_factory=list)
    compliance_control_refs: list = field(default_factory=list)
    verification: Verification = field(default_factory=Verification)
    dedupe_key: str = ""
    first_seen: str = field(default_factory=now_iso)
    tags: list = field(default_factory=list)
    id: str = ""
    schema_version: str = "1.0.0"

    def __post_init__(self):
        if not self.id:
            self.id = gen_id("fnd")

    # ------------------------------------------------------------- invariant
    def assert_consistent(self) -> None:
        """The trust primitive: 'confirmed' is only legal with independent validation."""
        if self.confidence == "confirmed" and not self.verification.validated:
            raise ValueError(
                f"finding {self.id}: confidence=confirmed requires verification.validated=True "
                "(evidence over alerts — section 21)"
            )

    def to_dict(self) -> dict:
        d = asdict(self)
        d["$schema"] = "https://rampart.dev/schemas/finding/v1.json"
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "Finding":
        d = {k: v for k, v in d.items() if not k.startswith("$")}

        def _sub(klass, val, default):
            if val is None:
                return default
            if isinstance(val, klass):
                return val
            return klass(**{k: v for k, v in val.items() if k in klass.__annotations__})

        d["cvss"] = _sub(CVSS, d.get("cvss"), CVSS())
        d["reproduction"] = _sub(Reproduction, d.get("reproduction"), Reproduction())
        d["remediation"] = _sub(Remediation, d.get("remediation"), Remediation())
        d["verification"] = _sub(Verification, d.get("verification"), Verification())
        if d.get("affected_code"):
            d["affected_code"] = _sub(AffectedCode, d.get("affected_code"), None)
        d["evidence"] = [_sub(Evidence, e, None) for e in (d.get("evidence") or [])]
        known = {k: v for k, v in d.items() if k in cls.__annotations__}
        return cls(**known)

    # --------------------------------------------------------------- SARIF
    def to_sarif_result(self) -> dict:
        level = {"critical": "error", "high": "error", "medium": "warning",
                 "low": "note", "info": "note"}.get(self.severity, "warning")
        rule_id = (self.cwe[0] if self.cwe else self.vuln_class) or "finding"
        loc_uri = self.endpoint.get("url") or self.asset.get("target", "")
        result = {
            "ruleId": rule_id,
            "level": level,
            "message": {"text": f"{self.title} — {self.description}"},
            "locations": [{
                "physicalLocation": {"artifactLocation": {"uri": loc_uri}}
            }],
            "partialFingerprints": {"dedupeKey/v1": self.dedupe_key or self.id},
            "properties": {
                "vuln_class": self.vuln_class,
                "confidence": self.confidence,
                "state": self.state,
                "cwe": self.cwe,
                "owasp": self.owasp,
                "cvss": asdict(self.cvss),
                "validated": self.verification.validated,
                "reproductions": self.verification.reproductions,
                "compliance_control_refs": self.compliance_control_refs,
            },
        }
        if self.affected_code and self.affected_code.file:
            result["locations"].append({
                "physicalLocation": {
                    "artifactLocation": {"uri": self.affected_code.file},
                    "region": {"startLine": self.affected_code.start_line,
                               "endLine": self.affected_code.end_line},
                }
            })
        return result
