"""Deterministic attack-chain correlation, risk scoring, and remediation prioritisation.

Chains are rule-based: each rule fires when its required vulnerability classes are present
among the confirmed findings, and composes them into a realistic multi-step narrative with
the contributing finding ids. Risk score aggregates finding severities and amplifies for
chains (composition is worse than the sum of parts). Nothing here invents a finding — it
only reasons over ones an independent oracle already confirmed.
"""
from __future__ import annotations

from dataclasses import dataclass, field

_SEV_WEIGHT = {"critical": 40, "high": 25, "medium": 10, "low": 3, "info": 1}
_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@dataclass
class CorrelationResult:
    chains: list = field(default_factory=list)       # [{id,title,severity,steps,finding_ids,rationale}]
    risk_score: int = 0
    risk_band: str = "Informational"
    roadmap: list = field(default_factory=list)      # prioritized remediation steps
    summary: str = ""


# A chain fires when `requires` is a subset of the confirmed classes present. `any_of` groups
# mean "at least one of these classes". Severity is the chain's composed impact.
_CHAIN_RULES = [
    {"id": "ssrf-cloud-takeover", "severity": "critical",
     "title": "Cloud account takeover via SSRF to instance metadata",
     "any_of": [["SSRF"]],
     "steps": ["Abuse the SSRF sink to request http://169.254.169.254/ (cloud metadata)",
               "Read the instance IAM role's temporary credentials",
               "Use the stolen credentials to access cloud APIs and pivot internally"],
     "rationale": "A confirmed SSRF commonly reaches cloud metadata, yielding IAM credentials."},
    {"id": "rce-full-compromise", "severity": "critical",
     "title": "Remote code execution → full server compromise",
     "any_of": [["CMDI"]],
     "steps": ["Inject an OS command through the vulnerable parameter",
               "Execute arbitrary commands as the application user",
               "Establish persistence / pivot to adjacent services"],
     "rationale": "Confirmed command injection is directly exploitable to RCE."},
    {"id": "sqli-breach", "severity": "critical",
     "title": "Database breach / authentication bypass via SQL injection",
     "any_of": [["SQLI"]],
     "steps": ["Use the injection to enumerate schema and dump tables",
               "Extract credentials/PII; optionally bypass authentication with a tautology",
               "Escalate to the DB host where stacked queries / file write are possible"],
     "rationale": "Confirmed SQLi enables data exfiltration and often auth bypass."},
    {"id": "mass-data-exfil", "severity": "high",
     "title": "Mass data exfiltration via broken authorization",
     "any_of": [["IDOR/BOLA", "BFLA", "EXCESSIVE_DATA"]],
     "steps": ["Authenticate as a low-privilege user",
               "Iterate object identifiers / call privileged functions to read other tenants' data",
               "Harvest the over-exposed fields (PII, secrets) at scale"],
     "rationale": "Access-control gaps + over-exposed fields compose into bulk data theft."},
    {"id": "file-disclosure-escalation", "severity": "high",
     "title": "Server file disclosure → secret theft → escalation",
     "any_of": [["PATH_TRAVERSAL"]],
     "steps": ["Traverse outside the intended directory to read config/secret files",
               "Recover credentials, tokens or source code",
               "Reuse the secrets to escalate access"],
     "rationale": "Path traversal exposes files that typically contain secrets."},
    {"id": "xss-account-takeover", "severity": "high",
     "title": "Account takeover via XSS + weak browser defenses",
     "requires_all": ["XSS"],
     "any_of": [["security-misconfiguration"]],
     "steps": ["Deliver the reflected XSS payload to a victim",
               "Exfiltrate the session (weak/missing CSP, cookie flags or permissive CORS)",
               "Act as the victim / take over the account"],
     "rationale": "Reflected XSS plus missing headers/CORS/cookie flags enables session theft."},
    {"id": "open-redirect-phishing", "severity": "medium",
     "title": "Credential phishing via trusted-domain open redirect",
     "any_of": [["OPEN_REDIRECT"]],
     "steps": ["Craft a link on the trusted domain that redirects to an attacker site",
               "Phish credentials / OAuth tokens using the borrowed trust",
               "Replay captured credentials"],
     "rationale": "Open redirect lends the target's reputation to phishing / token theft."},
    {"id": "llm-prompt-injection-abuse", "severity": "high",
     "title": "LLM prompt injection → data/tool abuse",
     "any_of": [["LLM"]],
     "steps": ["Inject instructions that override the system prompt",
               "Leak the system prompt/secrets or coerce tool calls",
               "Abuse any connected tools/data with the model's privileges"],
     "rationale": "A confirmed LLM injection/leak undermines every downstream trust boundary."},
]


def _confirmed(findings):
    return [f for f in findings if getattr(f.verification, "validated", False)
            and "external-scanner" not in f.tags]


def correlate(findings, appmodel=None, tech=None) -> CorrelationResult:
    confirmed = _confirmed(findings)
    present: dict[str, list] = {}
    for f in confirmed:
        present.setdefault(f.vuln_class, []).append(f)

    chains = []
    for rule in _CHAIN_RULES:
        if any(c not in present for c in rule.get("requires_all", [])):
            continue
        groups = rule.get("any_of", [])
        ok = all(any(c in present for c in group) for group in groups) if groups else True
        if not ok:
            continue
        ids, titles = [], []
        for group in groups + [rule.get("requires_all", [])]:
            for c in group:
                for f in present.get(c, []):
                    ids.append(f.id)
                    titles.append(f.title)
        chains.append({"id": rule["id"], "title": rule["title"], "severity": rule["severity"],
                       "steps": list(rule["steps"]), "rationale": rule["rationale"],
                       "finding_ids": sorted(set(ids)), "contributing": sorted(set(titles))})

    # ---- risk score: weighted findings + chain amplification, capped at 100 ----
    base = sum(_SEV_WEIGHT.get(f.severity, 1) for f in confirmed)
    chain_bonus = sum(15 if c["severity"] == "critical" else 8 for c in chains)
    score = min(100, base + chain_bonus) if confirmed else 0
    band = ("Critical" if score >= 80 else "High" if score >= 55
            else "Medium" if score >= 30 else "Low" if score > 0 else "Informational")

    # ---- remediation roadmap: dedupe by remediation summary, priority by severity then effort ----
    effort_rank = {"low": 0, "medium": 1, "high": 2}
    buckets: dict[str, dict] = {}
    for f in confirmed:
        key = f.remediation.summary or f.title
        b = buckets.setdefault(key, {"summary": key, "guidance": f.remediation.guidance,
                                     "effort": f.remediation.effort or "medium",
                                     "severity": f.severity, "count": 0, "classes": set()})
        b["count"] += 1
        b["classes"].add(f.vuln_class)
        if _SEV_RANK.get(f.severity, 9) < _SEV_RANK.get(b["severity"], 9):
            b["severity"] = f.severity
    roadmap = sorted(buckets.values(),
                     key=lambda b: (_SEV_RANK.get(b["severity"], 9), effort_rank.get(b["effort"], 1)))
    for b in roadmap:
        b["classes"] = sorted(b["classes"])

    crit_hi = [c for c in chains if c["severity"] in ("critical", "high")]
    summary = (f"{len(confirmed)} confirmed finding(s) compose into {len(chains)} attack chain(s); "
               f"{len(crit_hi)} reach critical/high impact. Aggregate risk {score}/100 ({band}).") \
        if confirmed else "No confirmed findings."

    return CorrelationResult(chains=chains, risk_score=score, risk_band=band,
                             roadmap=roadmap, summary=summary)
