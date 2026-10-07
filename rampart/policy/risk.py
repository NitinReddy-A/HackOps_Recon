"""Stage 3 — action-risk classifier.

A DETERMINISTIC rules table, not an LLM: a hijacked model must not be able to downgrade
its own risk. The effective tier is the MAXIMUM of what the HTTP method implies, what the
declared payload class implies, and what destructive-marker scanning finds — so mislabeling
a ``DELETE`` as ``benign-read`` cannot lower the tier (blueprint section 12).
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from ..schemas.toolcall import RiskTier, ToolAction

_WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

# Substrings that indicate destructive / prohibited intent (Tier 3), scanned in path+body.
_DESTRUCTIVE_MARKERS = [
    re.compile(r"(?i)\bdrop\s+table\b"),
    re.compile(r"(?i)\btruncate\b"),
    re.compile(r"(?i)\bdelete\s+from\b"),
    re.compile(r"(?i)\bshutdown\b"),
    re.compile(r"(?i)\brm\s+-rf\b"),
    re.compile(r"(?i)\b(or|and)\s+1=1\s*;?\s*(--|#)"),  # tautology + statement terminator
    re.compile(r"(?i)\bxp_cmdshell\b"),
    re.compile(r"(?i)/etc/passwd"),
]

_PAYLOAD_TIER = {
    "benign-read": RiskTier.READ_ONLY,
    "canary": RiskTier.CONTROLLED_VALIDATION,
    "boundary-probe": RiskTier.CONTROLLED_VALIDATION,
    "state-change": RiskTier.HIGH_RISK,
    "destructive": RiskTier.PROHIBITED,
}


@dataclass
class RiskResult:
    tier: int
    reason: str
    declared_tier: int
    downgrade_attempt: bool = False


def classify(action: ToolAction, declared_tier: int = 0) -> RiskResult:
    reasons = []

    method_tier = RiskTier.HIGH_RISK if action.method.upper() in _WRITE_METHODS else RiskTier.READ_ONLY
    if method_tier == RiskTier.HIGH_RISK:
        reasons.append(f"{action.method} is a state-changing method")

    payload_tier = _PAYLOAD_TIER.get(action.payload_class, RiskTier.HIGH_RISK)
    if action.payload_class not in _PAYLOAD_TIER:
        reasons.append(f"unknown payload_class {action.payload_class!r} -> treated as high-risk")
    else:
        reasons.append(f"payload_class={action.payload_class}")

    marker_tier = RiskTier.READ_ONLY
    # Scan path, body AND query values — a hijacked model must not be able to smuggle a
    # destructive payload through the query string where it would otherwise go unscanned.
    query_text = " ".join(str(v) for v in (action.query or {}).values())
    haystack = f"{action.path} {action.body or ''} {query_text}"
    for pat in _DESTRUCTIVE_MARKERS:
        if pat.search(haystack):
            marker_tier = RiskTier.PROHIBITED
            reasons.append(f"destructive marker matched: {pat.pattern}")
            break

    tier = int(max(method_tier, payload_tier, marker_tier))
    downgrade = declared_tier < tier
    if downgrade:
        reasons.append(f"declared_tier={declared_tier} < effective_tier={tier} (declaration ignored)")
    return RiskResult(tier=tier, reason="; ".join(reasons), declared_tier=declared_tier, downgrade_attempt=downgrade)
