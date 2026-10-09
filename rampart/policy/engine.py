"""Stage 4 — policy engine.

Given the effective risk tier, the engagement's ``action_policy``, and the current phase,
emit ALLOW / ALLOW_WITH_INTERRUPT / DENY. Declarative and versioned so a review can
reconstruct exactly why an action was permitted.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..schemas.scope import ActionPolicy
from ..schemas.toolcall import Decision, RiskTier

POLICY_VERSION = "v1"


@dataclass
class EngineResult:
    decision: str
    reason: str
    matched_rules: list


def decide(tier: int, policy: ActionPolicy, phase: str = "test") -> EngineResult:
    rules: list[str] = []

    if tier >= RiskTier.PROHIBITED:
        rules.append("policy.tier3=deny")
        return EngineResult(
            Decision.DENY, "Tier 3 (prohibited): DoS/destructive/exfil are denied by default", rules
        )

    # tier2_requires_approval ALWAYS gates Tier 2 — it is checked before the ceiling, so a
    # ``default_tier_ceiling: 2`` cannot silently turn approval-required writes into auto-allow.
    if tier == RiskTier.HIGH_RISK and policy.tier2_requires_approval is not False:
        rules.append("policy.tier2_requires_approval=true")
        return EngineResult(
            Decision.ALLOW_WITH_INTERRUPT, "Tier 2 (high-risk): requires human approval (HITL)", rules
        )

    if tier <= policy.default_tier_ceiling:
        rules.append(f"policy.tier_ceiling>={tier}")
        return EngineResult(
            Decision.ALLOW, f"Tier {tier} within ceiling {policy.default_tier_ceiling}", rules
        )

    if tier == RiskTier.HIGH_RISK:
        rules.append("policy.tier2_requires_approval=false;tier>ceiling")
        return EngineResult(Decision.DENY, "Tier 2 above ceiling and approval disabled", rules)

    rules.append("policy.default_deny")
    return EngineResult(Decision.DENY, f"Tier {tier} above ceiling {policy.default_tier_ceiling}", rules)
