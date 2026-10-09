"""The agent roster + the planner step (which backend runs each role)."""

from __future__ import annotations

AGENT_ROSTER = [
    {
        "role": "mapper",
        "title": "Attack-surface mapper",
        "backend": "reasoning",
        "duty": "label which endpoints return ownable objects / take inputs",
    },
    {
        "role": "planner",
        "title": "Assessment planner",
        "backend": "reasoning",
        "duty": "prioritise which classes/endpoints to test and why",
    },
    {
        "role": "specialist:bola",
        "title": "BOLA / IDOR specialist",
        "backend": "reasoning",
        "duty": "propose cross-account access-control hypotheses",
    },
    {
        "role": "specialist:injection",
        "title": "Injection specialist (XSS / SQLi / SSRF / cmdi / traversal / SSTI)",
        "backend": "deterministic-enum",
        "duty": "enumerate input-fuzzing hypotheses from parameters",
    },
    {
        "role": "specialist:llm",
        "title": "LLM red-team specialist",
        "backend": "deterministic-probes",
        "duty": "run the OWASP LLM Top-10 probe set",
    },
    {
        "role": "agent:business-logic",
        "title": "Business-logic abuse agent",
        "backend": "reasoning",
        "duty": "reason about intended behaviour and probe for logic abuse (no oracle exists)",
    },
    {
        "role": "agent:access-logic",
        "title": "Authorization-logic agent",
        "backend": "reasoning",
        "duty": "reason across roles/flows for multi-step authorization gaps",
    },
    {
        "role": "agent:critic",
        "title": "Adversarial critic / verifier",
        "backend": "reasoning",
        "duty": "try to DISPROVE each agent-proposed finding with a control probe",
    },
    {
        "role": "validator",
        "title": "Independent validator",
        "backend": "deterministic-ONLY",
        "duty": "re-derive proof via a deterministic oracle; sole gate for 'confirmed'",
    },
    {
        "role": "reporter",
        "title": "Reporter",
        "backend": "reasoning",
        "duty": "draft prose for validated + agent-assessed findings",
    },
]


def describe_roster() -> list[dict]:
    return [dict(r) for r in AGENT_ROSTER]


def run_planner(intel, appmodel: dict, scanner_runs: list, classes: list) -> dict:
    """Invoke the planner agent (reasoning backend) with a deterministic fallback."""
    try:
        plan = intel.plan_assessment(
            {
                "endpoints": [
                    {"id": e.get("id"), "method": e.get("method"), "path": e.get("path")}
                    for e in appmodel.get("endpoints", [])
                ],
                "candidate_classes": classes,
                "external_scanners": [s.get("scanner") for s in (scanner_runs or []) if s.get("available")],
            }
        )
        if isinstance(plan, dict) and plan.get("order"):
            return plan
    except Exception:  # noqa: BLE001 - planning is advisory; never break a run
        pass
    return {"order": classes, "notes": f"default priority over {len(classes)} class(es)", "steps": []}
