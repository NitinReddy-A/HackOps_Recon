"""Agentic reasoning layer — the multi-agent pipeline and its orchestration.

Roles (see roster): planner, specialists, the business-logic / access-logic agents, an
adversarial critic, and the reporter. Deterministic roles (the policy pipeline and the
oracles) are never an LLM — that is what keeps the safety and evidence guarantees true.
Agent-reasoned findings are tiered 'agent-assessed' (below oracle-'confirmed').
"""
from .brain import AgentBrain, MockBrain
from .harness import DecisionGuard, action_signature, validate_decision
from .orchestrator import AgentOrchestrator, AgentResult
from .roster import AGENT_ROSTER, describe_roster, run_planner

__all__ = ["AGENT_ROSTER", "describe_roster", "run_planner",
           "AgentBrain", "MockBrain", "AgentOrchestrator", "AgentResult",
           "DecisionGuard", "validate_decision", "action_signature"]
