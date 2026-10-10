"""Graph-based parallel orchestration.

A goal is decomposed into a DAG of Tasks; a scheduler runs ready tasks concurrently on a
bounded thread pool, and tasks may *spawn* new tasks dynamically (decompose-as-you-go) — so a
single planner node can fan out into hundreds of parallel agent/worker/oracle tasks that each
own one piece of the goal. Every action those tasks take still goes through the deterministic
policy choke-point and the (now thread-safe) audit log, so parallelism changes throughput, not
the safety or evidence guarantees.

Finding-driven escalation (``escalation``) adds the dynamic, result-reactive dimension: a
*validated* finding deterministically spawns bounded, deduped, oracle-proven follow-up tests.
"""

from .escalation import (
    ESCALATION_INJECTION_CLASSES,
    INJECTION_CLASSES,
    EscalationBudget,
    escalation_identity,
    follow_ups,
)
from .graph import GraphResult, Task, TaskGraph, TaskOutcome, run_graph

__all__ = [
    "Task",
    "TaskOutcome",
    "TaskGraph",
    "GraphResult",
    "run_graph",
    "EscalationBudget",
    "escalation_identity",
    "follow_ups",
    "INJECTION_CLASSES",
    "ESCALATION_INJECTION_CLASSES",
]
