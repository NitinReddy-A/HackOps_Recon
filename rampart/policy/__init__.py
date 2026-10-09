"""The deterministic safety pipeline — a single choke-point every tool call traverses.

    allowlist -> scope -> resolved-IP -> risk classifier -> policy engine -> (HITL) -> sandbox -> audit

Enforced as one library no agent code can bypass, fail-closed at every stage
(blueprint section 12). A hijacked LLM can, at worst, emit requests this layer rejects.
"""

from .pipeline import PipelineResult, PolicyPipeline

__all__ = ["PolicyPipeline", "PipelineResult"]
