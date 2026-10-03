"""The intelligence provider interface.

Each method takes structured context and returns structured data. Implementations must
treat any target-derived strings in the context as UNTRUSTED (never as instructions) —
the prompts module enforces delimiting for the LLM-backed provider.
"""
from __future__ import annotations


class IntelligenceProvider:
    name = "base"

    def label_endpoint(self, ctx: dict) -> dict:
        """Given an endpoint (method, path template, sample response shape), decide whether
        it returns an ownable object and which parameter selects it.

        Returns: {"returns_object_type": str|None, "object_selector": {"param","in"}|{},
                  "is_ownable": bool, "rationale": str}
        """
        raise NotImplementedError

    def propose_hypotheses(self, appmodel: dict) -> list[dict]:
        """Given the application model, propose testable weakness hypotheses.

        Returns a list of hypothesis dicts (see DeterministicProvider for the shape).
        """
        raise NotImplementedError

    def draft_finding_narrative(self, ctx: dict) -> dict:
        """Draft human-facing prose for a VALIDATED finding (description/impact/root_cause/
        remediation summary+guidance). Never invents evidence — prose only."""
        raise NotImplementedError

    def propose_patch(self, ctx: dict) -> dict:
        """Propose a minimal, advisory patch. Returns {"diff": str, "explanation": str}."""
        raise NotImplementedError
