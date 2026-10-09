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

    def propose_web_hypotheses(self, appmodel: dict) -> list[dict]:
        """Propose reflected-XSS / SQLi / open-redirect hypotheses from endpoint query params.

        Concrete default is empty; providers that enumerate inputs override this. (Input-fuzzing
        classes are enumerated deterministically — the oracle, not a model, decides validity.)
        """
        return []

    def plan_assessment(self, ctx: dict) -> dict:
        """Planner agent: prioritise which classes/endpoints to test. Returns
        {"order": [class,...], "notes": str, "steps": [{"class","rationale"}]}."""
        classes = list(ctx.get("candidate_classes") or [])
        severity_rank = {"SQLI": 0, "IDOR/BOLA": 1, "LLM": 2, "OPEN_REDIRECT": 3, "XSS": 4}
        order = sorted(classes, key=lambda c: severity_rank.get(c, 9))
        steps = [{"class": c, "rationale": f"test {c} across discovered inputs/endpoints"} for c in order]
        return {
            "order": order,
            "notes": f"deterministic priority over {len(order)} class(es)",
            "steps": steps,
        }

    def agent_step(self, ctx: dict) -> dict:
        """One decision for the reasoning agent loop (plan/explore/critique). The deterministic
        provider cannot reason about intended behaviour, so it stops immediately and the agentic
        layer honestly produces nothing. LLM-backed providers override this."""
        return {"thought": "deterministic provider cannot perform agentic reasoning", "stop": True}

    def draft_finding_narrative(self, ctx: dict) -> dict:
        """Draft human-facing prose for a VALIDATED finding (description/impact/root_cause/
        remediation summary+guidance). Never invents evidence — prose only."""
        raise NotImplementedError

    def propose_patch(self, ctx: dict) -> dict:
        """Propose a minimal, advisory patch. Returns {"diff": str, "explanation": str}."""
        raise NotImplementedError
