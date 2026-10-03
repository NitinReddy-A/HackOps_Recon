"""Rule-based intelligence — no LLM, zero cost, fully reproducible.

This is the default provider so the platform runs (and CI passes) for free and offline.
It encodes the same reasoning an analyst would apply to the application model: an endpoint
that returns an ownable object selected by a path parameter, guarded by an ``owner_only``
permission, with two seeded principals each owning an object, is a BOLA/IDOR hypothesis.
"""
from __future__ import annotations

import re

from .base import IntelligenceProvider

_PATH_PARAM = re.compile(r"\{([^}]+)\}")


class DeterministicProvider(IntelligenceProvider):
    name = "deterministic"

    def label_endpoint(self, ctx: dict) -> dict:
        method = (ctx.get("method") or "GET").upper()
        path = ctx.get("path") or ""
        params = _PATH_PARAM.findall(path)
        # Heuristic: a GET on a resource collection member (…/{id}) returns an ownable object.
        if method == "GET" and params:
            selector = params[-1]
            # object type guess: the path segment before the selector, singularized
            segs = [s for s in path.split("/") if s and "{" not in s]
            obj_type = segs[-1].rstrip("s").capitalize() if segs else "Object"
            return {
                "returns_object_type": ctx.get("returns_object_type") or obj_type,
                "object_selector": {"param": selector, "in": "path"},
                "is_ownable": True,
                "rationale": f"GET on a member resource selected by path param '{selector}' — likely an ownable object",
            }
        return {"returns_object_type": None, "object_selector": {}, "is_ownable": False,
                "rationale": "no member-resource selector detected"}

    def propose_hypotheses(self, appmodel: dict) -> list[dict]:
        endpoints = appmodel.get("endpoints", [])
        principals = appmodel.get("principals", [])
        objects = appmodel.get("objects", [])
        perms = appmodel.get("permissions", [])
        owner_only = {(p["object_type"], p["action"]) for p in perms if p.get("constraint") == "owner_only"}

        hyps: list[dict] = []
        for ep in endpoints:
            otype = ep.get("returns_object_type")
            sel = ep.get("object_selector") or {}
            if not otype or not sel:
                continue
            if (otype, "read") not in owner_only:
                continue
            owners = {}
            for o in objects:
                if o.get("type") == otype and o.get("seeded"):
                    owners.setdefault(o["owner_principal"], o)
            if len(owners) < 2:
                continue
            # pick attacker + victim among distinct owners
            owner_ids = list(owners.keys())
            attacker, victim = owner_ids[0], owner_ids[1]
            hyps.append({
                "vuln_class": "IDOR/BOLA",
                "cwe": ["CWE-639"],
                "endpoint_id": ep["id"],
                "endpoint_method": ep["method"],
                "endpoint_path": ep["path"],
                "object_type": otype,
                "selector_param": sel.get("param"),
                "attacker_principal": attacker,
                "victim_principal": victim,
                "attacker_object": owners[attacker],
                "victim_object": owners[victim],
                "rationale": (f"{ep['method']} {ep['path']} returns an ownable {otype} selected by "
                              f"'{sel.get('param')}' under an owner_only policy; two seeded owners exist, "
                              f"so a cross-account read by '{attacker}' of '{victim}'s object is testable at Tier 1."),
            })
        return hyps

    def draft_finding_narrative(self, ctx: dict) -> dict:
        ep = ctx.get("endpoint_path", "the endpoint")
        method = ctx.get("endpoint_method", "GET")
        otype = ctx.get("object_type", "object")
        return {
            "description": (f"The {method} {ep} endpoint authenticates the caller but does not verify "
                            f"ownership of the requested {otype}. An authenticated user can read another "
                            f"user's {otype} by supplying its identifier."),
            "impact": (f"Horizontal privilege escalation and disclosure of other users' {otype} data "
                       "(PII/business data), scaling to every enumerable identifier."),
            "root_cause": (f"Missing object-level authorization: the handler fetches the {otype} by id and "
                           "returns it without comparing the object's owner to the authenticated principal."),
            "remediation_summary": "Enforce an object-level ownership check before returning the object.",
            "remediation_guidance": ("After loading the object by id, compare its owner to the authenticated "
                                     "principal and return 403 Forbidden on mismatch (ASVS Authorization; CWE-639)."),
        }

    def propose_patch(self, ctx: dict) -> dict:
        var = ctx.get("object_var", "order")
        owner_attr = ctx.get("owner_attr", "owner_id")
        principal = ctx.get("principal_expr", "current_principal.id")
        diff = (
            f"  {var} = {ctx.get('fetch_expr', f'{var.capitalize()}.get(id)')}\n"
            f"- return {var}\n"
            f"+ if {var}.{owner_attr} != {principal}:\n"
            f"+     raise Forbidden()          # object-level authorization (CWE-639)\n"
            f"+ return {var}\n"
        )
        return {"diff": diff,
                "explanation": "Adds the missing ownership check immediately after the object is loaded."}
