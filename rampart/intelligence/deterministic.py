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

# Parameter/endpoint name hints for the open-redirect class (where testing every param is noise).
_REDIRECT_PARAM_HINTS = ("next", "url", "redirect", "redirect_uri", "return", "returnurl",
                         "return_url", "dest", "destination", "to", "continue", "goto", "callback")
_REDIRECT_PATH_HINTS = ("go", "redirect", "out", "link", "exit", "away")


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

    def propose_web_hypotheses(self, appmodel: dict) -> list[dict]:
        """Enumerate reflected-XSS / SQLi / open-redirect hypotheses from endpoint query params.

        Enumeration is deliberate and broad: the independent oracle is the gate, so proposing
        a probe that turns out safe costs one validation and is then dropped with proof — never
        a false positive. XSS/SQLi are tested on every query parameter; open-redirect is limited
        to redirect-shaped parameter/endpoint names to avoid pointless probes.
        """
        hyps: list[dict] = []
        for ep in appmodel.get("endpoints", []):
            if (ep.get("method") or "GET").upper() != "GET":
                continue
            qparams = [p for p in (ep.get("parameters") or []) if p.get("in") == "query" and p.get("name")]
            path = ep.get("path", "")
            path_is_redirecty = any(h in path.lower() for h in _REDIRECT_PATH_HINTS)
            for p in qparams:
                name = p["name"]
                common = {"endpoint_id": ep.get("id"), "endpoint_method": ep.get("method", "GET"),
                          "endpoint_path": path, "selector_param": name}
                hyps.append({**common, "vuln_class": "XSS", "cwe": ["CWE-79"],
                             "rationale": f"query param '{name}' on {path} may be reflected into HTML unencoded"})
                hyps.append({**common, "vuln_class": "SQLI", "cwe": ["CWE-89"], "base_value": "1",
                             "rationale": f"query param '{name}' on {path} may reach a SQL sink"})
                if name.lower() in _REDIRECT_PARAM_HINTS or path_is_redirecty:
                    hyps.append({**common, "vuln_class": "OPEN_REDIRECT", "cwe": ["CWE-601"],
                                 "rationale": f"query param '{name}' on {path} looks like a redirect target"})
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
