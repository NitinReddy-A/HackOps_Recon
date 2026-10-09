"""Attack-surface mapper — builds the application model (blueprint sections 13, 30.3).

Deterministic-heavy: endpoints come from an OpenAPI spec (grey-box "unlock"); ownership
ground truth comes from seeded test data per rampart.scope.yaml; the intelligence provider only
*labels* which endpoints return ownable objects (light LLM, or the deterministic heuristic).
"""

from __future__ import annotations

import json
import re

from ..schemas.appmodel import ApplicationModel, Endpoint, Obj, Permission, Principal
from ..schemas.scope import EngagementScope


def _slug(method: str, path: str) -> str:
    core = re.sub(r"[^a-z0-9]+", "_", path.lower()).strip("_")
    core = re.sub(r"_id_?$", "", core) or "root"
    return f"ep_{core}_{method.lower()}"


def _endpoints_from_openapi(spec: dict) -> list[Endpoint]:
    eps: list[Endpoint] = []
    for path, ops in (spec.get("paths") or {}).items():
        for method, op in ops.items():
            if method.lower() not in ("get", "post", "put", "patch", "delete"):
                continue
            security = op.get("security", None)
            # security: [] means explicitly public (e.g. login); absent -> assume auth required
            auth_required = security != []
            params = [
                {
                    "name": p.get("name"),
                    "in": p.get("in"),
                    "type": (p.get("schema") or {}).get("type", "string"),
                }
                for p in (op.get("parameters") or [])
                if p.get("name") and p.get("in")
            ]
            eps.append(
                Endpoint(
                    id=_slug(method, path),
                    method=method.upper(),
                    path=path,
                    auth_required=auth_required,
                    parameters=params,
                    provenance="spec",
                )
            )
    return eps


def build_model(
    scope: EngagementScope, openapi_path: str | None = None, seed_path: str | None = None, intel=None
) -> ApplicationModel:
    model = ApplicationModel(engagement_id=scope.authorization.ticket or "engagement")

    # 1) endpoints from spec
    if openapi_path:
        with open(openapi_path, encoding="utf-8") as fh:
            spec = json.load(fh)
        model.endpoints = _endpoints_from_openapi(spec)

    # 2) seed: roles, objects, permissions, endpoint hints
    seed = {}
    if seed_path:
        with open(seed_path, encoding="utf-8") as fh:
            seed = json.load(fh)
    model.roles = seed.get("roles") or sorted({a.role for a in scope.test_accounts})
    model.objects = [Obj(**o) for o in seed.get("objects", [])]
    model.permissions = [Permission(**p) for p in seed.get("permissions", [])]
    hints = {(h["method"].upper(), h["path"]): h for h in seed.get("endpoint_hints", [])}

    # 3) principals from the seeded test accounts (never real users)
    model.principals = [Principal(id=a.id, role=a.role, seeded=True) for a in scope.test_accounts]

    # 4) label endpoints: seed hints win; else the intelligence provider proposes
    for ep in model.endpoints:
        hint = hints.get((ep.method, ep.path))
        if hint:
            ep.returns_object_type = hint.get("returns_object_type")
            ep.object_selector = hint.get("object_selector") or {}
            ep.provenance = "spec+seed"
        elif intel is not None and ep.method == "GET" and "{" in ep.path:
            label = intel.label_endpoint({"method": ep.method, "path": ep.path, "sample_response": ""})
            if label.get("is_ownable"):
                ep.returns_object_type = label.get("returns_object_type")
                ep.object_selector = label.get("object_selector") or {}
        if ep.auth_required:
            ep.observed_roles = list(model.roles)

    return model
