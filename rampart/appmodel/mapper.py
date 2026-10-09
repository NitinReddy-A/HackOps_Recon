"""Attack-surface mapper — builds the application model (blueprint sections 13, 30.3).

Deterministic-heavy: endpoints come from an OpenAPI spec (grey-box "unlock"); ownership
ground truth comes from seeded test data per rampart.scope.yaml; the intelligence provider only
*labels* which endpoints return ownable objects (light LLM, or the deterministic heuristic).
"""

from __future__ import annotations

import json
import re
from urllib.parse import urlparse

from ..schemas.appmodel import ApplicationModel, Endpoint, Obj, Permission, Principal
from ..schemas.scope import EngagementScope


def _slug(method: str, path: str) -> str:
    core = re.sub(r"[^a-z0-9]+", "_", path.lower()).strip("_")
    core = re.sub(r"_id_?$", "", core) or "root"
    return f"ep_{core}_{method.lower()}"


_MAX_REF_DEPTH = 32


def _resolve_ref(spec: dict, obj, _seen=None):
    """Resolve a local ``{"$ref": "#/..."}`` (chained refs too); cycles/unknown refs -> None."""
    seen = set() if _seen is None else _seen
    depth = 0
    while isinstance(obj, dict) and isinstance(obj.get("$ref"), str):
        ref = obj["$ref"]
        if not ref.startswith("#/") or ref in seen or depth >= _MAX_REF_DEPTH:
            return None  # external, cyclic or absurdly deep reference
        seen.add(ref)
        depth += 1
        node = spec
        for part in ref[2:].split("/"):
            part = part.replace("~1", "/").replace("~0", "~")
            if not isinstance(node, dict) or part not in node:
                return None
            node = node[part]
        obj = node
    return obj


def _base_path(spec: dict) -> str:
    """Path prefix from OpenAPI 3 ``servers[0].url`` (absolute or relative) or Swagger 2 ``basePath``."""
    raw = ""
    servers = spec.get("servers")
    if isinstance(servers, list) and servers and isinstance(servers[0], dict):
        srv = servers[0]
        raw = str(srv.get("url") or "")
        for name, var in (srv.get("variables") or {}).items():
            if isinstance(var, dict) and "default" in var:
                raw = raw.replace("{" + str(name) + "}", str(var["default"]))
        if "://" in raw or raw.startswith("//"):
            try:
                raw = urlparse(raw).path
            except ValueError:
                raw = ""
    elif isinstance(spec.get("basePath"), str):
        raw = spec["basePath"]
    raw = raw.strip()
    if not raw or "{" in raw:
        return ""
    if not raw.startswith("/"):
        raw = "/" + raw
    return raw.rstrip("/")


def _params(spec: dict, raw_params) -> list[dict]:
    out = []
    for p in raw_params or []:
        p = _resolve_ref(spec, p)
        if not isinstance(p, dict) or not p.get("name") or not p.get("in"):
            continue
        schema = _resolve_ref(spec, p.get("schema") or {}) or {}
        out.append(
            {
                "name": p.get("name"),
                "in": p.get("in"),
                "type": schema.get("type", "string") if isinstance(schema, dict) else "string",
            }
        )
    return out


def _endpoints_from_openapi(spec: dict) -> list[Endpoint]:
    eps: list[Endpoint] = []
    base = _base_path(spec)
    for path, ops in (spec.get("paths") or {}).items():
        ops = _resolve_ref(spec, ops)
        if not isinstance(ops, dict):
            continue
        path_level = _params(spec, ops.get("parameters"))
        full_path = (base + path) if base else path
        for method, op in ops.items():
            if method.lower() not in ("get", "post", "put", "patch", "delete"):
                continue
            if not isinstance(op, dict):
                continue
            security = op.get("security", None)
            # security: [] means explicitly public (e.g. login); absent -> assume auth required
            auth_required = security != []
            # path-item params apply to every operation; operation params override by (name, in)
            merged = {(p["name"], p["in"]): p for p in path_level}
            for p in _params(spec, op.get("parameters")):
                merged[(p["name"], p["in"])] = p
            params = list(merged.values())
            eps.append(
                Endpoint(
                    id=_slug(method, full_path),
                    method=method.upper(),
                    path=full_path,
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
