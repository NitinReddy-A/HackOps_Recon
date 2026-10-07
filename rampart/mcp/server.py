"""A minimal, correct MCP stdio server for Rampart (JSON-RPC 2.0, stdlib only).

Protocol
--------
Line-delimited JSON over stdin/stdout. One JSON object per line. Methods:

* ``initialize``               -> serverInfo + capabilities
* ``notifications/initialized``-> notification, no response
* ``tools/list``               -> the tool catalogue (name, description, inputSchema)
* ``tools/call``               -> dispatch by name -> {content:[{type:"text",text:...}]}

Unknown methods return JSON-RPC error ``-32601``; unparseable lines return ``-32700``.
The read loop never crashes on a bad line.

Scope gate
----------
Every capability is executed through :class:`rampart.engagement.Engagement`, which
parses and validates the SECURITY.md authorization contract and refuses (fail-closed)
any target not inside ``scope.in_scope``. The server therefore *cannot* scan a target
the operator has not authorized — the scope file is the authorization boundary.
"""
from __future__ import annotations

import json
import os

from ..version import __version__
from ..schemas.scope import EngagementScope, ScopeError

PROTOCOL_VERSION = "2024-11-05"
SERVER_NAME = "rampart"


# =========================================================================== tools
TOOLS = [
    {
        "name": "rampart_scope_check",
        "description": (
            "Validate a Rampart SECURITY.md authorization contract WITHOUT touching the "
            "network. Parses the scope file and runs the R1 fail-closed gate (owner, "
            "authorized_by, attestation, in_scope hosts, resolved_ip_allowlist, expiry). "
            "Returns {valid, errors, ...}. Run this first — every other tool refuses to act "
            "unless this contract is valid and authorizes the target."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "scope_file": {
                    "type": "string",
                    "description": "Path to the SECURITY.md authorization contract.",
                },
            },
            "required": ["scope_file"],
        },
    },
    {
        "name": "rampart_scan",
        "description": (
            "Run an authorized web/API assessment against TARGET and return a JSON summary "
            "(confirmed findings, counts, and correlation risk_score/risk_band/attack-chains). "
            "Executes through Engagement: the SECURITY.md scope gate is enforced fail-closed, "
            "so a target not listed in scope.in_scope is REFUSED (isError) and never contacted. "
            "Only independently-validated findings are reported as confirmed."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "scope_file": {"type": "string", "description": "Path to the SECURITY.md contract (the authorization boundary)."},
                "target": {"type": "string", "description": "Authorized target base URL, e.g. http://127.0.0.1:8080. Must be inside scope.in_scope."},
                "openapi": {"type": "string", "description": "Optional OpenAPI spec path for a grey-box app model."},
                "appmodel_seed": {"type": "string", "description": "Optional seeded object-ownership file (enables BOLA/IDOR hypotheses)."},
                "secrets": {"type": "string", "description": "Optional secrets file (default: secrets.json next to the scope file)."},
                "application": {"type": "string", "description": "Application name recorded on findings (default: target)."},
                "crawl": {"type": "boolean", "description": "Discover endpoints/params by crawling, no OpenAPI needed (default: false)."},
                "repo": {"type": "string", "description": "Optional source repo path for white-box correlation."},
                "work_dir": {"type": "string", "description": "Run directory for audit/evidence/reports (default: .rampart)."},
            },
            "required": ["scope_file", "target"],
        },
    },
    {
        "name": "rampart_llm_test",
        "description": (
            "Assess an authorized LLM endpoint against the OWASP LLM Top 10 and return "
            "confirmed findings plus a probe-log summary. Runs through Engagement so the "
            "SECURITY.md scope gate is enforced fail-closed; an out-of-scope target is REFUSED. "
            "LLM prompts are Tier-2 (state-changing) POSTs — the operator authorizes them by "
            "providing an in-scope contract, so Tier-2 is auto-approved and audited. The model's "
            "reply is treated as data checked by a deterministic marker/canary oracle, never executed."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "scope_file": {"type": "string", "description": "Path to the SECURITY.md contract (the authorization boundary)."},
                "target": {"type": "string", "description": "Authorized LLM endpoint base URL. Must be inside scope.in_scope."},
                "chat_path": {"type": "string", "description": "Path that accepts the prompt (default: /chat)."},
                "input_field": {"type": "string", "description": "JSON field holding the user prompt (default: message)."},
                "output_field": {"type": "string", "description": "Dotted JSON path to the model reply (default: reply)."},
                "canary": {"type": "string", "description": "Secret planted in the system prompt, used as a leak oracle (optional)."},
                "application": {"type": "string", "description": "Application name recorded on findings (default: llm-target)."},
                "work_dir": {"type": "string", "description": "Run directory for audit/evidence/reports (default: .rampart)."},
            },
            "required": ["scope_file", "target"],
        },
    },
    {
        "name": "rampart_report",
        "description": (
            "Regenerate report artifacts (html, md, json, sarif, compliance) from a previously "
            "stored run in WORK_DIR and return the written file paths. Runs through Engagement, "
            "so the SECURITY.md scope gate is still validated (fail-closed) before any report is "
            "produced. No network traffic is generated."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "scope_file": {"type": "string", "description": "Path to the SECURITY.md contract (still validated)."},
                "target": {"type": "string", "description": "The target the stored run was executed against (must be in scope)."},
                "work_dir": {"type": "string", "description": "Run directory holding the stored findings/scan to report on."},
                "format": {"type": "string", "description": "Comma list of formats: html,md,json,sarif,compliance (default: html,json)."},
                "application": {"type": "string", "description": "Application name (default: target)."},
            },
            "required": ["scope_file", "target", "work_dir"],
        },
    },
]


# ===================================================================== JSON-RPC glue
def _result(rid, result):
    return {"jsonrpc": "2.0", "id": rid, "result": result}


def _error(rid, code, message):
    return {"jsonrpc": "2.0", "id": rid, "error": {"code": code, "message": message}}


def _tool_text(obj, is_error=False):
    """Wrap a payload in an MCP tool result ({content:[{type:text,text}]})."""
    text = obj if isinstance(obj, str) else json.dumps(obj, indent=2, default=str)
    return {"content": [{"type": "text", "text": text}], "isError": bool(is_error)}


# ========================================================================= handlers
def _tool_scope_check(args):
    scope_file = args.get("scope_file")
    if not scope_file:
        return _tool_text({"error": "scope_file is required"}, is_error=True)
    try:
        scope = EngagementScope.from_file(scope_file)
    except ScopeError as exc:
        # unreadable / unparseable contract — a definitive "invalid" answer
        return _tool_text({"valid": False, "errors": [str(exc)]}, is_error=True)
    errs = scope.validate()
    if errs:
        return _tool_text({"valid": False, "errors": errs})
    return _tool_text({
        "valid": True,
        "errors": [],
        "owner": scope.authorization.owner,
        "authorized_by": scope.authorization.authorized_by,
        "ticket": scope.authorization.ticket,
        "expires": scope.authorization.expires,
        "in_scope": [
            {"host": h.host, "ports": h.ports, "methods": h.methods, "paths_include": h.paths_include}
            for h in scope.in_scope
        ],
        "resolved_ip_allowlist": scope.resolved_ip_allowlist,
        "tier_ceiling": scope.action_policy.default_tier_ceiling,
    })


def _missing(args, keys):
    return [k for k in keys if not args.get(k)]


def _tool_scan(args):
    miss = _missing(args, ["scope_file", "target"])
    if miss:
        return _tool_text({"error": f"missing required argument(s): {', '.join(miss)}"}, is_error=True)

    from ..engagement import Engagement, EngagementConfig

    cfg = EngagementConfig(
        scope_file=args["scope_file"],
        target=args["target"],
        work_dir=args.get("work_dir") or ".rampart",
        openapi=args.get("openapi") or "",
        appmodel_seed=args.get("appmodel_seed") or "",
        secrets_file=args.get("secrets") or "",
        application=args.get("application") or "target",
        repo=args.get("repo") or "",
        crawl=bool(args.get("crawl", False)),
        intel="deterministic",
    )
    eng = Engagement(cfg)              # ScopeError / FileNotFoundError -> caught by dispatch
    result = eng.run_scan()

    corr = result.correlation
    confirmed = [f for f in result.findings if getattr(f.verification, "validated", False)]
    summary = {
        "target": eng.target_url,
        "intel_provider": eng.intel.name,
        "work_dir": os.path.abspath(eng.cfg.work_dir),
        "counts": {
            "confirmed": len(confirmed),
            "total_findings": len(result.findings),
            "endpoints_tested": result.endpoints_tested,
            "classes_tested": result.classes_tested,
        },
        "risk_score": getattr(corr, "risk_score", 0),
        "risk_band": getattr(corr, "risk_band", "Informational"),
        "attack_chains": [
            {"id": c.get("id"), "title": c.get("title"), "severity": c.get("severity"),
             "finding_ids": c.get("finding_ids", [])}
            for c in (getattr(corr, "chains", []) or [])
        ],
        "confirmed_findings": [
            {"title": f.title, "severity": f.severity, "vuln_class": f.vuln_class,
             "cwe": f.cwe, "endpoint": (f.endpoint or {}).get("url", "")}
            for f in confirmed
        ],
    }
    return _tool_text(summary)


def _tool_llm_test(args):
    miss = _missing(args, ["scope_file", "target"])
    if miss:
        return _tool_text({"error": f"missing required argument(s): {', '.join(miss)}"}, is_error=True)

    from ..engagement import Engagement, EngagementConfig

    # LLM prompts are Tier-2; the operator authorized them via the in-scope contract.
    approver = lambda req, dec: {"granted": True, "approver_user_id": "mcp:rampart_llm_test"}  # noqa: E731
    cfg = EngagementConfig(
        scope_file=args["scope_file"],
        target=args["target"],
        work_dir=args.get("work_dir") or ".rampart",
        application=args.get("application") or "llm-target",
        llm_chat_path=args.get("chat_path") or "/chat",
        llm_input_field=args.get("input_field") or "message",
        llm_output_field=args.get("output_field") or "reply",
        llm_canary=args.get("canary") or "",
        intel="deterministic",
        approver=approver,
    )
    eng = Engagement(cfg)              # ScopeError / FileNotFoundError -> caught by dispatch
    res = eng.run_llm()

    confirmed = [f for f in res.findings if getattr(f.verification, "validated", False)]
    summary = {
        "target": eng.target_url,
        "chat_path": eng.cfg.llm_chat_path,
        "confirmed_count": len(confirmed),
        "confirmed_findings": [
            {"title": f.title, "severity": f.severity, "vuln_class": f.vuln_class,
             "cwe": f.cwe, "owasp": f.owasp, "endpoint": (f.endpoint or {}).get("url", "")}
            for f in confirmed
        ],
        "probe_log": res.probe_log,
    }
    return _tool_text(summary)


def _tool_report(args):
    miss = _missing(args, ["scope_file", "target", "work_dir"])
    if miss:
        return _tool_text({"error": f"missing required argument(s): {', '.join(miss)}"}, is_error=True)

    from ..engagement import Engagement, EngagementConfig

    formats = [f.strip() for f in (args.get("format") or "html,json").split(",") if f.strip()]
    cfg = EngagementConfig(
        scope_file=args["scope_file"],
        target=args["target"],
        work_dir=args["work_dir"],
        application=args.get("application") or "target",
        intel="deterministic",
    )
    eng = Engagement(cfg)              # ScopeError / FileNotFoundError -> caught by dispatch
    written, rb, chain_ok = eng.report(formats)
    m = rb.metrics()
    summary = {
        "written": {k: os.path.abspath(v) for k, v in written.items()},
        "formats": list(written.keys()),
        "audit_chain_intact": bool(chain_ok),
        "risk_score": m.get("risk_score"),
        "risk_band": m.get("risk_band"),
        "confirmed": m.get("confirmed"),
    }
    return _tool_text(summary)


_TOOL_HANDLERS = {
    "rampart_scope_check": _tool_scope_check,
    "rampart_scan": _tool_scan,
    "rampart_llm_test": _tool_llm_test,
    "rampart_report": _tool_report,
}


def _dispatch_tool(name, arguments):
    handler = _TOOL_HANDLERS.get(name)
    if handler is None:
        return _tool_text({"error": f"unknown tool: {name!r}"}, is_error=True)
    try:
        return handler(arguments or {})
    except (ScopeError, FileNotFoundError) as exc:
        # refused by the scope gate or a missing input file — clean result, never a stack trace
        return _tool_text({"error": str(exc), "refused": True}, is_error=True)
    except Exception as exc:  # noqa: BLE001 - a tool error must not kill the server
        return _tool_text({"error": f"{type(exc).__name__}: {exc}"}, is_error=True)


# ======================================================================= dispatcher
def handle_request(req):
    """Handle one parsed JSON-RPC request object; return a response dict or None."""
    method = req.get("method")
    rid = req.get("id")
    is_notification = "id" not in req

    if method == "initialize":
        return _result(rid, {
            "protocolVersion": PROTOCOL_VERSION,
            "serverInfo": {"name": SERVER_NAME, "version": __version__},
            "capabilities": {"tools": {}},
        })
    if method == "notifications/initialized":
        return None
    if method == "tools/list":
        return _result(rid, {"tools": TOOLS})
    if method == "tools/call":
        params = req.get("params") or {}
        return _result(rid, _dispatch_tool(params.get("name"), params.get("arguments")))

    # unknown method
    if is_notification:
        return None  # unknown notification: silently ignore (per JSON-RPC)
    return _error(rid, -32601, f"method not found: {method!r}")


def _process_line(line):
    """Parse and dispatch a single line; return a response dict or None."""
    try:
        req = json.loads(line)
    except (json.JSONDecodeError, ValueError):
        return _error(None, -32700, "Parse error")
    if not isinstance(req, dict):
        return _error(None, -32600, "Invalid Request")
    try:
        return handle_request(req)
    except Exception as exc:  # noqa: BLE001 - never crash the read loop
        if "id" not in req:
            return None
        return _error(req.get("id"), -32603, f"Internal error: {exc}")


def serve_stdio(stdin, stdout):
    """Run the MCP server read loop over the given text streams.

    Reads one JSON-RPC request per line from ``stdin`` and writes one JSON object
    per line to ``stdout``. Returns when ``stdin`` reaches EOF. Testable with
    ``io.StringIO`` streams — no real pipes required.
    """
    while True:
        line = stdin.readline()
        if not line:  # EOF
            break
        line = line.strip()
        if not line:
            continue
        resp = _process_line(line)
        if resp is not None:
            stdout.write(json.dumps(resp) + "\n")
            stdout.flush()
