"""The ``rampart`` command-line interface (developer-first DX, blueprint section 19).

    rampart init      --scope-file rampart.scope.yaml
    rampart test      --scope-file rampart.scope.yaml --target http://127.0.0.1:8080 [--repo .] [--report html,md,sarif,json]
    rampart sast      --scope-file rampart.scope.yaml --repo .          (white-box; no --target needed)
    rampart retest    --scope-file rampart.scope.yaml --work-dir .rampart   (target read from the stored run)
    rampart report    --scope-file rampart.scope.yaml --format html
    rampart verify-audit --work-dir .rampart

`test` is the flagship: scope-gate -> map -> hypothesize -> validate -> report, with
`--repo` adding white-box SAST/secrets/SCA, source correlation and an advisory patch.
Dependency-free (argparse).

Exit codes: 0 success · 1 a gate failed (CI gate, --fail-on-static, pr-comment --fail-on,
retest still-vulnerable/regression, dashboard could not bind) · 2 refused / invalid input /
incomplete run (target unreachable, every request blocked by policy) / retest inconclusive.

Option precedence: explicit CLI flag > ``--config`` file (or ./rampart.yaml) > built-in default.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys

from .schemas.finding import State
from .schemas.scope import EngagementScope, ScopeError
from .version import __version__

_USE_COLOR = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def _c(text, code):
    return f"\033[{code}m{text}\033[0m" if _USE_COLOR else str(text)


def bold(t):
    return _c(t, "1")


def green(t):
    return _c(t, "32")


def red(t):
    return _c(t, "31")


def yellow(t):
    return _c(t, "33")


def cyan(t):
    return _c(t, "36")


def dim(t):
    return _c(t, "2")


_SEV_C = {"critical": red, "high": red, "medium": yellow, "low": cyan, "info": dim}

# ANSI/VT escape sequences (CSI, OSC, single-char ESC) and C0/C1 control characters.
_ANSI_RE = re.compile(
    r"\x1b\[[0-?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)?|\x1b[@-_]|\x9b[0-?]*[ -/]*[@-~]"
)
_CTRL_RE = re.compile(r"[\x00-\x1f\x7f-\x9f]")


def _clean(text) -> str:
    """Make a target-derived string (finding title, server banner, model reply note) safe to print:
    strip ANSI escape sequences and replace every C0/C1 control character with a space, so a
    hostile target cannot rewrite the operator's terminal."""
    t = _ANSI_RE.sub("", str(text if text is not None else ""))
    return _CTRL_RE.sub(" ", t)


def _banner():
    print(bold(cyan("  Rampart")) + dim("  — find, prove, fix · authorized, self-hosted AppSec"))


def _err(msg) -> None:
    print(red(f"✗ {_clean(msg)}"))


# ------------------------------------------------------------------ severities / formats
GATE_SEVERITIES = ("low", "medium", "high", "critical")


def _severity_arg(value: str) -> str:
    v = str(value or "").strip().lower()
    if v not in GATE_SEVERITIES:
        raise argparse.ArgumentTypeError(
            f"invalid severity {value!r} (choose from {', '.join(GATE_SEVERITIES)})"
        )
    return v


def _check_severity(value, flag: str) -> str:
    """Validate a severity that may come from a config file. Raises ValueError."""
    try:
        return _severity_arg(value)
    except argparse.ArgumentTypeError as exc:
        raise ValueError(f"{flag}: {exc}") from None


# ------------------------------------------------------------------ config + defaults
# Built-in defaults. Every scan option is declared with default=None so we can tell an explicit
# CLI flag (wins) from "unset" (config file value, else the built-in default below).
_BOOL_OPTS = (
    "crawl",
    "exploit",
    "agents",
    "oob",
    "browser",
    "grpc",
    "infra",
    "authz",
    "bizlogic",
    "api_scan",
    "do_iac",
    "sca_online",
    "active",
    "ci",
    "approve_tier2",
)
_BASE_DEFAULTS = {
    "scope_file": "rampart.scope.yaml",
    "target": "",
    "work_dir": ".rampart",
    "repo": "",
    "openapi": "",
    "appmodel_seed": "",
    "secrets": "",
    "intel": "deterministic",
    "application": "target",
    "login_path": "/api/login",
    "token_path": "token",
    "report": "html,md,json,sarif",
    "scanners": "",
    "parallel": 0,
    "store": "",
    "since": "",
    "fail_on": "high",
    "fail_on_static": "",
    "oob_collaborator_url": "",
    "format": "html",
    "chat_path": "/chat",
    "input_field": "message",
    "output_field": "reply",
    "canary": "",
    **dict.fromkeys(_BOOL_OPTS, False),
}
_CMD_DEFAULTS = {
    "pipeline": {"report": "html,md,json,sarif,compliance,soc2"},
    "retest": {"report": "html,md"},
    "llm-test": {"report": "html,md,json", "application": "llm-target"},
}


def _coerce(dest: str, val, default):
    """Coerce a config-file value to the option's type. Raises ValueError on a bad value."""
    if isinstance(default, bool):
        if isinstance(val, bool):
            return val
        s = str(val).strip().lower()
        if s in ("1", "true", "yes", "on"):
            return True
        if s in ("0", "false", "no", "off", ""):
            return False
        raise ValueError(f"config key {dest!r} must be a boolean, got {val!r}")
    if isinstance(default, int):
        if isinstance(val, bool):
            raise ValueError(f"config key {dest!r} must be an integer, got {val!r}")
        try:
            return int(val)
        except (TypeError, ValueError):
            raise ValueError(f"config key {dest!r} must be an integer, got {val!r}") from None
    if isinstance(val, (list, tuple)):
        return ",".join(str(v).strip() for v in val)
    if isinstance(val, (dict, bool)) or val is None:
        raise ValueError(f"config key {dest!r} must be a string, got {val!r}")
    return str(val)


def _load_config_file(path: str) -> dict:
    from . import yaml_lite

    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    try:
        data = yaml_lite.load(text)
    except Exception as exc:  # noqa: BLE001 - surfaced as a readable error, never a traceback
        raise ValueError(f"could not parse config {path}: {exc}") from None
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ValueError(f"config {path} must be a mapping of option: value")
    return data


def _apply_config(args, parser) -> list:
    """Resolve every option: explicit CLI flag > config file > built-in default.

    ``--config PATH`` (or ./rampart.yaml when present) may set any long option of the command
    using its flag name (``work-dir``) or dest (``work_dir``). Returns warnings (unknown keys).
    Raises ValueError / FileNotFoundError on an unreadable or ill-typed config."""
    cmd = args.cmd
    if parser is None:  # called directly (tests / embedding): use the command's own sub-parser
        parser = getattr(build_parser(), "_rampart_subparsers", {}).get(cmd)
    defaults = dict(_BASE_DEFAULTS)
    defaults.update(_CMD_DEFAULTS.get(cmd, {}))
    names: dict[str, str] = {}
    dests = []
    for action in getattr(parser, "_actions", []):
        if not action.option_strings or action.dest in ("help", "config"):
            continue
        dests.append(action.dest)
        names[action.dest] = action.dest
        for opt in action.option_strings:
            if opt.startswith("--"):
                names[opt[2:]] = action.dest
                names[opt[2:].replace("-", "_")] = action.dest

    path = getattr(args, "config", None) or ""
    if path and not os.path.exists(path):
        raise FileNotFoundError(f"config file not found: {path}")
    if not path and os.path.exists("rampart.yaml"):
        path = "rampart.yaml"
    config = _load_config_file(path) if path else {}
    warnings = []
    resolved = {}
    for key, val in config.items():
        dest = names.get(str(key)) or names.get(str(key).replace("-", "_"))
        if dest is None:
            warnings.append(f"config {path}: unknown key {key!r} ignored for `rampart {cmd}`")
            continue
        resolved[dest] = _coerce(dest, val, defaults.get(dest, ""))
    for dest in dests:
        if getattr(args, dest, None) is None:
            if dest in resolved:
                setattr(args, dest, resolved[dest])
            else:
                setattr(args, dest, defaults.get(dest))
    args.config_path = path
    return warnings


def _make_config(args, approver=None, offline=False):
    from .engagement import EngagementConfig

    return EngagementConfig(
        scope_file=args.scope_file,
        target=args.target or "",
        work_dir=args.work_dir,
        secrets_file=getattr(args, "secrets", "") or "",
        openapi=getattr(args, "openapi", "") or "",
        appmodel_seed=getattr(args, "appmodel_seed", "") or "",
        login_path=getattr(args, "login_path", "") or "/api/login",
        token_json_path=getattr(args, "token_path", "") or "token",
        intel=getattr(args, "intel", "") or "deterministic",
        application=getattr(args, "application", "") or "target",
        repo=getattr(args, "repo", "") or "",
        scanners=getattr(args, "scanners", "") or "",
        crawl=bool(getattr(args, "crawl", False)),
        exploit=bool(getattr(args, "exploit", False)),
        agents=bool(getattr(args, "agents", False)),
        oob=bool(getattr(args, "oob", False)),
        browser=bool(getattr(args, "browser", False)),
        grpc=bool(getattr(args, "grpc", False)),
        infra=bool(getattr(args, "infra", False)),
        authz=bool(getattr(args, "authz", False)),
        bizlogic=bool(getattr(args, "bizlogic", False)),
        api_scan=bool(getattr(args, "api_scan", False)),
        do_dast=bool(getattr(args, "do_dast", True)),
        do_sast=bool(getattr(args, "do_sast", False)),
        do_sca=bool(getattr(args, "do_sca", False)),
        do_iac=bool(getattr(args, "do_iac", False)),
        sca_online=bool(getattr(args, "sca_online", False)),
        parallel=int(getattr(args, "parallel", 0) or 0),
        active=bool(getattr(args, "active", False)),
        deep=bool(getattr(args, "deep", False)),
        store_url=getattr(args, "store", "") or "",
        sast_since=getattr(args, "since", "") or "",
        oob_collaborator_url=getattr(args, "oob_collaborator_url", "") or "",
        offline=offline,
        approver=approver,
    )


def _build_engagement(cfg):
    """Construct an Engagement, turning every expected failure into (None, message)."""
    from .audit.log import AuditLogError
    from .engagement import Engagement

    try:
        return Engagement(cfg), ""
    except ScopeError as e:
        return None, f"refused to run: {e}"
    except FileNotFoundError as e:
        return None, f"refused to run: {e}"
    except AuditLogError as e:
        return None, f"audit log problem: {e}"
    except (ValueError, OSError) as e:
        return None, f"refused to run: {e}"


# --------------------------------------------------------------------------- init
def cmd_init(args):
    _banner()
    try:
        scope = EngagementScope.from_file(args.scope_file)
    except (ScopeError, OSError) as e:
        _err(e)
        return 2
    errs = scope.validate()
    if errs:
        print(red("✗ scope contract is INVALID (engagement would be refused):"))
        for e in errs:
            print(red(f"   - {_clean(e)}"))
        return 2
    print(green("✓ scope contract is valid — engagement may run"))
    print(f"  owner:        {scope.authorization.owner}")
    print(f"  authorized by:{scope.authorization.authorized_by}")
    print(f"  ticket:       {scope.authorization.ticket}")
    print(f"  expires:      {scope.authorization.expires}")
    for hs in scope.in_scope:
        print(f"  in-scope:     {hs.host}:{hs.ports} {hs.methods} paths={hs.paths_include}")
    print(f"  resolved-IPs: {scope.resolved_ip_allowlist}")
    print(
        f"  tier ceiling: {scope.action_policy.default_tier_ceiling} "
        f"(Tier2 approval={scope.action_policy.tier2_requires_approval}, Tier3=deny)"
    )
    print(f"  test accounts:{[a.id for a in scope.test_accounts]}")
    return 0


# --------------------------------------------------------------------------- test
_WHITEBOX_MODES = ("sast", "sca", "iac")


def _print_warnings(args) -> None:
    if getattr(args, "active", False):
        print(
            yellow(
                bold("! --active: gated WRITE / state-changing probes are ENABLED")
                + " (mass assignment, GraphQL, XXE, stored XSS, gRPC invocation). "
                "Only run this against a disposable or authorized test environment."
            )
        )
    if getattr(args, "approve_tier2", False):
        print(
            yellow(
                bold("! --approve-tier2: every Tier-2 (state-changing) action will be AUTO-APPROVED")
                + " without a human in the loop. Use with care."
            )
        )


def cmd_test(args, parser=None, mode=None):
    _banner()
    try:
        for w in _apply_config(args, parser):
            print(yellow(f"! {w}"))
        args.fail_on = _check_severity(args.fail_on, "--fail-on")
        if args.fail_on_static:
            args.fail_on_static = _check_severity(args.fail_on_static, "--fail-on-static")
        from .engagement import normalize_formats

        formats = normalize_formats(args.report)
    except (ValueError, FileNotFoundError, OSError) as e:
        _err(e)
        return 2
    if mode:
        cfg_mode = _MODES[mode]
        for k, v in cfg_mode.items():
            if k != "desc":
                setattr(args, k, v)
        print(dim(f"  mode {mode}: {cfg_mode['desc']}"))
    elif args.cmd in ("test", "scan") and args.repo:
        # `rampart test --repo X` runs the white-box stages too (SAST + secrets + SCA; IaC with --iac)
        args.do_sast = True
        args.do_sca = True
    if getattr(args, "sca_online", False):
        args.do_sca = True  # --sca-online implies the SCA stage
    if getattr(args, "_pipeline", False):
        print(
            dim(
                "  pipeline: recon + full coverage + API/authz/business-logic + IaC + gRPC + infra "
                "+ OOB blind-SSRF + chains + exploitation + agentic reasoning"
                + ("" if args.active else " (read-only: add --active for gated write probes)")
            )
        )
    # sast/sca/iac never contact the target: they run offline (a --target, if given, is only
    # validated against the scope) and need a --repo to scan.
    offline = mode in _WHITEBOX_MODES
    if offline and not args.repo:
        _err(f"`rampart {mode}` needs --repo (the source tree to scan)")
        return 2
    if not offline and not args.target:
        _err("no target given (pass --target or set it in the config file)")
        return 2
    _print_warnings(args)
    approver = None
    if getattr(args, "approve_tier2", False):
        approver = lambda req, dec: {"granted": True, "approver_user_id": "cli:--approve-tier2"}  # noqa: E731
    eng, why = _build_engagement(_make_config(args, approver=approver, offline=offline))
    if eng is None:
        _err(why)
        return 2

    if offline:
        print(
            f"{green('✓')} scope contract valid · white-box only (no target contacted) · repo {bold(args.repo)}"
        )
    else:
        print(
            f"{green('✓')} scope gate passed · target {bold(eng.target_url)} · intel {cyan(eng.intel.name)}"
        )
    print(dim(f"  work dir: {os.path.abspath(eng.cfg.work_dir)}"))

    from .policy.budget import install_kill_signal_handlers, restore_signal_handlers

    previous = install_kill_signal_handlers(eng.budget)
    try:
        result = eng.run_scan()
    except (OSError, ValueError) as e:
        _err(f"scan aborted: {type(e).__name__}: {e}")
        return 2
    finally:
        restore_signal_handlers(previous)

    for entry in result.phase_log:
        msg = _clean(entry.get("msg", ""))
        colour = yellow if msg.lower().startswith(("warning", "incomplete")) or "skipped —" in msg else str
        print(dim(f"  [{_clean(entry.get('phase', '')):>11}] ") + colour(msg))

    if args.repo and result.complete and not offline:
        touched = eng.remediate()
        print(
            f"{green('✓')} remediation proposed for {len(touched)} validated finding(s) "
            + dim("(advisory patch written; never auto-applied)")
        )

    written, rb, chain_ok = eng.report(formats)
    _print_summary(rb, chain_ok, eng)
    for fmt, path in written.items():
        print(f"  {fmt:>10}: {path}")

    if not result.complete:
        reason = result.incomplete_reason
        if reason.startswith("target unreachable"):
            headline = "target unreachable"
        elif reason.startswith("all requests blocked"):
            headline = "all requests blocked by policy"
        else:
            headline = "scan incomplete"
        _err(f"{headline} — scan INCOMPLETE: {reason}")
        print(red("  the results above are NOT a clean bill of health; exit 2 (fails any CI gate)"))
        return 2

    gate_rc = 0
    if getattr(args, "ci", False):
        gate = _ci_gate(rb, args.fail_on)
        if gate:
            print(red(f"✗ CI gate failed: {gate}"))
            gate_rc = 1
        else:
            print(green("✓ CI gate passed"))
    static_hits = _static_at_or_above(rb, args.fail_on_static or args.fail_on)
    if args.fail_on_static:
        if static_hits:
            print(
                red(
                    f"✗ static gate failed: {len(static_hits)} static finding(s) at or above '{args.fail_on_static}'"
                )
            )
            gate_rc = 1
        else:
            print(green(f"✓ static gate passed (--fail-on-static {args.fail_on_static})"))
    elif static_hits and getattr(args, "ci", False):
        print(
            yellow(
                f"! note: {len(static_hits)} static (SAST/SCA/IaC) finding(s) at or above '{args.fail_on}' "
                "do not gate unless --fail-on-static is set"
            )
        )
    return gate_rc


def _static_at_or_above(rb, severity) -> list:
    from .reporting.status import is_dropped, is_fixed, is_static, sev_rank

    if not severity:
        return []
    thr = sev_rank(severity)
    return [
        f
        for f in rb.findings
        if is_static(f) and not is_dropped(f) and not is_fixed(f) and sev_rank(f.severity) <= thr
    ]


def _print_summary(rb, chain_ok, eng):
    m = rb.metrics()
    vr = f"{m['finding_validation_rate'] * 100:.0f}%"
    dropped_txt = f"{m['dropped_candidates']} dropped by FP gate"
    print()
    print(bold("  Results"))
    riskc = (
        red if m["risk_band"] in ("Critical", "High") else (yellow if m["risk_band"] == "Medium" else green)
    )
    exploit_txt = (
        f" · {cyan(str(m['demonstrated_exploits']))} demonstrated" if m.get("demonstrated_exploits") else ""
    )
    agent_txt = f" · {cyan(str(m['agent_assessed']))} agent-assessed" if m.get("agent_assessed") else ""
    print(
        f"   risk {riskc(str(m['risk_score']) + '/100 ' + m['risk_band'])} · "
        f"{cyan(str(m['attack_chains']))} attack chain(s){exploit_txt}{agent_txt}"
        + dim("  (runtime-confirmed findings only)")
    )
    if m.get("static_unvalidated"):
        # aggregate risk ignores unvalidated static findings — show their exposure separately
        print(f"   static exposure {yellow(_clean(rb._static_risk_text(m)))}")
    print(f"   {green(str(m['confirmed']))} confirmed · {dim(dropped_txt)} · validation rate {bold(vr)}")
    extra = []
    if m.get("static_findings"):
        sc = f" ({m['source_correlated']} source-correlated)" if m.get("source_correlated") else ""
        extra.append(f"{cyan(str(m['static_findings']))} static/SAST{sc}")
    if m.get("agent_assessed"):
        extra.append(f"{cyan(str(m['agent_assessed']))} agent-assessed")
    if extra:
        print("   " + " · ".join(extra))
    for f in rb.findings:
        title = _clean(f.title)
        if f.state == State.DROPPED:
            print("   " + dim(f"· dropped: {title}"))
            continue
        sev = _SEV_C.get(f.severity, dim)(f"[{_clean(f.severity).upper()}]")
        mark = green("✔ CONFIRMED") if f.verification.validated else yellow(f"~{_clean(f.confidence)}")
        print(f"   {sev} {title} {mark}")
    # intelligence backend: warn loudly when an LLM provider fell back to the deterministic one
    stored = rb.scan or {}
    intel = stored.get("intel") if isinstance(stored.get("intel"), dict) else eng.intel_status()
    if intel.get("degraded"):
        reasons = "; ".join(intel.get("degraded_reasons") or []) or "unknown reason"
        print(
            yellow(
                f"   ! intel {intel.get('provider')} degraded: {_clean(reasons)}; deterministic fallback used"
            )
        )
    for n in intel.get("notes") or []:
        print(dim(f"   · intel note: {_clean(n)}"))
    # budget: denials mean checks were skipped — a budget-starved run is not a clean run
    b = rb.budget if isinstance(rb.budget, dict) and "requests_used" in rb.budget else eng.budget_status()
    if b.get("denied_total"):
        denied = ", ".join(f"{k}={v}" for k, v in (b.get("denied") or {}).items() if v)
        print(
            yellow(
                f"   ! budget denied {b['denied_total']} request(s)/LLM call(s) ({denied}) — coverage is reduced"
            )
        )
    if b.get("throttled_requests"):
        print(
            dim(
                f"   · rate limit throttled {b['throttled_requests']} request(s) for {b.get('throttle_wait_s', 0)}s"
            )
        )
    _ok, msg, n_events = eng.audit_status()
    if chain_ok:
        ac = green("intact")
    elif n_events == 0:
        ac = yellow("no events")
    else:
        ac = red(f"BROKEN ({_clean(msg)})")
    print(
        dim(
            f"   audit chain: {ac} · {n_events} events · "
            f"cost ${m['usd_spent']} · {m['tokens_used']} tokens · {b.get('requests_used', 0)} requests"
        )
    )
    print()


def _ci_gate(rb, fail_on):
    """Return a failure message if any CONFIRMED finding (validated and still open — the shared
    ``status.is_confirmed`` rule) is at or above ``fail_on``; "" otherwise."""
    from .reporting.status import SEV_RANK, is_confirmed, sev_rank

    level = str(fail_on or "high").strip().lower()
    threshold = SEV_RANK.get(level, SEV_RANK["high"])
    bad = [f for f in rb.findings if is_confirmed(f) and sev_rank(f.severity) <= threshold]
    if bad:
        return f"{len(bad)} validated finding(s) at or above '{level}'"
    return ""


# ---------------------------------------------------------------- scan modes
# Each mode is an isolated slice of the engagement so users run exactly the check they want.
_MODES = {
    "recon": {"do_dast": False, "crawl": True, "desc": "crawl + map + fingerprint only"},
    "dast": {"do_dast": True, "desc": "black-box HTTP/web/API testing (oracle classes + misconfig)"},
    "api": {"do_dast": True, "desc": "API-focused black-box testing (BOLA/BFLA/mass-assignment/exposure/…)"},
    "sast": {
        "do_dast": False,
        "do_sast": True,
        "do_sca": True,
        "do_iac": True,
        "desc": "white-box source + secret/dependency + IaC scan (no target contacted)",
    },
    "sca": {
        "do_dast": False,
        "do_sca": True,
        "desc": "dependency + secret scan (add --sca-online for OSV CVE matching)",
    },
    "iac": {
        "do_dast": False,
        "do_iac": True,
        "desc": "white-box IaC / cloud-config scan (Terraform/CFN/Kubernetes/Dockerfile)",
    },
    "grpc": {"do_dast": False, "grpc": True, "desc": "gRPC server-reflection exposure probe ([grpc] extra)"},
    "infra": {
        "do_dast": False,
        "infra": True,
        "desc": "live infrastructure / exposed-services scan (scope-gated TCP)",
    },
    "authz": {
        "do_dast": False,
        "authz": True,
        "desc": "deeper auth checks (weak JWT secret, expiry-not-enforced)",
    },
    "bizlogic": {
        "do_dast": False,
        "bizlogic": True,
        "desc": "deterministic business-logic checks (economic/parameter tampering)",
    },
    "apiscan": {
        "do_dast": False,
        "api_scan": True,
        "desc": "deeper API checks (HTTP verb tampering, GraphQL depth)",
    },
    "agents": {"do_dast": True, "agents": True, "desc": "black-box + agentic business-logic reasoning"},
}


def cmd_mode(args, mode, parser=None):
    return cmd_test(args, parser=parser, mode=mode)


def _oracle_count() -> int:
    from .validation.registry import ORACLES

    return len(ORACLES)


def cmd_features(args):
    _banner()
    t = "--target http://127.0.0.1:8080"
    rows = [
        ("recon", "Attack-surface discovery (crawl, map, fingerprint)", f"rampart recon {t}"),
        (
            "dast",
            f"Black-box web/API testing — {_oracle_count()} oracle-validated classes + misconfig checks",
            f"rampart dast {t}",
        ),
        ("api", "API-focused testing (BOLA, BFLA, mass assignment, data exposure)", f"rampart api {t}"),
        (
            "sast",
            "White-box source scan (native AST sinks) + secrets + dependencies + IaC (offline)",
            "rampart sast --repo .",
        ),
        (
            "sca",
            "Full SCA — pinned deps matched against OSV.dev with upgrade remediation",
            "rampart sca --repo . --sca-online",
        ),
        (
            "iac",
            "IaC / cloud-config scan (Terraform, CloudFormation, Kubernetes, Dockerfile)",
            "rampart iac --repo .",
        ),
        ("grpc", "gRPC server-reflection exposure probe", "rampart grpc --target grpc://127.0.0.1:50051"),
        (
            "llm",
            "OWASP LLM Top 10 (prompt injection, leakage, jailbreak)",
            "rampart llm-test --target http://127.0.0.1:8080 --chat-path /chat",
        ),
        (
            "agents",
            "Agentic reasoning for business-logic / auth-flow flaws (agent-assessed)",
            f"rampart agents {t} --intel claude-code",
        ),
        (
            "exploit",
            "Demonstrate bounded, non-destructive impact for confirmed findings",
            f"rampart dast {t} --exploit",
        ),
        ("oob", "Blind SSRF/XXE confirmation via out-of-band collaborator", f"rampart dast {t} --oob"),
        (
            "browser",
            "DOM & stored XSS via headless browser (optional [browser] extra)",
            f"rampart dast {t} --browser",
        ),
        (
            "scanners",
            "External OSS tools (nuclei/nmap/semgrep/trivy/testssl) as leads",
            f"rampart dast {t} --scanners all",
        ),
        (
            "pipeline",
            "Everything (read-only), orchestrated, with correlation + risk + SOC 2 report",
            f"rampart pipeline {t}",
        ),
        ("serve", "Local zero-dep web dashboard", "rampart serve"),
        ("mcp", "MCP server (scope-guarded tools for Claude Code / agents)", "rampart mcp"),
        ("report", "Regenerate reports (html/md/json/sarif/compliance/soc2)", "rampart report --format soc2"),
    ]
    print(bold("\n  Rampart capabilities (run any in isolation, or `pipeline` for all)\n"))
    for name, desc, example in rows:
        print(f"   {cyan(name):<12} {desc}")
        print(dim(f"                {example}"))
    print(
        dim(
            "\n  Every example reads ./rampart.scope.yaml (pass --scope-file to use another contract); the "
            "target must be listed in it, host AND port.\n"
            "  Testing types: black-box (dast/api/llm) · grey-box (dast + --openapi/seed) · "
            "white-box (sast/sca/iac). Confidence tiers: oracle-confirmed > agent-assessed > external-lead > static."
        )
    )
    return 0


# ------------------------------------------------------------------------- pipeline
def cmd_pipeline(args, parser=None):
    """The full pipeline: scope-gate -> crawl -> map -> every class -> correlate -> report.

    Gated write probes are NOT implied: pass --active explicitly (a prominent warning is shown)."""
    args.crawl = True
    args.exploit = True
    args.agents = True
    args.oob = True
    args.do_sast = True  # white-box runs too when --repo is given (skipped otherwise)
    args.do_sca = True
    args.do_iac = True  # IaC/cloud-config scan when --repo is given (skipped otherwise)
    args.grpc = True  # gRPC reflection probe (no-op unless the [grpc] extra + a gRPC target)
    args.infra = True  # live exposed-services scan of the in-scope host (scoped ports only)
    args.authz = True  # deeper auth (weak JWT secret / expiry)
    args.bizlogic = True  # deterministic business-logic (economic/parameter tampering)
    args.api_scan = True  # deeper API checks (verb tampering, GraphQL depth)
    # --active and --sca-online stay explicit operator opt-ins: one sends state-changing requests,
    # the other sends dependency names to an external service (OSV.dev).
    args._pipeline = True
    return cmd_test(args, parser=parser)


# ------------------------------------------------------------------------- serve
def cmd_serve(args):
    from .server.dashboard import build_server

    _banner()
    try:
        httpd = build_server(args.host, args.port, args.work_dir)
    except OSError as e:
        _err(e)
        return 1
    host, port = httpd.server_address[:2]
    print(
        f"{green('✓')} Rampart dashboard on http://{args.host}:{port}  "
        + dim(f"(work-dir {os.path.abspath(args.work_dir)})"),
        flush=True,
    )
    print(dim("  press Ctrl-C to stop"), flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n  stopped", flush=True)
    finally:
        httpd.server_close()
    return 0


# ------------------------------------------------------------------------- stored runs
def _stored_run_or_error(args) -> str:
    """'' if args.work_dir holds a stored run, else an error message. Creates nothing."""
    from .engagement import has_stored_run

    if not has_stored_run(args.work_dir):
        return (
            f"no stored run in {os.path.abspath(args.work_dir)} (run `rampart test` first or pass --work-dir)"
        )
    return ""


def _resolve_stored_target(args) -> None:
    from .engagement import stored_run_target

    if not getattr(args, "target", None):
        args.target = stored_run_target(args.work_dir)
        if args.target:
            print(dim(f"  target (from stored run): {args.target}"))


# ------------------------------------------------------------------------- retest
_RETEST_COLOURS = {
    "Fixed": green,
    "still-vulnerable": red,
    "Regression": red,
    "inconclusive": yellow,
}


def cmd_retest(args, parser=None):
    _banner()
    try:
        for w in _apply_config(args, parser):
            print(yellow(f"! {w}"))
        from .engagement import normalize_formats

        formats = normalize_formats(args.report)
    except (ValueError, FileNotFoundError, OSError) as e:
        _err(e)
        return 2
    why = _stored_run_or_error(args)
    if why:
        _err(why)
        return 2
    _resolve_stored_target(args)
    if not args.target:
        _err("no target recorded in the stored run — pass --target")
        return 2
    eng, why = _build_engagement(_make_config(args))
    if eng is None:
        _err(why)
        return 2
    from .policy.budget import install_kill_signal_handlers, restore_signal_handlers

    previous = install_kill_signal_handlers(eng.budget)
    try:
        results = eng.retest()
    finally:
        restore_signal_handlers(previous)
    if not results:
        print(yellow("no validated findings to retest (run `rampart test` first)"))
        return 0
    counts: dict[str, int] = {}
    for f, outcome in results:
        counts[outcome] = counts.get(outcome, 0) + 1
        col = _RETEST_COLOURS.get(outcome, dim)
        print(f"  {col(outcome)}: {_clean(f.title)}")
    print(dim("  " + " · ".join(f"{v} {k}" for k, v in counts.items())))
    try:
        eng.report(formats)
    except OSError as e:
        _err(f"could not write reports: {e}")
    if counts.get("still-vulnerable") or counts.get("Regression"):
        print(red("✗ retest: finding(s) still vulnerable / regressed"))
        return 1
    if counts.get("inconclusive"):
        print(
            yellow(
                "! retest inconclusive for some finding(s) — the target could not give a meaningful answer"
            )
        )
        return 2
    print(green("✓ retest: every replayable finding is fixed"))
    return 0


# ------------------------------------------------------------------------- report
def cmd_report(args, parser=None):
    _banner()
    try:
        for w in _apply_config(args, parser):
            print(yellow(f"! {w}"))
        from .engagement import normalize_formats

        formats = normalize_formats(args.format)
    except (ValueError, FileNotFoundError, OSError) as e:
        _err(e)
        return 2
    why = _stored_run_or_error(args)
    if why:
        _err(why)
        return 2
    _resolve_stored_target(args)
    eng, why = _build_engagement(_make_config(args, offline=not args.target))
    if eng is None:
        _err(why)
        return 2
    try:
        written, rb, chain_ok = eng.report(formats)
    except (OSError, ValueError) as e:
        _err(e)
        return 2
    _print_summary(rb, chain_ok, eng)
    for fmt, path in written.items():
        print(f"  {fmt:>10}: {path}")
    return 0


# -------------------------------------------------------------------- tools
def cmd_tools(args):
    from .scanners.adapters import doctor

    _banner()
    info = doctor()
    dstat = green("available") if info["docker"] else yellow("not detected")
    print(f"  Docker: {dstat}  " + dim("(optional — enables containerised scanners)"))
    print(bold("\n  External OSS scanner adapters"))
    any_avail = False
    for row in info["adapters"]:
        if row["available"]:
            any_avail = True
            mark = green("✓ installed")
            extra = dim(f" · {_clean(row['version'])}") if row["version"] else ""
            if row.get("skip_reason"):
                extra += yellow(f" · will skip: {_clean(row['skip_reason'])}")
        else:
            mark = dim("· not installed")
            extra = dim(f" — {row['install_hint']}")
        net = cyan("[network]") if row["network"] else dim(f"[{row['category']}]")
        print(f"   {mark}  {bold(row['name']):<22} {net}{extra}")
    print()
    if any_avail:
        print(dim("  enable with:  rampart test --scanners nuclei,semgrep ...  (or --scanners all)"))
    else:
        print(dim("  none installed — Rampart's built-in oracles still run with zero external deps."))
    print(dim("  see docs/EXTERNAL_TOOLS.md to light these up."))
    # Built-in optional engines
    try:
        from .browser import available as _browser_available
        from .browser import install_hint as _browser_hint

        browser_ok = _browser_available()
    except Exception:  # noqa: BLE001
        browser_ok, _browser_hint = False, "pip install rampart-appsec[browser]"
    try:
        from .grpc_scan import available as _grpc_available
        from .grpc_scan import install_hint as _grpc_hint

        grpc_ok = _grpc_available()
    except Exception:  # noqa: BLE001
        grpc_ok, _grpc_hint = False, "pip install rampart-appsec[grpc]"
    print(bold("\n  Built-in engines"))
    bmark = green("✓ available") if browser_ok else dim("· not installed")
    print(
        f"   {bmark}  {bold('headless-browser (DOM/stored XSS)'):<40} "
        + ("" if browser_ok else dim(_browser_hint))
    )
    gmark = green("✓ available") if grpc_ok else dim("· not installed")
    print(
        f"   {gmark}  {bold('gRPC reflection / per-RPC probe'):<40} " + ("" if grpc_ok else dim(_grpc_hint))
    )
    print(
        f"   {green('✓ built-in')}  {bold('OOB collaborator (blind SSRF/XXE)'):<40} "
        + dim("enable with --oob (remote targets: --oob-collaborator-url)")
    )
    print(
        f"   {green('✓ built-in')}  {bold('agentic reasoning (business logic)'):<40} "
        + dim("enable with --agents (needs --intel claude-code / openai-compat)")
    )
    return 0


# -------------------------------------------------------------------- llm-test
def cmd_llm_test(args, parser=None):
    _banner()
    try:
        for w in _apply_config(args, parser):
            print(yellow(f"! {w}"))
        args.fail_on = _check_severity(args.fail_on, "--fail-on")
        from .engagement import normalize_formats

        formats = normalize_formats(args.report)
    except (ValueError, FileNotFoundError, OSError) as e:
        _err(e)
        return 2
    if not args.target:
        _err("no target given (pass --target)")
        return 2
    from .engagement import EngagementConfig

    # The LLM assessment sends gated POSTs (Tier 2); the operator authorizes them by running
    # this command against an in-scope endpoint, so Tier-2 is auto-approved and audited as such.
    approver = lambda req, dec: {"granted": True, "approver_user_id": "cli:llm-test"}  # noqa: E731
    cfg = EngagementConfig(
        scope_file=args.scope_file,
        target=args.target,
        work_dir=args.work_dir,
        secrets_file=getattr(args, "secrets", "") or "",
        application=args.application or "llm-target",
        llm_chat_path=args.chat_path,
        llm_input_field=args.input_field,
        llm_output_field=args.output_field,
        llm_canary=args.canary,
        approver=approver,
    )
    eng, why = _build_engagement(cfg)
    if eng is None:
        _err(why)
        return 2
    print(
        f"{green('✓')} scope gate passed · LLM target {bold(eng.target_url)}{_clean(eng.cfg.llm_chat_path)}"
    )
    from .policy.budget import install_kill_signal_handlers, restore_signal_handlers

    previous = install_kill_signal_handlers(eng.budget)
    try:
        res = eng.run_llm()
    finally:
        restore_signal_handlers(previous)
    print(bold("\n  OWASP LLM Top-10 probes"))
    for p in res.probe_log:
        mark = {
            "confirmed": green("✔ CONFIRMED"),
            "not-vulnerable": dim("· held"),
            "blocked": yellow("blocked"),
            "unconfirmed": yellow("~unconfirmed"),
            "error": red("error"),
            "inconclusive": yellow("inconclusive"),
            "skipped": dim("skipped"),
        }.get(p["result"], _clean(p["result"]))
        note = dim(f"  {_clean(p['note'])}") if p.get("note") else ""
        print(f"   {_clean(p['owasp']):<42} {mark}{note}")
    written, rb, chain_ok = eng.report(formats)
    m = rb.metrics()
    counts = getattr(res, "counts", {}) or {}
    print(
        f"\n  {green(str(m['confirmed']))} confirmed LLM finding(s) · "
        f"{counts.get('executed', 0)}/{counts.get('total', len(res.probe_log))} probe(s) evaluated · audit chain "
        f"{'intact' if chain_ok else red('BROKEN')}"
    )
    for fmt, path in written.items():
        print(f"  {fmt:>10}: {path}")
    if not getattr(res, "complete", True) or not counts.get("executed", 0):
        _err(
            f"LLM assessment INCOMPLETE: {getattr(res, 'incomplete_reason', '') or 'no probe was evaluated'}"
        )
        return 2
    if (counts.get("error", 0) + counts.get("inconclusive", 0)) > 0 and not m["confirmed"]:
        _err(
            f"{counts.get('error', 0)} probe(s) errored and {counts.get('inconclusive', 0)} were inconclusive with "
            "nothing confirmed — the result is not a clean bill of health"
        )
        return 2
    if getattr(args, "ci", False):
        gate = _ci_gate(rb, args.fail_on)
        if gate:
            print(red(f"✗ CI gate failed: {gate}"))
            return 1
        print(green("✓ CI gate passed"))
    return 0


# -------------------------------------------------------------------- verify-audit
def cmd_verify_audit(args):
    from .audit import AuditLog

    _banner()
    path = os.path.join(args.work_dir, "audit.jsonl")
    if not os.path.exists(path):
        _err(f"audit chain: not intact — no events (no audit log at {path})")
        return 2
    log = AuditLog(path)
    ok, msg = log.verify_chain()
    events = log.read_all()
    print((green("✓") if ok else red("✗")) + f" audit chain: {_clean(msg)} ({len(events)} events)")
    return 0 if ok else 1


def cmd_pr_comment(args):
    """Render a run's findings as a GitHub PR comment, and post it (or print it with --dry-run)."""
    from .reporting.status import SEV_RANK, is_confirmed, sev_rank

    report_path = args.report or os.path.join(args.work_dir, "reports", "report.json")
    if not os.path.exists(report_path):
        _err(f"no report at {report_path} — run a scan with `--report json` first")
        return 2
    try:
        with open(report_path, encoding="utf-8") as fh:
            report = json.load(fh)
        if not isinstance(report, dict) or not isinstance(report.get("findings", []), list):
            raise ValueError("not a Rampart report.json (expected an object with a 'findings' list)")
    except (OSError, ValueError) as e:
        _err(f"could not read {report_path}: {e}")
        return 2
    from .reporting.pr_comment import render_from_report

    fail_on = getattr(args, "fail_on", "") or None
    body = render_from_report(
        report,
        fail_on=fail_on,
        report_url=getattr(args, "report_url", "") or "",
        application=getattr(args, "application", "") or "",
    )

    gate_breached = False
    if fail_on:
        thr = SEV_RANK[fail_on]
        gate_breached = any(
            isinstance(f, dict) and is_confirmed(f) and sev_rank(f.get("severity")) <= thr
            for f in report.get("findings", [])
        )

    if getattr(args, "dry_run", False):
        print(body)
        return 1 if gate_breached else 0

    from .integrations.github import post_or_update_comment

    res = post_or_update_comment(
        body,
        repo=getattr(args, "repo", "") or None,
        pr=(getattr(args, "pr", 0) or None),
        token=getattr(args, "token", "") or None,
    )
    if res.get("posted"):
        print(green(f"✓ PR comment {res.get('action')}: {res.get('url', '')}"))
    else:
        print(red(f"✗ not posted: {_clean(res.get('reason'))}"))
        print(dim("  (showing the comment below; re-run with --dry-run to only print it)"))
        print(body)
    if gate_breached:
        print(red(f"✗ PR gate failed: confirmed finding(s) at or above '{fail_on}'"))
    return 1 if gate_breached else 0


# -------------------------------------------------------------------------- parser
def _add_scan_opts(sp, *, since=True):
    """Every option shared by test/scan/pipeline/modes. Defaults are None (see _apply_config)."""
    sp.add_argument("--scope-file", default=None, help="the rampart.scope.yaml authorization contract")
    sp.add_argument("--target", default=None, help="authorized target base URL, e.g. http://127.0.0.1:8080")
    sp.add_argument(
        "--work-dir", default=None, help="run directory (audit, evidence, reports); default .rampart"
    )
    sp.add_argument("--config", default=None, help="load option defaults from a YAML file (CLI flags win)")
    sp.add_argument("--repo", default=None, help="repo path: white-box SAST/secrets/SCA + source correlation")
    sp.add_argument("--openapi", default=None, help="OpenAPI spec for the app model (grey-box)")
    sp.add_argument("--appmodel-seed", default=None, help="seeded object-ownership file")
    sp.add_argument("--secrets", default=None, help="secrets file (default: secrets.json next to the scope)")
    sp.add_argument(
        "--intel", default=None, help="intelligence provider: deterministic | claude-code | openai-compat"
    )
    sp.add_argument("--application", default=None, help="application name for findings")
    sp.add_argument("--login-path", default=None)
    sp.add_argument("--token-path", default=None)
    sp.add_argument(
        "--report", default=None, help="comma list: html,md,json,sarif,compliance,soc2 (case-insensitive)"
    )
    sp.add_argument(
        "--scanners",
        default=None,
        help="external OSS adapters: nuclei,nmap,semgrep,bandit,gitleaks,trivy,... or 'all'",
    )
    sp.add_argument(
        "--crawl", action="store_true", default=None, help="discover endpoints/params by crawling"
    )
    sp.add_argument(
        "--exploit",
        action="store_true",
        default=None,
        help="demonstrate bounded impact for confirmed findings",
    )
    sp.add_argument(
        "--agents", action="store_true", default=None, help="multi-agent reasoning (needs an LLM intel)"
    )
    sp.add_argument("--oob", action="store_true", default=None, help="OOB collaborator for blind SSRF/XXE")
    sp.add_argument(
        "--oob-collaborator-url",
        default=None,
        help="externally reachable collaborator base URL (needed for --oob against a non-loopback target)",
    )
    sp.add_argument(
        "--browser", action="store_true", default=None, help="headless-browser DOM/stored XSS ([browser])"
    )
    sp.add_argument("--grpc", action="store_true", default=None, help="gRPC reflection probe ([grpc] extra)")
    sp.add_argument(
        "--infra", action="store_true", default=None, help="live exposed-services scan (scoped ports)"
    )
    sp.add_argument(
        "--authz", action="store_true", default=None, help="deeper auth checks (weak JWT secret, expiry)"
    )
    sp.add_argument(
        "--bizlogic", action="store_true", default=None, help="deterministic business-logic checks"
    )
    sp.add_argument(
        "--api-scan", dest="api_scan", action="store_true", default=None, help="verb tampering, GraphQL depth"
    )
    sp.add_argument(
        "--iac", dest="do_iac", action="store_true", default=None, help="scan --repo for IaC misconfig"
    )
    sp.add_argument(
        "--sca-online",
        dest="sca_online",
        action="store_true",
        default=None,
        help="full SCA via OSV.dev (implies SCA; sends package names to an external service)",
    )
    sp.add_argument("--parallel", type=int, default=None, help="orchestrator worker cap (0 = scope limit)")
    sp.add_argument(
        "--deep",
        action="store_true",
        default=None,
        help="finding-driven escalation: a validated finding spawns bounded, oracle-proven deep-scan "
        "follow-ups (deduped; hard depth/total/per-finding caps)",
    )
    sp.add_argument(
        "--active",
        action="store_true",
        default=None,
        help="allow gated write/state-changing probes (off by default, also for pipeline)",
    )
    sp.add_argument(
        "--store", default=None, help="multi-tenant store URL (sqlite:///runs.db or postgresql://…)"
    )
    if since:
        sp.add_argument(
            "--since", default=None, help="diff-aware SAST: only .py files changed vs this git ref"
        )
    sp.add_argument(
        "--ci", action="store_true", default=None, help="nonzero exit if the severity gate is breached"
    )
    sp.add_argument(
        "--fail-on",
        type=_severity_arg,
        default=None,
        metavar="{low,medium,high,critical}",
        help="CI gate severity for confirmed findings (default high; case-insensitive)",
    )
    sp.add_argument(
        "--fail-on-static",
        type=_severity_arg,
        default=None,
        metavar="{low,medium,high,critical}",
        help="also fail (exit 1) on static SAST/SCA/IaC findings at or above this severity",
    )
    sp.add_argument(
        "--approve-tier2",
        action="store_true",
        default=None,
        help="auto-approve Tier-2 actions (use with care)",
    )


def build_parser():
    p = argparse.ArgumentParser(
        prog="rampart", description="Authorized, self-hosted, evidence-first AppSec agent."
    )
    p.add_argument("--version", action="version", version=f"rampart {__version__}")
    sub = p.add_subparsers(dest="cmd")
    subs: dict = {}

    sp = sub.add_parser("init", help="validate the scope contract")
    sp.add_argument("--scope-file", default="rampart.scope.yaml")

    for name, help_text in (
        ("test", "run an authorized assessment (flagship)"),
        ("scan", "alias for test"),
        ("pipeline", "the full pipeline (crawl + all read-only classes + chains + report); --active opt-in"),
    ):
        sp = sub.add_parser(name, help=help_text)
        _add_scan_opts(sp)
        subs[name] = sp

    mode_help = {
        "recon": "mode: attack-surface discovery only (crawl + map + fingerprint)",
        "dast": "mode: black-box web/API testing (oracle classes + misconfig)",
        "api": "mode: API-focused black-box testing",
        "sast": "mode: white-box source scan + secrets + dependencies + IaC (no --target needed)",
        "sca": "mode: dependency + secret scan (--sca-online for OSV CVE matching; no --target needed)",
        "iac": "mode: white-box IaC / cloud-config scan (no --target needed)",
        "grpc": "mode: gRPC server-reflection exposure probe (--target grpc://host:port)",
        "infra": "mode: live infrastructure / exposed-services scan",
        "authz": "mode: deeper auth checks (weak JWT secret, expiry-not-enforced)",
        "bizlogic": "mode: deterministic business-logic checks (economic/parameter tampering)",
        "apiscan": "mode: deeper API checks (HTTP verb tampering, GraphQL depth)",
        "agents": "mode: black-box + agentic business-logic reasoning",
    }
    for name in _MODES:
        sp = sub.add_parser(name, help=mode_help[name])
        _add_scan_opts(sp)
        subs[name] = sp
    sub.add_parser("features", help="list Rampart's capabilities and how to run each in isolation")

    sp = sub.add_parser("serve", help="serve a local web dashboard over a run work-dir (zero-dep)")
    sp.add_argument("--host", default="127.0.0.1")
    sp.add_argument("--port", type=int, default=8787)
    sp.add_argument("--work-dir", default=".rampart")

    sp = sub.add_parser("retest", help="replay validated findings against the (patched) target")
    sp.add_argument("--scope-file", default=None)
    sp.add_argument("--target", default=None, help="default: the target recorded in the stored run")
    sp.add_argument("--work-dir", default=None)
    sp.add_argument("--config", default=None)
    sp.add_argument("--secrets", default=None)
    sp.add_argument("--openapi", default=None)
    sp.add_argument("--appmodel-seed", default=None)
    sp.add_argument("--intel", default=None)
    sp.add_argument("--application", default=None)
    sp.add_argument("--login-path", default=None)
    sp.add_argument("--token-path", default=None)
    sp.add_argument("--report", default=None, help="comma list of report formats (default html,md)")
    subs["retest"] = sp

    sp = sub.add_parser("report", help="regenerate reports from a stored run")
    sp.add_argument("--scope-file", default=None)
    sp.add_argument("--target", default=None, help="default: the target recorded in the stored run")
    sp.add_argument("--work-dir", default=None)
    sp.add_argument("--config", default=None)
    sp.add_argument("--secrets", default=None)
    sp.add_argument("--openapi", default=None)
    sp.add_argument("--appmodel-seed", default=None)
    sp.add_argument("--application", default=None)
    sp.add_argument(
        "--format", default=None, help="comma list: html,md,json,sarif,compliance,soc2 (case-insensitive)"
    )
    subs["report"] = sp

    sp = sub.add_parser("verify-audit", help="verify the append-only audit hash chain")
    sp.add_argument("--work-dir", default=".rampart")

    sp = sub.add_parser("pr-comment", help="post a run's findings as a GitHub pull-request comment")
    sp.add_argument("--work-dir", default=".rampart")
    sp.add_argument(
        "--report", default="", help="path to report.json (default: <work-dir>/reports/report.json)"
    )
    sp.add_argument("--repo", default="", help="owner/name (default: $GITHUB_REPOSITORY)")
    sp.add_argument("--pr", type=int, default=0, help="PR number (default: inferred from the GitHub event)")
    sp.add_argument("--token", default="", help="GitHub token (default: $GITHUB_TOKEN)")
    sp.add_argument(
        "--fail-on",
        type=_severity_arg,
        default=None,
        metavar="{low,medium,high,critical}",
        help="exit 1 if a confirmed finding is >= this severity",
    )
    sp.add_argument("--report-url", default="", help="link to the full report, shown in the comment")
    sp.add_argument("--application", default="", help="application name shown in the comment header")
    sp.add_argument("--dry-run", action="store_true", help="print the comment instead of posting it")

    sub.add_parser("tools", help="show which external OSS scanners / optional engines are installed")

    sub.add_parser("mcp", help="run the MCP stdio server (scope-guarded tools for Claude Code / agents)")

    sp = sub.add_parser("llm-test", help="assess an LLM endpoint against the OWASP LLM Top 10")
    sp.add_argument("--scope-file", default=None)
    sp.add_argument("--target", default=None, help="authorized LLM endpoint base URL")
    sp.add_argument("--work-dir", default=None)
    sp.add_argument("--config", default=None)
    sp.add_argument("--secrets", default=None)
    sp.add_argument("--chat-path", default=None, help="path that accepts the prompt (default /chat)")
    sp.add_argument(
        "--input-field", default=None, help="JSON field holding the user prompt (default message)"
    )
    sp.add_argument(
        "--output-field", default=None, help="dotted JSON path to the model reply (default reply)"
    )
    sp.add_argument("--canary", default=None, help="secret planted in the system prompt (leak oracle)")
    sp.add_argument("--application", default=None)
    sp.add_argument("--report", default=None)
    sp.add_argument(
        "--ci", action="store_true", default=None, help="nonzero exit if the severity gate is breached"
    )
    sp.add_argument(
        "--fail-on",
        type=_severity_arg,
        default=None,
        metavar="{low,medium,high,critical}",
        help="CI gate severity (default high; case-insensitive)",
    )
    subs["llm-test"] = sp
    p._rampart_subparsers = subs
    return p


def _force_utf8():
    for stream in (sys.stdout, sys.stderr):
        try:
            # line-buffered so progress/banners show up promptly under docker compose / pipes
            stream.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)
        except Exception:  # noqa: BLE001 - older/odd streams; fall back silently
            pass


def main(argv=None):
    _force_utf8()
    parser = build_parser()
    args = parser.parse_args(argv)
    subs = getattr(parser, "_rampart_subparsers", {})
    sp = subs.get(args.cmd)
    if args.cmd in ("test", "scan"):
        return cmd_test(args, parser=sp)
    if args.cmd == "pipeline":
        return cmd_pipeline(args, parser=sp)
    if args.cmd in _MODES:
        return cmd_mode(args, args.cmd, parser=sp)
    if args.cmd == "features":
        return cmd_features(args)
    if args.cmd == "serve":
        return cmd_serve(args)
    if args.cmd == "init":
        return cmd_init(args)
    if args.cmd == "retest":
        return cmd_retest(args, parser=sp)
    if args.cmd == "report":
        return cmd_report(args, parser=sp)
    if args.cmd == "verify-audit":
        return cmd_verify_audit(args)
    if args.cmd == "pr-comment":
        return cmd_pr_comment(args)
    if args.cmd == "tools":
        return cmd_tools(args)
    if args.cmd == "mcp":
        from .mcp import serve_stdio

        return serve_stdio(sys.stdin, sys.stdout) or 0
    if args.cmd == "llm-test":
        return cmd_llm_test(args, parser=sp)
    parser.print_help()
    return 2
