"""The ``rampart`` command-line interface (developer-first DX, blueprint section 19).

    rampart init      --scope-file SECURITY.md
    rampart test      --scope-file SECURITY.md --target http://127.0.0.1:8080 [--repo .] [--report html,md,sarif,json]
    rampart retest    --scope-file SECURITY.md --target ... --work-dir .rampart
    rampart report    --scope-file SECURITY.md --target ... --format html
    rampart verify-audit --work-dir .rampart

`test` is the flagship: scope-gate -> map -> hypothesize -> validate -> report, with
`--repo` adding source correlation and an advisory patch. Dependency-free (argparse).
"""
from __future__ import annotations

import argparse
import os
import sys

from .version import __version__
from .schemas.scope import EngagementScope, ScopeError
from .schemas.finding import State

_USE_COLOR = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def _c(text, code):
    return f"\033[{code}m{text}\033[0m" if _USE_COLOR else str(text)


def bold(t): return _c(t, "1")
def green(t): return _c(t, "32")
def red(t): return _c(t, "31")
def yellow(t): return _c(t, "33")
def cyan(t): return _c(t, "36")
def dim(t): return _c(t, "2")


_SEV_C = {"critical": red, "high": red, "medium": yellow, "low": cyan, "info": dim}


def _banner():
    print(bold(cyan("  Rampart")) + dim("  — find, prove, fix · authorized, self-hosted AppSec"))


def _load_config(args):
    """Fill UNSET args from a rampart.yaml (or --config) file. CLI flags always win."""
    path = getattr(args, "config", "") or ("rampart.yaml" if os.path.exists("rampart.yaml") else "")
    if not path or not os.path.exists(path):
        return
    from . import yaml_lite
    try:
        with open(path, encoding="utf-8") as fh:
            data = yaml_lite.load(fh.read()) or {}
    except Exception:  # noqa: BLE001 - a bad config must not crash the CLI
        print(yellow(f"! could not parse config {path}; ignoring"))
        return
    if not isinstance(data, dict):
        return
    # argparse defaults we treat as "unset" so a config value may fill them (CLI overrides still win
    # in practice — a user who types the default value and also sets it in config gets the config one).
    known_defaults = {"scope_file": "SECURITY.md", "intel": "deterministic", "application": "target",
                      "login_path": "/api/login", "token_path": "token", "fail_on": "high",
                      "report": "html,md,json,sarif"}
    for key, val in data.items():
        attr = str(key).replace("-", "_")
        if not hasattr(args, attr):
            continue
        cur = getattr(args, attr)
        unset = cur in ("", None) or cur == known_defaults.get(attr) or (attr == "crawl" and not cur)
        if unset and val not in (None, ""):
            setattr(args, attr, val)


def _make_config(args, approver=None):
    from .engagement import EngagementConfig
    return EngagementConfig(
        scope_file=args.scope_file,
        target=args.target,
        work_dir=args.work_dir,
        secrets_file=getattr(args, "secrets", "") or "",
        openapi=getattr(args, "openapi", "") or "",
        appmodel_seed=getattr(args, "appmodel_seed", "") or "",
        login_path=getattr(args, "login_path", "/api/login"),
        token_json_path=getattr(args, "token_path", "token"),
        intel=getattr(args, "intel", "deterministic"),
        application=getattr(args, "application", "target"),
        repo=getattr(args, "repo", "") or "",
        scanners=getattr(args, "scanners", "") or "",
        crawl=getattr(args, "crawl", False),
        exploit=getattr(args, "exploit", False),
        approver=approver,
    )


# --------------------------------------------------------------------------- init
def cmd_init(args):
    _banner()
    try:
        scope = EngagementScope.from_file(args.scope_file)
    except ScopeError as e:
        print(red(f"✗ {e}"))
        return 2
    errs = scope.validate()
    if errs:
        print(red("✗ scope contract is INVALID (engagement would be refused):"))
        for e in errs:
            print(red(f"   - {e}"))
        return 2
    print(green("✓ scope contract is valid — engagement may run"))
    print(f"  owner:        {scope.authorization.owner}")
    print(f"  authorized by:{scope.authorization.authorized_by}")
    print(f"  ticket:       {scope.authorization.ticket}")
    print(f"  expires:      {scope.authorization.expires}")
    for hs in scope.in_scope:
        print(f"  in-scope:     {hs.host}:{hs.ports} {hs.methods} paths={hs.paths_include}")
    print(f"  resolved-IPs: {scope.resolved_ip_allowlist}")
    print(f"  tier ceiling: {scope.action_policy.default_tier_ceiling} "
          f"(Tier2 approval={scope.action_policy.tier2_requires_approval}, Tier3=deny)")
    print(f"  test accounts:{[a.id for a in scope.test_accounts]}")
    return 0


# --------------------------------------------------------------------------- test
def cmd_test(args):
    from .engagement import Engagement
    _banner()
    _load_config(args)
    # precedence: explicit CLI flag > rampart.yaml > built-in default
    args.scope_file = getattr(args, "scope_file", None) or "SECURITY.md"
    args.intel = getattr(args, "intel", None) or "deterministic"
    args.application = getattr(args, "application", None) or "target"
    args.login_path = getattr(args, "login_path", None) or "/api/login"
    args.token_path = getattr(args, "token_path", None) or "token"
    args.fail_on = getattr(args, "fail_on", None) or "high"
    args.report = getattr(args, "report", None) or (
        "html,md,json,sarif,compliance,soc2" if getattr(args, "_pipeline", False) else "html,md,json,sarif")
    if not getattr(args, "target", None):
        print(red("✗ no target given (pass --target or set it in rampart.yaml)"))
        return 2
    approver = None
    if getattr(args, "approve_tier2", False):
        print(yellow("! --approve-tier2: Tier-2 (state-changing) actions will be auto-approved"))
        approver = lambda req, dec: {"granted": True, "approver_user_id": "cli:--approve-tier2"}
    try:
        eng = Engagement(_make_config(args, approver=approver))
    except (ScopeError, FileNotFoundError) as e:
        print(red(f"✗ refused to run: {e}"))
        return 2

    print(f"{green('✓')} scope gate passed · target {bold(eng.target_url)} · intel {cyan(eng.intel.name)}")
    print(dim(f"  work dir: {os.path.abspath(eng.cfg.work_dir)}"))
    result = eng.run_scan()

    for entry in result.phase_log:
        print(dim(f"  [{entry['phase']:>11}] ") + entry["msg"])

    if args.repo:
        touched = eng.remediate()
        print(f"{green('✓')} remediation proposed for {len(touched)} validated finding(s) "
              + dim("(advisory patch written; never auto-applied)"))

    formats = [f.strip() for f in (args.report or "html,md,json,sarif").split(",") if f.strip()]
    written, rb, chain_ok = eng.report(formats)
    _print_summary(rb, chain_ok, eng)
    for fmt, path in written.items():
        print(f"  {fmt:>10}: {path}")

    # CI gate
    if getattr(args, "ci", False):
        gate = _ci_gate(rb, args.fail_on)
        if gate:
            print(red(f"✗ CI gate failed: {gate}"))
            return 1
        print(green("✓ CI gate passed"))
    return 0


def _print_summary(rb, chain_ok, eng):
    m = rb.metrics()
    vr = f"{m['finding_validation_rate'] * 100:.0f}%"
    dropped_txt = f"{m['dropped_candidates']} dropped by FP gate"
    print()
    print(bold("  Results"))
    riskc = red if m["risk_band"] in ("Critical", "High") else (yellow if m["risk_band"] == "Medium" else green)
    exploit_txt = f" · {cyan(str(m['demonstrated_exploits']))} demonstrated" if m.get("demonstrated_exploits") else ""
    print(f"   risk {riskc(str(m['risk_score']) + '/100 ' + m['risk_band'])} · "
          f"{cyan(str(m['attack_chains']))} attack chain(s){exploit_txt}")
    print(f"   {green(str(m['confirmed']))} confirmed · {dim(dropped_txt)} · validation rate {bold(vr)}")
    for f in rb.findings:
        if f.state == State.DROPPED:
            print("   " + dim(f"· dropped: {f.title}"))
            continue
        sev = _SEV_C.get(f.severity, dim)(f"[{f.severity.upper()}]")
        mark = green("✔ CONFIRMED") if f.verification.validated else yellow(f"~{f.confidence}")
        print(f"   {sev} {f.title} {mark}")
    ac = green("intact") if chain_ok else red("BROKEN")
    print(dim(f"   audit chain: {ac} · {len(eng.audit.read_all())} events · "
              f"cost ${m['usd_spent']} · {m['tokens_used']} tokens"))
    print()


def _ci_gate(rb, fail_on):
    order = ["info", "low", "medium", "high", "critical"]
    threshold = order.index(fail_on) if fail_on in order else order.index("high")
    bad = [f for f in rb.findings if f.state != State.DROPPED and f.verification.validated
           and order.index(f.severity) >= threshold]
    if bad:
        return f"{len(bad)} validated finding(s) at or above '{fail_on}'"
    return ""


# ------------------------------------------------------------------------- pipeline
def cmd_pipeline(args):
    """The full intense pipeline: scope-gate -> crawl -> map -> every class -> correlate -> report."""
    args.crawl = True
    args.exploit = True
    args._pipeline = True
    print(dim("  pipeline: recon crawl + full class coverage + chains + demonstrated exploitation"))
    return cmd_test(args)


# ------------------------------------------------------------------------- serve
def cmd_serve(args):
    from .server import serve
    _banner()
    print(f"{green('✓')} Rampart dashboard on http://{args.host}:{args.port}  "
          + dim(f"(work-dir {os.path.abspath(args.work_dir)})"))
    print(dim("  press Ctrl-C to stop"))
    try:
        serve(args.host, args.port, args.work_dir)
    except KeyboardInterrupt:
        print("\n  stopped")
    return 0


# ------------------------------------------------------------------------- retest
def cmd_retest(args):
    from .engagement import Engagement
    _banner()
    try:
        eng = Engagement(_make_config(args))
    except (ScopeError, FileNotFoundError) as e:
        print(red(f"✗ {e}"))
        return 2
    results = eng.retest()
    if not results:
        print(yellow("no validated findings to retest (run `rampart test` first)"))
        return 0
    for f, outcome in results:
        col = green if outcome == "Fixed" else (red if outcome == "Regression" else yellow)
        print(f"  {col(outcome)}: {f.title}")
    eng.report([f.strip() for f in (args.report or "html,md").split(",")])
    return 0


# ------------------------------------------------------------------------- report
def cmd_report(args):
    from .engagement import Engagement
    _banner()
    try:
        eng = Engagement(_make_config(args))
    except (ScopeError, FileNotFoundError) as e:
        print(red(f"✗ {e}"))
        return 2
    written, rb, chain_ok = eng.report([f.strip() for f in args.format.split(",")])
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
            extra = dim(f" · {row['version']}") if row["version"] else ""
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
        print(dim("  see reports/DOCKER_AND_EXTERNAL_TOOLS.md to light these up."))
    return 0


# -------------------------------------------------------------------- llm-test
def cmd_llm_test(args):
    from .engagement import Engagement, EngagementConfig
    _banner()
    # The LLM assessment sends gated POSTs (Tier 2); the operator authorizes them by running
    # this command against an in-scope endpoint, so Tier-2 is auto-approved and audited as such.
    approver = lambda req, dec: {"granted": True, "approver_user_id": "cli:llm-test"}
    cfg = EngagementConfig(
        scope_file=args.scope_file, target=args.target, work_dir=args.work_dir,
        application=getattr(args, "application", "llm-target"),
        llm_chat_path=args.chat_path, llm_input_field=args.input_field,
        llm_output_field=args.output_field, llm_canary=args.canary, approver=approver)
    try:
        eng = Engagement(cfg)
    except (ScopeError, FileNotFoundError) as e:
        print(red(f"✗ refused to run: {e}"))
        return 2
    print(f"{green('✓')} scope gate passed · LLM target {bold(eng.target_url)}{eng.cfg.llm_chat_path}")
    res = eng.run_llm()
    print(bold("\n  OWASP LLM Top-10 probes"))
    for p in res.probe_log:
        mark = {"confirmed": green("✔ CONFIRMED"), "not-vulnerable": dim("· held"),
                "blocked": yellow("blocked"), "unconfirmed": yellow("~unconfirmed")}.get(p["result"], p["result"])
        print(f"   {p['owasp']:<42} {mark}")
    written, rb, chain_ok = eng.report([f.strip() for f in (args.report or "html,md,json").split(",")])
    m = rb.metrics()
    print(f"\n  {green(str(m['confirmed']))} confirmed LLM finding(s) · audit chain "
          f"{'intact' if chain_ok else red('BROKEN')}")
    for fmt, path in written.items():
        print(f"  {fmt:>10}: {path}")
    return 0


# -------------------------------------------------------------------- verify-audit
def cmd_verify_audit(args):
    from .audit import AuditLog
    _banner()
    path = os.path.join(args.work_dir, "audit.jsonl")
    if not os.path.exists(path):
        print(red(f"no audit log at {path}"))
        return 2
    log = AuditLog(path)
    ok, msg = log.verify_chain()
    events = log.read_all()
    print((green("✓") if ok else red("✗")) + f" audit chain: {msg} ({len(events)} events)")
    return 0 if ok else 1


# -------------------------------------------------------------------------- parser
def build_parser():
    p = argparse.ArgumentParser(prog="rampart", description="Authorized, self-hosted, evidence-first AppSec agent.")
    p.add_argument("--version", action="version", version=f"rampart {__version__}")
    sub = p.add_subparsers(dest="cmd")

    def add_common(sp, need_target=True):
        sp.add_argument("--scope-file", default="SECURITY.md", help="the SECURITY.md authorization contract")
        sp.add_argument("--target", required=need_target, help="authorized target base URL, e.g. http://127.0.0.1:8080")
        sp.add_argument("--work-dir", default=".rampart", help="run directory (audit, evidence, reports)")

    sp = sub.add_parser("init", help="validate the scope contract")
    sp.add_argument("--scope-file", default="SECURITY.md")

    sp = sub.add_parser("test", help="run an authorized assessment (flagship)")
    add_common(sp, need_target=False)
    sp.add_argument("--config", default="", help="load defaults from a rampart.yaml (CLI flags win)")
    sp.add_argument("--repo", default="", help="repo path for source correlation + advisory patch")
    sp.add_argument("--openapi", default="", help="OpenAPI spec for the app model (grey-box)")
    sp.add_argument("--appmodel-seed", default="", help="seeded object-ownership file")
    sp.add_argument("--secrets", default="", help="secrets file (default: secrets.json next to scope)")
    sp.add_argument("--intel", default="deterministic", help="intelligence provider: deterministic | claude-code")
    sp.add_argument("--application", default="target", help="application name for findings")
    sp.add_argument("--login-path", default="/api/login")
    sp.add_argument("--token-path", default="token")
    sp.add_argument("--report", default="html,md,json,sarif", help="comma list: html,md,json,sarif,compliance")
    sp.add_argument("--scanners", default="", help="external OSS adapters to run: nuclei,nmap,semgrep,trivy,testssl or 'all'")
    sp.add_argument("--crawl", action="store_true", help="discover endpoints/params by crawling (no OpenAPI needed)")
    sp.add_argument("--exploit", action="store_true", help="demonstrate bounded, non-destructive impact for confirmed findings")
    sp.add_argument("--ci", action="store_true", help="nonzero exit if the severity gate is breached")
    sp.add_argument("--fail-on", default="high", help="CI gate severity: low|medium|high|critical")
    sp.add_argument("--approve-tier2", action="store_true", help="auto-approve Tier-2 actions (use with care)")

    sp = sub.add_parser("pipeline", help="the full intense pipeline (crawl + all classes + chains + report)")
    add_common(sp, need_target=False)
    sp.add_argument("--config", default="")
    sp.add_argument("--repo", default="")
    sp.add_argument("--openapi", default="")
    sp.add_argument("--appmodel-seed", default="")
    sp.add_argument("--secrets", default="")
    sp.add_argument("--intel", default="deterministic")
    sp.add_argument("--application", default="target")
    sp.add_argument("--login-path", default="/api/login")
    sp.add_argument("--token-path", default="token")
    sp.add_argument("--report", default="")
    sp.add_argument("--scanners", default="")
    sp.add_argument("--crawl", action="store_true")
    sp.add_argument("--exploit", action="store_true")
    sp.add_argument("--ci", action="store_true")
    sp.add_argument("--fail-on", default="high")
    sp.add_argument("--approve-tier2", action="store_true")

    sp = sub.add_parser("serve", help="serve a local web dashboard over a run work-dir (zero-dep)")
    sp.add_argument("--host", default="127.0.0.1")
    sp.add_argument("--port", type=int, default=8787)
    sp.add_argument("--work-dir", default=".rampart")

    sp = sub.add_parser("scan", help="alias for test")
    add_common(sp, need_target=False)
    sp.add_argument("--config", default="")
    for a in ("--repo", "--openapi", "--appmodel-seed", "--secrets"):
        sp.add_argument(a, default="")
    sp.add_argument("--intel", default="deterministic")
    sp.add_argument("--application", default="target")
    sp.add_argument("--login-path", default="/api/login")
    sp.add_argument("--token-path", default="token")
    sp.add_argument("--report", default="html,md,json,sarif")
    sp.add_argument("--scanners", default="")
    sp.add_argument("--crawl", action="store_true")
    sp.add_argument("--exploit", action="store_true")
    sp.add_argument("--ci", action="store_true")
    sp.add_argument("--fail-on", default="high")
    sp.add_argument("--approve-tier2", action="store_true")

    sp = sub.add_parser("retest", help="replay validated findings against the (patched) target")
    add_common(sp)
    sp.add_argument("--secrets", default="")
    sp.add_argument("--openapi", default="")
    sp.add_argument("--appmodel-seed", default="")
    sp.add_argument("--intel", default="deterministic")
    sp.add_argument("--application", default="target")
    sp.add_argument("--login-path", default="/api/login")
    sp.add_argument("--token-path", default="token")
    sp.add_argument("--report", default="html,md")

    sp = sub.add_parser("report", help="regenerate reports from a stored run")
    add_common(sp)
    sp.add_argument("--secrets", default="")
    sp.add_argument("--openapi", default="")
    sp.add_argument("--appmodel-seed", default="")
    sp.add_argument("--application", default="target")
    sp.add_argument("--format", default="html", help="comma list: html,md,json,sarif,compliance")

    sp = sub.add_parser("verify-audit", help="verify the append-only audit hash chain")
    sp.add_argument("--work-dir", default=".rampart")

    sub.add_parser("tools", help="show which external OSS scanners are installed (doctor)")

    sub.add_parser("mcp", help="run the MCP stdio server (scope-guarded tools for Claude Code / agents)")

    sp = sub.add_parser("llm-test", help="assess an LLM endpoint against the OWASP LLM Top 10")
    sp.add_argument("--scope-file", default="SECURITY.md")
    sp.add_argument("--target", required=True, help="authorized LLM endpoint base URL")
    sp.add_argument("--work-dir", default=".rampart")
    sp.add_argument("--chat-path", default="/chat", help="path that accepts the prompt")
    sp.add_argument("--input-field", default="message", help="JSON field holding the user prompt")
    sp.add_argument("--output-field", default="reply", help="dotted JSON path to the model reply")
    sp.add_argument("--canary", default="", help="secret planted in the system prompt (leak oracle)")
    sp.add_argument("--application", default="llm-target")
    sp.add_argument("--report", default="html,md,json")
    return p


def _force_utf8():
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:  # noqa: BLE001 - older/odd streams; fall back silently
            pass


def main(argv=None):
    _force_utf8()
    args = build_parser().parse_args(argv)
    if args.cmd in ("test", "scan"):
        return cmd_test(args)
    if args.cmd == "pipeline":
        return cmd_pipeline(args)
    if args.cmd == "serve":
        return cmd_serve(args)
    if args.cmd == "init":
        return cmd_init(args)
    if args.cmd == "retest":
        return cmd_retest(args)
    if args.cmd == "report":
        return cmd_report(args)
    if args.cmd == "verify-audit":
        return cmd_verify_audit(args)
    if args.cmd == "tools":
        return cmd_tools(args)
    if args.cmd == "mcp":
        import sys as _sys
        from .mcp import serve_stdio
        return serve_stdio(_sys.stdin, _sys.stdout) or 0
    if args.cmd == "llm-test":
        return cmd_llm_test(args)
    build_parser().print_help()
    return 0
