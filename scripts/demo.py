"""One-command demo: start the owned target, run a full assessment, open the report.

    python scripts/demo.py                # vulnerable target -> confirmed findings
    python scripts/demo.py --fixed        # patched target   -> FP gate drops everything
    python scripts/demo.py --intel claude-code   # use Claude Code for the reasoning layer
    python scripts/demo.py --no-open      # don't open the HTML report in a browser

Everything runs on localhost against a target we ship and own. Nothing touches the internet.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
import time
import urllib.request
import webbrowser

HERE = os.path.dirname(__file__)
PLATFORM = os.path.abspath(os.path.join(HERE, ".."))
DEMO = os.path.join(PLATFORM, "examples", "demo_target", "vulnerable_app.py")
LLM_DEMO = os.path.join(PLATFORM, "examples", "demo_target", "vulnerable_llm.py")
DEMO_DIR = os.path.join(PLATFORM, "examples", "demo_target")
sys.path.insert(0, PLATFORM)

from rampart.engagement import Engagement, EngagementConfig  # noqa: E402

_LLM_CANARY = "SK-DEMO-CANARY-9f3a2b17"  # matches examples/demo_target/vulnerable_llm.py


def _start_proc(script, fixed, fixed_flag="--fixed"):
    cmd = [sys.executable, script, "--port", "0", "--host", "127.0.0.1"]
    if fixed:
        cmd.append(fixed_flag)
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    line = proc.stdout.readline()
    m = re.search(r":(\d+)", line)
    if not m:
        raise SystemExit(f"demo target failed to start: {line!r}")
    port = int(m.group(1))
    for _ in range(50):
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=1)
            break
        except Exception:  # noqa: BLE001
            time.sleep(0.1)
    return proc, port


def _llm_scope(port):
    import tempfile

    tmp = tempfile.mkdtemp(prefix="rampart-llm-demo-")
    scope = f"""apiVersion: security-agent/v1
kind: EngagementScope
authorization: {{owner: you@localhost, authorized_by: you@localhost, ticket: LLM-DEMO,
  attestation: "I own this local LLM target.", expires: "2099-12-31T23:59:59Z"}}
scope:
  in_scope:
    - host: "127.0.0.1"
      ports: [{port}]
      paths_include: ["/chat", "/"]
      methods: ["GET", "POST"]
  out_of_scope: {{paths_exclude: [], hosts_exclude: []}}
  resolved_ip_allowlist: ["127.0.0.1/32"]
limits: {{max_requests_per_host_per_min: 500, max_total_requests: 5000}}
action_policy: {{default_tier_ceiling: 1, tier2_requires_approval: true, tier3: deny}}
test_accounts: []
notify: {{}}
"""
    path = os.path.join(tmp, "rampart.scope.yaml")
    open(path, "w", encoding="utf-8").write(scope)
    open(os.path.join(tmp, "secrets.json"), "w", encoding="utf-8").write("{}")
    return path


def run_llm_demo(fixed, no_open):
    proc, port = _start_proc(LLM_DEMO, fixed)
    print(f"  demo LLM up on http://127.0.0.1:{port}/chat  [{'GUARDRAILED' if fixed else 'VULNERABLE'}]")
    work_dir = os.path.join(PLATFORM, ".rampart-llm-demo")
    import shutil

    shutil.rmtree(work_dir, ignore_errors=True)
    try:
        cfg = EngagementConfig(
            scope_file=_llm_scope(port),
            target=f"http://127.0.0.1:{port}",
            work_dir=work_dir,
            application="demo-llm",
            llm_chat_path="/chat",
            llm_canary=_LLM_CANARY,
            approver=lambda req, dec: {"granted": True, "approver_user_id": "demo"},
        )
        eng = Engagement(cfg)
        res = eng.run_llm()
        written, rb, chain_ok = eng.report(["html", "md", "json"])
        print("\n  OWASP LLM Top-10:")
        for p in res.probe_log:
            print(f"    {p['owasp']:<42} {p['result']}")
        m = rb.metrics()
        print(
            f"\n  {m['confirmed']} confirmed LLM finding(s) · audit chain "
            f"{'intact' if chain_ok else 'BROKEN'} · {len(eng.audit.read_all())} events"
        )
        html = written.get("html")
        print(f"\n  report: {html}\n")
        if html and not no_open:
            webbrowser.open("file://" + os.path.abspath(html))
    finally:
        proc.terminate()


def _start_target(fixed):
    cmd = [sys.executable, DEMO, "--port", "0", "--host", "127.0.0.1"]
    if fixed:
        cmd.append("--fixed")
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    line = proc.stdout.readline()
    m = re.search(r":(\d+)", line)
    if not m:
        raise SystemExit(f"demo target failed to start: {line!r}")
    port = int(m.group(1))
    for _ in range(50):
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=1)
            break
        except Exception:  # noqa: BLE001
            time.sleep(0.1)
    print(f"  demo target up on http://127.0.0.1:{port}  [{'FIXED' if fixed else 'VULNERABLE'}]")
    return proc, port


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--fixed", action="store_true", help="run the patched target (proves the FP gate)")
    ap.add_argument("--intel", default="deterministic", help="deterministic | claude-code | openai-compat")
    ap.add_argument("--llm", action="store_true", help="run the LLM (OWASP LLM Top-10) demo instead")
    ap.add_argument("--no-open", action="store_true")
    args = ap.parse_args()

    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:  # noqa: BLE001
        pass

    print("\n  Rampart demo — authorized, self-hosted, evidence-first AppSec\n")
    if args.llm:
        return run_llm_demo(args.fixed, args.no_open)
    proc, port = _start_target(args.fixed)
    work_dir = os.path.join(PLATFORM, ".rampart-demo")
    import shutil

    shutil.rmtree(work_dir, ignore_errors=True)  # fresh run for clean, single-engagement numbers
    try:
        # write a scope contract for the ephemeral port
        import tempfile

        tmp = tempfile.mkdtemp(prefix="rampart-demo-")
        scope = open(os.path.join(DEMO_DIR, "rampart.scope.yaml"), encoding="utf-8").read()
        scope = re.sub(r"ports:\s*\[\d+\]", f"ports: [{port}]", scope)
        scope_path = os.path.join(tmp, "rampart.scope.yaml")
        open(scope_path, "w", encoding="utf-8").write(scope)

        cfg = EngagementConfig(
            scope_file=scope_path,
            target=f"http://127.0.0.1:{port}",
            work_dir=work_dir,
            secrets_file=os.path.join(DEMO_DIR, "secrets.json"),
            openapi=os.path.join(DEMO_DIR, "openapi.json"),
            appmodel_seed=os.path.join(DEMO_DIR, "appmodel_seed.json"),
            application="demo-shop-api",
            intel=args.intel,
            repo=(DEMO_DIR if not args.fixed else ""),
        )
        eng = Engagement(cfg)
        eng.run_scan()
        if not args.fixed:
            eng.remediate()
        written, rb, chain_ok = eng.report(["html", "md", "json", "sarif", "compliance"])

        m = rb.metrics()
        print(f"\n  risk {m['risk_score']}/100 ({m['risk_band']}) · {m['attack_chains']} attack chain(s)")
        print(
            f"  {m['confirmed']} confirmed · {m['dropped_candidates']} dropped by FP gate "
            f"· validation rate {m['finding_validation_rate'] * 100:.0f}%"
        )
        for f in rb.findings:
            state = "CONFIRMED" if f.verification.validated else f.state
            print(f"    [{f.severity.upper():>6}] {f.title}  ({state})")
        print(
            f"\n  audit chain: {'intact' if chain_ok else 'BROKEN'} · "
            f"{len(eng.audit.read_all())} events · cost ${m['usd_spent']}"
        )
        html = written.get("html")
        print(f"\n  report: {html}\n")
        if html and not args.no_open:
            webbrowser.open("file://" + os.path.abspath(html))
    finally:
        proc.terminate()


if __name__ == "__main__":
    raise SystemExit(main())
