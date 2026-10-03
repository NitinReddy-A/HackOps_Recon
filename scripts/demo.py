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
DEMO_DIR = os.path.join(PLATFORM, "examples", "demo_target")
sys.path.insert(0, PLATFORM)

from rampart.engagement import Engagement, EngagementConfig  # noqa: E402


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
    ap.add_argument("--no-open", action="store_true")
    args = ap.parse_args()

    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:  # noqa: BLE001
        pass

    print("\n  Rampart demo — authorized, self-hosted, evidence-first AppSec\n")
    proc, port = _start_target(args.fixed)
    work_dir = os.path.join(PLATFORM, ".rampart-demo")
    import shutil
    shutil.rmtree(work_dir, ignore_errors=True)   # fresh run for clean, single-engagement numbers
    try:
        # write a scope contract for the ephemeral port
        import tempfile
        tmp = tempfile.mkdtemp(prefix="rampart-demo-")
        scope = open(os.path.join(DEMO_DIR, "SECURITY.md"), encoding="utf-8").read()
        scope = re.sub(r"ports:\s*\[\d+\]", f"ports: [{port}]", scope)
        scope_path = os.path.join(tmp, "SECURITY.md")
        open(scope_path, "w", encoding="utf-8").write(scope)

        cfg = EngagementConfig(
            scope_file=scope_path, target=f"http://127.0.0.1:{port}", work_dir=work_dir,
            secrets_file=os.path.join(DEMO_DIR, "secrets.json"),
            openapi=os.path.join(DEMO_DIR, "openapi.json"),
            appmodel_seed=os.path.join(DEMO_DIR, "appmodel_seed.json"),
            application="demo-shop-api", intel=args.intel,
            repo=(DEMO_DIR if not args.fixed else ""),
        )
        eng = Engagement(cfg)
        result = eng.run_scan()
        if not args.fixed:
            eng.remediate()
        written, rb, chain_ok = eng.report(["html", "md", "json", "sarif", "compliance"])

        m = rb.metrics()
        print(f"\n  {m['confirmed']} confirmed · {m['dropped_candidates']} dropped by FP gate "
              f"· validation rate {m['finding_validation_rate']*100:.0f}%")
        for f in rb.findings:
            state = "CONFIRMED" if f.verification.validated else f.state
            print(f"    [{f.severity.upper():>6}] {f.title}  ({state})")
        print(f"\n  audit chain: {'intact' if chain_ok else 'BROKEN'} · "
              f"{len(eng.audit.read_all())} events · cost ${m['usd_spent']}")
        html = written.get("html")
        print(f"\n  report: {html}\n")
        if html and not args.no_open:
            webbrowser.open("file://" + os.path.abspath(html))
    finally:
        proc.terminate()


if __name__ == "__main__":
    raise SystemExit(main())
