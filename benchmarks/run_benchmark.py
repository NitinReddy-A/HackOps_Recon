"""Reliability benchmark harness (blueprint section 25).

Spins up the intentionally-vulnerable demo target in an isolated, offline loopback network
in both VULNERABLE and FIXED modes (a VAmPI-style on/off switch giving clean FP/FN
measurement), runs a full Rampart engagement against each, and scores the *confirmed*
findings against known ground truth. Prints precision / recall / F1, finding-validation
rate, mean-time-to-first-finding, and cost — and writes ``benchmarks/results.json``.

Usage:
    python benchmarks/run_benchmark.py [--runs 1] [--intel deterministic]

Everything runs against a throwaway target we own; there is no route to any real asset.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import urllib.request

HERE = os.path.dirname(__file__)
PLATFORM = os.path.abspath(os.path.join(HERE, ".."))
DEMO = os.path.join(PLATFORM, "examples", "demo_target", "vulnerable_app.py")
DEMO_DIR = os.path.join(PLATFORM, "examples", "demo_target")
sys.path.insert(0, PLATFORM)

from rampart.engagement import Engagement, EngagementConfig  # noqa: E402

# ground truth: (vuln_class, endpoint-path-key) that SHOULD be confirmed per mode
GROUND_TRUTH = {
    "vulnerable": {
        ("IDOR/BOLA", "/api/orders/"),
        ("XSS", "/api/search"),
        ("SQLI", "/api/products"),
        ("OPEN_REDIRECT", "/api/go"),
        ("SSRF", "/api/fetch"),
        ("CMDI", "/api/ping"),
        ("PATH_TRAVERSAL", "/api/file"),
        ("BFLA", "/api/reports/orders"),
        ("EXCESSIVE_DATA", "/api/profile"),
        ("SSTI", "/api/greet"),
        ("XSS", "/api/greet"),
        ("JWT", "/api/me"),
        ("HOST_HEADER_INJECTION", "/api/reset"),
        ("sensitive-file-exposure", "/"),
        ("security-misconfiguration", "/"),
    },
    "fixed": set(),
}

_PATH_KEYS = (
    "/api/reports/orders",
    "/api/orders/",
    "/api/search",
    "/api/products",
    "/api/go",
    "/api/fetch",
    "/api/ping",
    "/api/file",
    "/api/profile",
    "/api/greet",
    "/api/me",
    "/api/reset",
)


def _pathkey(url: str) -> str:
    for key in _PATH_KEYS:
        if key in url:
            return key
    return "/"


SCOPE_TMPL = """apiVersion: security-agent/v1
kind: EngagementScope
authorization: {{owner: bench, authorized_by: bench, ticket: BENCH, attestation: ok, expires: "2099-01-01T00:00:00Z"}}
scope:
  in_scope:
    - host: "127.0.0.1"
      ports: [{port}]
      paths_include: ["/**"]
      methods: ["GET", "POST"]
  out_of_scope: {{paths_exclude: [], hosts_exclude: []}}
  resolved_ip_allowlist: ["127.0.0.1/32"]
limits: {{max_requests_per_host_per_min: 1000, max_total_requests: 10000}}
action_policy: {{default_tier_ceiling: 1, tier2_requires_approval: true, tier3: deny}}
test_accounts:
  - {{id: user_a, role: customer, secret_ref: "vault://demo/user_a"}}
  - {{id: user_b, role: customer, secret_ref: "vault://demo/user_b"}}
notify: {{on_start: [bench]}}
"""


def _start_target(fixed: bool):
    cmd = [sys.executable, DEMO, "--port", "0", "--host", "127.0.0.1"]
    if fixed:
        cmd.append("--fixed")
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    line = proc.stdout.readline()
    port = int(re.search(r":(\d+)", line).group(1))
    for _ in range(50):
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=1)
            break
        except Exception:  # noqa: BLE001
            time.sleep(0.1)
    return proc, port


def _confirmed_set(findings):
    out = set()
    for f in findings:
        if not f.verification.validated or "external-scanner" in f.tags:
            continue
        out.add((f.vuln_class, _pathkey(f.endpoint.get("url", ""))))
    return out


def _run_once(mode, intel):
    fixed = mode == "fixed"
    proc, port = _start_target(fixed)
    tmp = tempfile.mkdtemp(prefix=f"bench-{mode}-")
    try:
        scope_path = os.path.join(tmp, "rampart.scope.yaml")
        with open(scope_path, "w", encoding="utf-8") as fh:
            fh.write(SCOPE_TMPL.format(port=port))
        cfg = EngagementConfig(
            scope_file=scope_path,
            target=f"http://127.0.0.1:{port}",
            work_dir=os.path.join(tmp, ".rampart"),
            secrets_file=os.path.join(DEMO_DIR, "secrets.json"),
            openapi=os.path.join(DEMO_DIR, "openapi.json"),
            appmodel_seed=os.path.join(DEMO_DIR, "appmodel_seed.json"),
            application="demo-shop-api",
            intel=intel,
        )
        t0 = time.monotonic()
        eng = Engagement(cfg)
        result = eng.run_scan()
        elapsed = time.monotonic() - t0
        confirmed = _confirmed_set(result.findings)
        expected = GROUND_TRUTH[mode]
        tp = len(confirmed & expected)
        fp = len(confirmed - expected)
        fn = len(expected - confirmed)
        return {
            "mode": mode,
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "confirmed": sorted(f"{a}@{b}" for a, b in confirmed),
            "expected": sorted(f"{a}@{b}" for a, b in expected),
            "elapsed_s": round(elapsed, 3),
            "cost_usd": eng.budget.snapshot()["usd_spent"],
            "tokens": eng.budget.snapshot()["tokens_used"],
        }
    finally:
        proc.terminate()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", type=int, default=1)
    ap.add_argument("--intel", default="deterministic")
    args = ap.parse_args()

    runs = []
    for _ in range(args.runs):
        for mode in ("vulnerable", "fixed"):
            runs.append(_run_once(mode, args.intel))

    tp = sum(r["tp"] for r in runs)
    fp = sum(r["fp"] for r in runs)
    fn = sum(r["fn"] for r in runs)
    precision = tp / (tp + fp) if (tp + fp) else 1.0
    recall = tp / (tp + fn) if (tp + fn) else 1.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    mttf = round(sum(r["elapsed_s"] for r in runs) / len(runs), 3)

    summary = {
        "intel": args.intel,
        "runs": args.runs,
        "true_positives": tp,
        "false_positives": fp,
        "false_negatives": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "mean_time_to_finding_s": mttf,
        "total_cost_usd": round(sum(r["cost_usd"] for r in runs), 4),
        "per_run": runs,
    }
    with open(os.path.join(HERE, "results.json"), "w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=2)

    print("=" * 60)
    print(f"  RAMPART BENCHMARK  (intel={args.intel}, runs={args.runs})")
    print("=" * 60)
    print(f"  Precision : {precision * 100:5.1f}%   (FP={fp})")
    print(f"  Recall    : {recall * 100:5.1f}%   (FN={fn})")
    print(f"  F1        : {f1 * 100:5.1f}%")
    print(f"  TP/FP/FN  : {tp}/{fp}/{fn}")
    print(f"  MTT-find  : {mttf}s   cost=${summary['total_cost_usd']}")
    print("-" * 60)
    for r in runs:
        verdict = "OK" if (r["fp"] == 0 and r["fn"] == 0) else "MISS"
        print(f"  [{verdict:>4}] {r['mode']:<10} confirmed={r['confirmed']}")
    print("=" * 60)
    return 0 if (fp == 0 and fn == 0) else 1


if __name__ == "__main__":
    raise SystemExit(main())
