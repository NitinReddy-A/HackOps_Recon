"""Score Rampart against ANY vulnerable-app fixture (not just the built-in demo).

Generalises `run_benchmark.py`: point it at a running fixture (crAPI / VAmPI / Juice Shop / your
own app) with a ground-truth file of expected (vuln_class, path-key) pairs, and it runs an
assessment and reports precision / recall / F1. Designed to run in CI against a Dockerised
fixture (see .github/workflows/corpus.yml) so coverage is measured, not asserted.

    python benchmarks/corpus_runner.py --target http://127.0.0.1:5000 \
        --scope-file vampi-SECURITY.md --ground-truth vampi-ground-truth.json [--active --crawl]

ground-truth.json: {"path_keys": ["/users/v1", ...], "expected": [["BOLA","/users/v1"], ...]}
"""
from __future__ import annotations

import argparse
import json
import os
import sys

HERE = os.path.dirname(__file__)
sys.path.insert(0, os.path.abspath(os.path.join(HERE, "..")))


def path_key(url: str, keys) -> str:
    for k in keys:
        if k in (url or ""):
            return k
    return "/"


def score(findings, expected, path_keys) -> dict:
    """Pure scorer: compare oracle-confirmed findings to the ground-truth set."""
    confirmed = {(f.vuln_class, path_key(f.endpoint.get("url", ""), path_keys))
                 for f in findings
                 if getattr(f.verification, "validated", False) and "external-scanner" not in f.tags}
    expected_set = {tuple(x) for x in expected}
    tp = len(confirmed & expected_set)
    fp = len(confirmed - expected_set)
    fn = len(expected_set - confirmed)
    precision = tp / (tp + fp) if (tp + fp) else 1.0
    recall = tp / (tp + fn) if (tp + fn) else 1.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    return {"tp": tp, "fp": fp, "fn": fn, "precision": round(precision, 4),
            "recall": round(recall, 4), "f1": round(f1, 4),
            "confirmed": sorted(f"{a}@{b}" for a, b in confirmed),
            "missed": sorted(f"{a}@{b}" for a, b in (expected_set - confirmed)),
            "unexpected": sorted(f"{a}@{b}" for a, b in (confirmed - expected_set))}


def run_and_score(target, scope_file, gt, work_dir=".rampart-corpus", **flags) -> dict:
    from rampart.engagement import Engagement, EngagementConfig
    approver = (lambda req, dec: {"granted": True, "approver_user_id": "corpus"}) if flags.get("active") else None
    cfg = EngagementConfig(scope_file=scope_file, target=target, work_dir=work_dir,
                           secrets_file=flags.get("secrets", ""), openapi=flags.get("openapi", ""),
                           appmodel_seed=flags.get("appmodel_seed", ""), application=flags.get("application", "corpus"),
                           crawl=flags.get("crawl", False), active=flags.get("active", False), approver=approver)
    result = Engagement(cfg).run_scan()
    return score(result.findings, gt.get("expected", []), gt.get("path_keys", []))


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", required=True)
    ap.add_argument("--scope-file", required=True)
    ap.add_argument("--ground-truth", required=True)
    ap.add_argument("--secrets", default="")
    ap.add_argument("--openapi", default="")
    ap.add_argument("--appmodel-seed", default="")
    ap.add_argument("--application", default="corpus")
    ap.add_argument("--work-dir", default=".rampart-corpus")
    ap.add_argument("--crawl", action="store_true")
    ap.add_argument("--active", action="store_true")
    ap.add_argument("--min-recall", type=float, default=0.0, help="exit non-zero if recall is below this")
    args = ap.parse_args(argv)
    with open(args.ground_truth, encoding="utf-8") as fh:
        gt = json.load(fh)
    r = run_and_score(args.target, args.scope_file, gt, work_dir=args.work_dir, secrets=args.secrets,
                      openapi=args.openapi, appmodel_seed=args.appmodel_seed, application=args.application,
                      crawl=args.crawl, active=args.active)
    print(json.dumps(r, indent=2))
    return 1 if r["recall"] < args.min_recall else 0


if __name__ == "__main__":
    raise SystemExit(main())
