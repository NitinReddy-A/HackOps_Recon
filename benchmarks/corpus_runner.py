"""Score Rampart against ANY vulnerable-app fixture (not just the built-in demo) — the external,
multi-app benchmark *program*, as opposed to the single self-fixture regression in
``run_benchmark.py``.

Point it at a running fixture (crAPI / VAmPI / Juice Shop / your own app) with a ground-truth file
of expected ``(vuln_class, path-key)`` pairs. It runs the assessment ``--runs`` times and reports,
honestly:

* **per-class and overall** precision / recall / F1 (not just an overall threshold);
* a **coverage manifest** — for every expected class, whether it was ``tested`` and
  ``confirmed`` / ``missed`` (a real false negative) or ``not-tested`` (a coverage gap: the engine
  never even tried it). *"No findings" must never be read as "fully tested"*, so a class the engine
  did not exercise is reported as ``not-tested``, not silently as a pass;
* **variance across runs** and whether the confirmed set was **deterministic**;
* **inconclusive / error** signals — whether any run was incomplete (target unreachable / all
  blocked), plus the dropped-by-FP-gate and agent-assessed counts.

    python benchmarks/corpus_runner.py --target http://127.0.0.1:5000 \
        --scope-file benchmarks/fixtures/vampi-rampart.scope.yaml \
        --ground-truth benchmarks/fixtures/vampi-ground-truth.json --crawl --runs 5 --min-recall 0.5

ground-truth.json: {"path_keys": ["/users/v1", ...], "expected": [["IDOR/BOLA","/users/v1"], ...]}
Designed to run against a Dockerised fixture (see .github/workflows/corpus.yml) so coverage is
*measured*, not asserted. The pure scorers below are unit-tested in tests/test_corpus.py.
"""

from __future__ import annotations

import argparse
import json
import os
import statistics
import sys

HERE = os.path.dirname(__file__)
sys.path.insert(0, os.path.abspath(os.path.join(HERE, "..")))


def path_key(url: str, keys) -> str:
    for k in keys:
        if k in (url or ""):
            return k
    return "/"


def _rate(num: int, denom_tp: int, denom_other: int) -> float:
    d = denom_tp + denom_other
    return round(denom_tp / d, 4) if d else 1.0


def score(findings, expected, path_keys) -> dict:
    """Pure scorer: compare oracle-confirmed findings to the ground truth, overall and per class."""
    confirmed = {
        (f.vuln_class, path_key(f.endpoint.get("url", ""), path_keys))
        for f in findings
        if getattr(f.verification, "validated", False) and "external-scanner" not in f.tags
    }
    expected_set = {tuple(x) for x in expected}
    tp = len(confirmed & expected_set)
    fp = len(confirmed - expected_set)
    fn = len(expected_set - confirmed)
    precision = _rate(tp, tp, fp)
    recall = _rate(tp, tp, fn)
    f1 = round(2 * precision * recall / (precision + recall), 4) if (precision + recall) else 0.0

    per_class: dict[str, dict] = {}
    for cls in sorted({c for c, _ in expected_set} | {c for c, _ in confirmed}):
        c_conf = {pk for c, pk in confirmed if c == cls}
        c_exp = {pk for c, pk in expected_set if c == cls}
        ctp, cfp, cfn = len(c_conf & c_exp), len(c_conf - c_exp), len(c_exp - c_conf)
        per_class[cls] = {
            "tp": ctp,
            "fp": cfp,
            "fn": cfn,
            "precision": _rate(ctp, ctp, cfp),
            "recall": _rate(ctp, ctp, cfn),
        }

    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "per_class": per_class,
        "confirmed": sorted(f"{a}@{b}" for a, b in confirmed),
        "missed": sorted(f"{a}@{b}" for a, b in (expected_set - confirmed)),
        "unexpected": sorted(f"{a}@{b}" for a, b in (confirmed - expected_set)),
    }


def coverage_manifest(scan_result, expected) -> dict:
    """Honest coverage: for every expected class, say whether the engine actually tested it.

    A class that was never exercised is ``not-tested`` (a coverage gap), NOT a silent pass — so a
    clean run cannot be mistaken for full coverage. ``tested`` is derived from the scan's
    ``classes_tested`` (a hypothesis was investigated for that class).
    """
    tested = set(getattr(scan_result, "classes_tested", []) or [])
    confirmed_classes = {
        f.vuln_class
        for f in getattr(scan_result, "findings", [])
        if getattr(f.verification, "validated", False)
    }
    expected_classes = sorted({c for c, _ in (tuple(x) for x in expected)})
    rows = {}
    for cls in expected_classes:
        if cls not in tested:
            rows[cls] = "not-tested"  # coverage gap — the engine never tried this class
        elif cls in confirmed_classes:
            rows[cls] = "tested+confirmed"
        else:
            rows[cls] = "tested+missed"  # a real false negative (it was exercised and not proven)
    return {
        "classes_expected": expected_classes,
        "classes_tested_by_engine": sorted(tested),
        "expected_coverage": rows,
        "not_tested": [c for c, v in rows.items() if v == "not-tested"],
        "note": "'not-tested' is a coverage gap, not a pass: no findings for a class never implies it was fully tested.",
    }


def _run_signals(scan_result) -> dict:
    findings = getattr(scan_result, "findings", []) or []
    return {
        "complete": bool(getattr(scan_result, "complete", True)),
        "incomplete_reason": getattr(scan_result, "incomplete_reason", "") or "",
        "dropped_by_fp_gate": sum(
            1 for f in findings if getattr(f, "state", None) and str(f.state).endswith("DROPPED")
        ),
        "agent_assessed": sum(1 for f in findings if "agent-assessed" in getattr(f, "tags", [])),
        "endpoints_tested": int(getattr(scan_result, "endpoints_tested", 0) or 0),
    }


def _one_run(target, scope_file, gt, work_dir, flags) -> tuple[dict, dict, dict]:
    from rampart.engagement import Engagement, EngagementConfig

    approver = (
        (lambda req, dec: {"granted": True, "approver_user_id": "corpus"}) if flags.get("active") else None
    )
    cfg = EngagementConfig(
        scope_file=scope_file,
        target=target,
        work_dir=work_dir,
        secrets_file=flags.get("secrets", ""),
        openapi=flags.get("openapi", ""),
        appmodel_seed=flags.get("appmodel_seed", ""),
        application=flags.get("application", "corpus"),
        crawl=flags.get("crawl", False),
        active=flags.get("active", False),
        deep=flags.get("deep", False),
        approver=approver,
    )
    result = Engagement(cfg).run_scan()
    sc = score(result.findings, gt.get("expected", []), gt.get("path_keys", []))
    return sc, coverage_manifest(result, gt.get("expected", [])), _run_signals(result)


def aggregate(runs: list[dict]) -> dict:
    """Mean / stdev of precision/recall/F1 across runs, and whether the confirmed set was stable."""
    if not runs:
        return {}
    recalls = [r["recall"] for r in runs]
    precisions = [r["precision"] for r in runs]
    f1s = [r["f1"] for r in runs]
    confirmed_sets = {tuple(r["confirmed"]) for r in runs}

    def ms(xs):
        return {"mean": round(statistics.mean(xs), 4), "stdev": round(statistics.pstdev(xs), 4)}

    return {
        "runs": len(runs),
        "precision": ms(precisions),
        "recall": ms(recalls),
        "f1": ms(f1s),
        "deterministic": len(confirmed_sets) == 1,
        "min_recall": min(recalls),
    }


def run_and_score(target, scope_file, gt, work_dir=".rampart-corpus", runs=1, **flags) -> dict:
    per_run = []
    manifest = {}
    signals = []
    for i in range(max(1, int(runs))):
        sc, manifest, sig = _one_run(target, scope_file, gt, f"{work_dir}/run{i}", flags)
        per_run.append(sc)
        signals.append(sig)
    return {
        "application": flags.get("application", "corpus"),
        "aggregate": aggregate(per_run),
        "per_run": per_run,
        "coverage_manifest": manifest,
        "signals": signals,
    }


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
    ap.add_argument("--deep", action="store_true")
    ap.add_argument("--runs", type=int, default=1, help="repeat the assessment N times for variance")
    ap.add_argument("--out", default="", help="write the full JSON report to this path")
    ap.add_argument(
        "--min-recall", type=float, default=0.0, help="exit non-zero if mean recall is below this"
    )
    args = ap.parse_args(argv)
    with open(args.ground_truth, encoding="utf-8") as fh:
        gt = json.load(fh)
    report = run_and_score(
        args.target,
        args.scope_file,
        gt,
        work_dir=args.work_dir,
        runs=args.runs,
        secrets=args.secrets,
        openapi=args.openapi,
        appmodel_seed=args.appmodel_seed,
        application=args.application,
        crawl=args.crawl,
        active=args.active,
        deep=args.deep,
    )
    out = json.dumps(report, indent=2)
    print(out)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(out)
    if report["coverage_manifest"].get("not_tested"):
        print(
            "WARNING: classes never exercised (coverage gap): "
            + ", ".join(report["coverage_manifest"]["not_tested"]),
            file=sys.stderr,
        )
    return 1 if report["aggregate"].get("recall", {}).get("mean", 0.0) < args.min_recall else 0


if __name__ == "__main__":
    raise SystemExit(main())
