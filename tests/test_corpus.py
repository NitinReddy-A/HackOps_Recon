"""Corpus scorer — the reusable precision/recall scoring used for external fixtures."""

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "benchmarks")))
from corpus_runner import path_key, score  # noqa: E402

from rampart.schemas.finding import Finding, State, Verification  # noqa: E402


def _confirmed(vuln_class, url):
    return Finding(
        engagement_id="e",
        title=vuln_class,
        vuln_class=vuln_class,
        severity="high",
        confidence="confirmed",
        state=State.VALIDATED,
        endpoint={"url": url},
        verification=Verification(method="m", validated=True, validator="v"),
    )


def test_path_key_matches_substring():
    assert path_key("http://h/api/search?q=1", ["/api/search", "/api/go"]) == "/api/search"
    assert path_key("http://h/other", ["/api/search"]) == "/"


def test_score_perfect():
    r = score([_confirmed("XSS", "http://h/api/search")], [["XSS", "/api/search"]], ["/api/search"])
    assert r["tp"] == 1 and r["fp"] == 0 and r["fn"] == 0
    assert r["precision"] == 1.0 and r["recall"] == 1.0 and r["f1"] == 1.0


def test_score_counts_missed_and_unexpected():
    findings = [_confirmed("XSS", "http://h/api/search"), _confirmed("SSRF", "http://h/api/fetch")]
    expected = [["XSS", "/api/search"], ["SQLI", "/api/products"]]
    keys = ["/api/search", "/api/products", "/api/fetch"]
    r = score(findings, expected, keys)
    assert r["tp"] == 1 and r["fn"] == 1 and r["fp"] == 1
    assert "SQLI@/api/products" in r["missed"]
    assert "SSRF@/api/fetch" in r["unexpected"]


def test_score_ignores_external_and_unvalidated():
    f_ext = _confirmed("XSS", "http://h/api/search")
    f_ext.tags = ["external-scanner"]
    f_unval = Finding(
        engagement_id="e",
        title="x",
        vuln_class="XSS",
        endpoint={"url": "http://h/api/search"},
        verification=Verification(validated=False),
    )
    r = score([f_ext, f_unval], [["XSS", "/api/search"]], ["/api/search"])
    assert r["tp"] == 0 and r["fn"] == 1  # only oracle-confirmed, non-external findings count


# ---- enhanced benchmark program: per-class metrics, coverage manifest, variance ----
from types import SimpleNamespace  # noqa: E402

from corpus_runner import aggregate, coverage_manifest  # noqa: E402


def test_score_breaks_down_per_class():
    findings = [
        _confirmed("XSS", "http://h/api/search"),
        _confirmed("SQLI", "http://h/api/products"),
    ]
    expected = [["XSS", "/api/search"], ["SQLI", "/api/products"], ["SQLI", "/api/users"]]
    keys = ["/api/search", "/api/products", "/api/users"]
    pc = score(findings, expected, keys)["per_class"]
    assert pc["XSS"]["tp"] == 1 and pc["XSS"]["recall"] == 1.0
    # SQLI: one of two expected confirmed -> recall 0.5
    assert pc["SQLI"]["tp"] == 1 and pc["SQLI"]["fn"] == 1 and pc["SQLI"]["recall"] == 0.5


def test_coverage_manifest_flags_untested_classes():
    # The engine tested XSS + SQLI; SSRF was expected but never exercised -> coverage gap.
    scan = SimpleNamespace(
        classes_tested=["XSS", "SQLI"],
        findings=[_confirmed("XSS", "http://h/api/search")],
    )
    expected = [["XSS", "/api/search"], ["SQLI", "/api/products"], ["SSRF", "/api/fetch"]]
    m = coverage_manifest(scan, expected)
    assert m["expected_coverage"]["XSS"] == "tested+confirmed"
    assert m["expected_coverage"]["SQLI"] == "tested+missed"  # exercised, not proven -> real FN
    assert m["expected_coverage"]["SSRF"] == "not-tested"  # never exercised -> coverage gap
    assert m["not_tested"] == ["SSRF"]


def test_aggregate_reports_variance_and_determinism():
    runs = [
        {"precision": 1.0, "recall": 0.8, "f1": 0.89, "confirmed": ["XSS@/a"]},
        {"precision": 1.0, "recall": 0.8, "f1": 0.89, "confirmed": ["XSS@/a"]},
    ]
    agg = aggregate(runs)
    assert agg["runs"] == 2 and agg["deterministic"] is True
    assert agg["recall"]["mean"] == 0.8 and agg["recall"]["stdev"] == 0.0
    # a divergent run makes it non-deterministic
    runs2 = runs + [{"precision": 1.0, "recall": 0.6, "f1": 0.75, "confirmed": ["XSS@/a", "SQLI@/b"]}]
    assert aggregate(runs2)["deterministic"] is False
