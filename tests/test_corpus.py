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
