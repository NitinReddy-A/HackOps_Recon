"""Deterministic response differ used by the oracles and the validator.

Kept deliberately simple and dependency-free: status/length/similarity deltas plus a
signature check. These are the *code* signals the false-positive gate relies on, never
an LLM guess.
"""

from __future__ import annotations

import difflib


def body_similarity(a: str, b: str) -> float:
    if a is None or b is None:
        return 0.0
    if a == b:
        return 1.0
    return difflib.SequenceMatcher(None, a, b).ratio()


def contains_signature(body: str, signature: str) -> bool:
    if not signature:
        return False
    return signature in (body or "")


def diff_summary(baseline, test) -> dict:
    return {
        "status_baseline": getattr(baseline, "status", None),
        "status_test": getattr(test, "status", None),
        "len_baseline": getattr(baseline, "size", 0),
        "len_test": getattr(test, "size", 0),
        "similarity": round(body_similarity(getattr(baseline, "body", ""), getattr(test, "body", "")), 4),
    }
