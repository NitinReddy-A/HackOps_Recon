"""Shared finding-status and severity helpers for every output surface.

One definition of "confirmed" keeps the metrics, Markdown/HTML/JSON/SARIF reports, the PR comment
and the dashboard consistent: a finding is *confirmed* only while it is independently validated
**and** still open — a candidate the gate dropped, or a finding a retest flipped to Fixed, is not.
Works on live ``Finding`` objects and on report-JSON finding dicts alike.
"""

from __future__ import annotations

SEV_ORDER = ("critical", "high", "medium", "low", "info")
SEV_RANK = {s: i for i, s in enumerate(SEV_ORDER)}  # critical=0 … info=4 (sort ascending = worst first)

DROPPED = "Dropped"
FIXED = "Fixed"
STATIC_TAGS = ("sast", "sca", "iac")


def _get(obj, key, default=None):
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


def norm_severity(sev) -> str:
    """A known lowercase severity; anything odd (None, non-string, unknown word) becomes ``info``."""
    s = sev.strip().lower() if isinstance(sev, str) else ""
    return s if s in SEV_RANK else "info"


def sev_rank(sev) -> int:
    """Sort key: 0 for critical … 4 for info (unknown values sort as info)."""
    return SEV_RANK[norm_severity(sev)]


def state_of(f) -> str:
    return str(_get(f, "state", "") or "")


def is_validated(f) -> bool:
    return bool(_get(_get(f, "verification", None) or {}, "validated", False))


def is_dropped(f) -> bool:
    return state_of(f) == DROPPED


def is_fixed(f) -> bool:
    return state_of(f) == FIXED


def is_confirmed(f) -> bool:
    """Validated by the independent oracle and still open (not Dropped, not Fixed by retest)."""
    return is_validated(f) and state_of(f) not in (DROPPED, FIXED)


def is_static(f) -> bool:
    """A white-box (SAST / SCA / IaC) finding."""
    tags = _get(f, "tags", None) or []
    return any(t in tags for t in STATIC_TAGS)


def unique_by_id(findings) -> list:
    """Drop repeated entries for the same finding (same id, or same dedupe key); first one wins."""
    seen, out = set(), []
    for f in findings:
        keys = {("id", _get(f, "id", None) or id(f))}
        if _get(f, "dedupe_key", None):
            keys.add(("dk", _get(f, "dedupe_key")))
        if keys & seen:
            continue
        seen |= keys
        out.append(f)
    return out
