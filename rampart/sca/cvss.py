"""A compact, deterministic CVSS v3.1 base-score calculator (stdlib only).

OSV advisories carry a CVSS *vector string* (e.g. ``CVSS:3.1/AV:N/AC:L/...``) rather than a
numeric score. We recompute the base score from the vector ourselves — deterministically, by the
published formula — so a finding's severity is derived from evidence (the advisory's own metrics),
never guessed. If the vector is missing or malformed we fall back to the advisory's text severity.
"""

from __future__ import annotations

import math

# Metric weights from the CVSS v3.1 specification (section 7.4).
_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}  # scope unchanged
_PR_C = {"N": 0.85, "L": 0.68, "H": 0.5}  # scope changed
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"N": 0.0, "L": 0.22, "H": 0.56}


def _roundup(x: float) -> float:
    """CVSS 3.1 Roundup: smallest number, to one decimal, that is >= x (avoids FP noise)."""
    i = int(round(x * 100000))
    if i % 10000 == 0:
        return i / 100000.0
    return (math.floor(i / 10000) + 1) / 10.0


def parse_vector(vector: str) -> dict:
    out = {}
    if not vector:
        return out
    parts = vector.split("/")
    for p in parts:
        if ":" in p:
            k, _, v = p.partition(":")
            out[k.strip().upper()] = v.strip().upper()
    return out


def base_score(vector: str) -> float | None:
    """Return the CVSS v3.x base score for a vector string, or None if it can't be computed."""
    m = parse_vector(vector)
    try:
        av, ac, pr, ui = _AV[m["AV"]], _AC[m["AC"]], m["PR"], _UI[m["UI"]]
        scope_changed = m["S"] == "C"
        c, i, a = _CIA[m["C"]], _CIA[m["I"]], _CIA[m["A"]]
    except KeyError:
        return None
    pr_w = (_PR_C if scope_changed else _PR_U).get(pr)
    if pr_w is None:
        return None

    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
    else:
        impact = 6.42 * iss
    if impact <= 0:
        return 0.0
    exploitability = 8.22 * av * ac * pr_w * ui
    raw = (1.08 * (impact + exploitability)) if scope_changed else (impact + exploitability)
    return _roundup(min(raw, 10.0))


def severity_band(score: float | None) -> str:
    """Map a numeric base score to Rampart's severity vocabulary."""
    if score is None:
        return "medium"
    if score == 0:
        return "info"
    if score < 4.0:
        return "low"
    if score < 7.0:
        return "medium"
    if score < 9.0:
        return "high"
    return "critical"


# Text severity (GHSA-style) -> (severity, representative score) when no CVSS vector is present.
_TEXT = {
    "CRITICAL": ("critical", 9.5),
    "HIGH": ("high", 8.0),
    "MODERATE": ("medium", 5.5),
    "MEDIUM": ("medium", 5.5),
    "LOW": ("low", 3.0),
    "NONE": ("info", 0.0),
}


def from_text(sev: str) -> tuple[str, float]:
    return _TEXT.get((sev or "").strip().upper(), ("medium", 5.0))
