"""Stage 3 — action-risk classifier.

A DETERMINISTIC rules table, not an LLM: a hijacked model must not be able to downgrade
its own risk. The effective tier is the MAXIMUM of what the HTTP method implies, what the
declared payload class implies, and what destructive-marker scanning finds — so mislabeling
a ``DELETE`` as ``benign-read`` cannot lower the tier (blueprint section 12).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from urllib.parse import unquote_plus

from ..schemas.toolcall import RiskTier, ToolAction

_WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

# Patterns that indicate destructive / state-changing / prohibited intent (Tier 3). They are
# matched against every place a payload can ride (path, query keys+values, header names+values,
# body — see :func:`scan_text`), after URL-decoding and normalizing SQL block comments and
# whitespace runs. These are things that DAMAGE or change state on the target. Note: reading a
# sensitive file (e.g. path traversal to /etc/passwd) is *disclosure*, not destruction — that is
# a Tier-1 read probe and is NOT listed here; the disclosure is the finding, and non-destructive
# reads on an in-scope target are exactly what we are authorized to test.
_DESTRUCTIVE_MARKERS = [
    re.compile(r"(?i)\bdrop\s+(?:table|database|schema|index|view|user|function|procedure|trigger)\b"),
    re.compile(r"(?i)\bdropdatabase\b"),  # mongo db.dropDatabase()
    re.compile(r"(?i)\btruncate\b"),
    re.compile(r"(?i)\bdelete\s+from\b"),
    re.compile(r"(?i)\balter\s+table\b[^;\x00]*\bdrop\b"),
    re.compile(r"(?i)\bupdate\s+[\w.`\"\[\]]+\s+set\b"),
    re.compile(r"(?i)\bflush(?:all|db)\b"),  # redis wipe
    re.compile(r"(?i)\b(?:shutdown|reboot|poweroff)\b"),
    re.compile(r"(?i)\binit\s+0\b"),
    re.compile(r"(?i)\bkill(?:all)?\s+-(?:9|kill)\b"),
    # rm with any recursive/force flag spelling: rm -rf, rm -fr, rm -r -f, rm -Rf, rm --recursive
    re.compile(r"(?i)\brm\s+(?:-{1,2}[a-z-]+\s+)*(?:-[a-z]*[rf][a-z]*|--recursive|--force)\b"),
    re.compile(r"(?i)\b(or|and)\s+1=1\s*;?\s*(--|#)"),  # tautology + statement terminator
    re.compile(r"(?i)\bxp_cmdshell\b"),
    re.compile(r"(?i)\bmkfs(?:\.\w+)?\b"),  # format a filesystem
    re.compile(r"(?i)\bformat\s+[a-z]:"),  # format a Windows drive
    re.compile(r"(?i)\bdd\s+[^|;\x00]*\bif="),  # raw disk copy/wipe
    re.compile(r":\(\)\s*\{"),  # shell fork bomb :(){ :|:& };:
]

_SQL_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.DOTALL)
_WS = re.compile(r"\s+")
# parts are joined with NUL so no marker (``\s+``/``[^;]*``) can match across two separate fields
_SEP = "\x00"

_PAYLOAD_TIER = {
    "benign-read": RiskTier.READ_ONLY,
    "canary": RiskTier.CONTROLLED_VALIDATION,
    "boundary-probe": RiskTier.CONTROLLED_VALIDATION,
    "state-change": RiskTier.HIGH_RISK,
    "destructive": RiskTier.PROHIBITED,
}


@dataclass
class RiskResult:
    tier: int
    reason: str
    declared_tier: int
    downgrade_attempt: bool = False


def _flatten(obj, out: list) -> None:
    if isinstance(obj, dict):
        for k, v in obj.items():
            out.append(str(k))
            _flatten(v, out)
    elif isinstance(obj, (list, tuple, set)):
        for v in obj:
            _flatten(v, out)
    elif obj is not None:
        out.append(str(obj))


def _variants(text: str) -> list[str]:
    """``text`` plus its URL-decodings (``+`` -> space, up to 3 rounds), each normalized so SQL
    block comments (``DROP/**/TABLE``), NULs and whitespace runs collapse to a single space."""
    forms = [text]
    cur = text
    for _ in range(3):
        nxt = unquote_plus(cur)
        if nxt == cur:
            break
        forms.append(nxt)
        cur = nxt
    if "\\u" in cur or "\\x" in cur:  # JSON / JS escapes in a raw body
        try:
            forms.append(cur.encode("latin-1", "backslashreplace").decode("unicode_escape"))
        except (UnicodeDecodeError, UnicodeEncodeError):
            pass
    out = []
    for f in forms:
        f = f.replace("\x00", " ")
        f = _SQL_BLOCK_COMMENT.sub(" ", f)
        out.append(_WS.sub(" ", f))
    return out


def scan_text(action: ToolAction) -> str:
    """Everything a destructive payload could ride in: path, query KEYS and values (incl. lists),
    header names and values, and the body (raw, form-decoded and — if JSON — every key/string)."""
    parts: list[str] = [str(action.path or "")]
    _flatten(action.query or {}, parts)
    _flatten(action.headers or {}, parts)
    body = action.body
    if body:
        if isinstance(body, (bytes, bytearray)):
            body = bytes(body).decode("utf-8", "replace")
        body = str(body)
        parts.append(body)
        try:
            _flatten(json.loads(body), parts)
        except (ValueError, TypeError, RecursionError):
            pass
    hay: list[str] = []
    for p in parts:
        hay.extend(_variants(p))
    return _SEP.join(hay)


def classify(action: ToolAction, declared_tier: int = 0) -> RiskResult:
    reasons = []

    method_tier = RiskTier.HIGH_RISK if action.method.upper() in _WRITE_METHODS else RiskTier.READ_ONLY
    if method_tier == RiskTier.HIGH_RISK:
        reasons.append(f"{action.method} is a state-changing method")

    payload_tier = _PAYLOAD_TIER.get(action.payload_class, RiskTier.HIGH_RISK)
    if action.payload_class not in _PAYLOAD_TIER:
        reasons.append(f"unknown payload_class {action.payload_class!r} -> treated as high-risk")
    else:
        reasons.append(f"payload_class={action.payload_class}")

    marker_tier = RiskTier.READ_ONLY
    # Scan path, query keys+values, headers and body — URL-decoded and comment/whitespace
    # normalized — so a hijacked model cannot smuggle a destructive payload past the markers.
    haystack = scan_text(action)
    for pat in _DESTRUCTIVE_MARKERS:
        if pat.search(haystack):
            marker_tier = RiskTier.PROHIBITED
            reasons.append(f"destructive marker matched: {pat.pattern}")
            break

    tier = int(max(method_tier, payload_tier, marker_tier))
    downgrade = declared_tier < tier
    if downgrade:
        reasons.append(f"declared_tier={declared_tier} < effective_tier={tier} (declaration ignored)")
    return RiskResult(
        tier=tier, reason="; ".join(reasons), declared_tier=declared_tier, downgrade_attempt=downgrade
    )
