"""Render a Rampart run as a GitHub pull-request comment (Markdown).

Works from either live ``Finding`` objects (the SDK) or the ``findings`` list in a ``report.json``
(the CLI / the Action), so every surface produces the same comment. The output carries a hidden
marker so the poster can update one sticky comment instead of spamming a new one each run.
"""

from __future__ import annotations

import re
from urllib.parse import quote

from .mdsafe import md_cell, one_line
from .status import is_confirmed, is_dropped, is_fixed, norm_severity

MARKER = "<!-- rampart-report -->"
_SEV_ORDER = ["critical", "high", "medium", "low", "info"]
_SEV_EMOJI = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}

_ZWJ = "‍"
# @user / @org/team mentions and #123 / owner/repo#123 issue references would notify people or
# cross-link other issues from target-controlled text; a zero-width joiner breaks the auto-link.
_MENTION = re.compile(r"([@#])(?=[A-Za-z0-9_-])")


def _no_ping(s: str) -> str:
    return _MENTION.sub(lambda m: m.group(1) + _ZWJ, s)


def _cell(x, limit: int = 0) -> str:
    """Untrusted text for a table cell: one line, HTML/markdown/pipe-escaped, no live mentions."""
    s = one_line(x)
    if limit and len(s) > limit:
        s = s[: limit - 1] + "…"
    return _no_ping(md_cell(s))


def _code_cell(x, limit: int = 0) -> str:
    """Untrusted text shown as a code span in a table cell (backticks replaced, pipes escaped)."""
    s = one_line(x).replace("`", "'")
    if limit and len(s) > limit:
        s = s[: limit - 1] + "…"
    if not s:
        return ""
    return "`" + s.replace("|", "\\|") + "`"


def _get(obj, key, default=None):
    """Read a field from a dataclass-ish object or a dict."""
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


def _location(f) -> str:
    endpoint = _get(f, "endpoint", {}) or {}
    url = _get(endpoint, "url", "") if endpoint else ""
    if url:
        method = _get(endpoint, "method", "") or ""
        return f"{method} {url}".strip()
    affected = _get(f, "affected_code", None)
    if affected:
        file = _get(affected, "file", "")
        line = _get(affected, "start_line", 0)
        if file:
            return f"{file}:{line}" if line else file
    asset = _get(f, "asset", {}) or {}
    return _get(asset, "target", "") or ""


def _normalize(f) -> dict:
    verification = _get(f, "verification", {}) or {}
    tags = _get(f, "tags", []) or []
    cwe = _get(f, "cwe", []) or []
    return {
        "severity": norm_severity(_get(f, "severity", "info")),
        "title": _get(f, "title", "finding"),
        "vuln_class": _get(f, "vuln_class", ""),
        "cwe": list(cwe) if isinstance(cwe, (list, tuple)) else [cwe],
        "location": _location(f),
        "validated": bool(_get(verification, "validated", False)),
        "state": _get(f, "state", ""),
        "confirmed": is_confirmed(f),
        "fixed": is_fixed(f),
        "dropped": is_dropped(f),
        "agent": "agent-assessed" in tags,
    }


def _sev_rank(sev) -> int:
    order = ["info", "low", "medium", "high", "critical"]
    sev = norm_severity(sev)
    return order.index(sev)


def render_pr_comment(
    findings,
    *,
    application: str = "",
    fail_on: str | None = None,
    report_url: str = "",
    max_rows: int = 30,
) -> str:
    """Return a Markdown PR comment summarizing a run.

    ``findings`` is a list of ``Finding`` objects or report-JSON finding dicts. If ``fail_on`` is
    set, the header shows whether the severity gate passed.
    """
    norm = [_normalize(f) for f in findings]
    confirmed = [f for f in norm if f["confirmed"]]
    agent = [f for f in norm if f["agent"] and not f["dropped"] and not f["fixed"]]
    fixed = [f for f in norm if f["fixed"]]
    dropped = [f for f in norm if f["dropped"]]

    counts = dict.fromkeys(_SEV_ORDER, 0)
    for f in confirmed:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    gate_line = ""
    if fail_on:
        gate = norm_severity(fail_on)
        threshold = _sev_rank(gate)
        breached = [f for f in confirmed if _sev_rank(f["severity"]) >= threshold]
        if breached:
            gate_line = f"❌ **Gate failed** — {len(breached)} confirmed finding(s) at or above `{gate}`."
        else:
            gate_line = f"✅ **Gate passed** — no confirmed findings at or above `{gate}`."

    app = f" for {_code_cell(application, 80)}" if one_line(application) else ""
    lines = [MARKER, f"## 🛡️ Rampart security report{app}", ""]
    if gate_line:
        lines += [gate_line, ""]

    if not confirmed:
        lines.append("**No confirmed vulnerabilities.** ✅")
    else:
        badge = " · ".join(f"{_SEV_EMOJI[s]} {counts[s]} {s}" for s in _SEV_ORDER if counts.get(s))
        lines.append(f"**{len(confirmed)} confirmed** — {badge}")
        lines.append("")
        lines.append("| Severity | Finding | Location | CWE |")
        lines.append("|---|---|---|---|")
        ordered = sorted(confirmed, key=lambda f: -_sev_rank(f["severity"]))
        for f in ordered[:max_rows]:
            cwe = _cell(", ".join(str(c) for c in f["cwe"][:2]), 40)
            loc = _code_cell(f["location"], 80)
            title = _cell(f["title"], 100)
            lines.append(f"| {_SEV_EMOJI[f['severity']]} {f['severity']} | {title} | {loc} | {cwe} |")
        if len(ordered) > max_rows:
            lines.append(f"| … | _{len(ordered) - max_rows} more_ | | |")

    notes = []
    if fixed:
        notes.append(f"{len(fixed)} verified fixed by retest")
    if agent:
        notes.append(f"{len(agent)} agent-assessed (needs human review)")
    if dropped:
        notes.append(f"{len(dropped)} dropped by the false-positive gate")
    if notes:
        lines += ["", "> " + " · ".join(notes) + "."]

    url = one_line(report_url)
    if url:
        lines += ["", f"[Full report]({quote(url, safe=':/?#=&%@+,;~')})"]
    lines += ["", f"<sub>Generated by [Rampart](https://github.com/NitinReddy-A/rampart){app}.</sub>"]
    return "\n".join(lines)


def render_from_report(report: dict, **kwargs) -> str:
    """Render from a parsed ``report.json`` dict (its ``findings`` list)."""
    app = kwargs.pop("application", "") or (report.get("engagement", {}) or {}).get("application", "")
    return render_pr_comment(report.get("findings", []) or [], application=app, **kwargs)
