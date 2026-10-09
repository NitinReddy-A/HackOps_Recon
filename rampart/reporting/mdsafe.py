"""Escaping for untrusted strings embedded in Markdown output.

Report fields routinely carry target-controlled text (Server headers, crawled paths, parameter
names, page titles, attack-chain "built from" lists). Markdown renderers pass raw HTML through,
so every such string must be neutralised before it is emitted, or the rendered report becomes an
XSS vector against whoever opens it. The helpers here:

* ``md`` — inline text: one line, ``& < >`` as entities, backslash/backtick/bracket escaped so it
  can neither open HTML, a code span, nor a link/image.
* ``md_cell`` — ``md`` plus ``|`` escaped, for GFM table cells.
* ``md_code`` — a code span whose fence is longer than any backtick run inside it (code-span
  content is literal, so no entity escaping is needed or wanted).
* ``md_fence`` — a fenced block (column 0) whose fence outlasts any backtick run in the body.
"""

from __future__ import annotations

import re

_WS = re.compile(r"\s+")
_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")
_TICKS = re.compile(r"`+")
_MD_ESC = str.maketrans(
    {
        "\\": "\\\\",
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        "`": "\\`",
        "[": "\\[",
        "]": "\\]",
    }
)


def one_line(x) -> str:
    """``str(x)`` with control characters removed and all whitespace runs collapsed to one space."""
    s = "" if x is None else str(x)
    return _WS.sub(" ", _CTRL.sub("", s)).strip()


def md(x) -> str:
    """Inline Markdown text that renders literally (no HTML, code spans, links or line breaks)."""
    return one_line(x).translate(_MD_ESC)


def md_cell(x) -> str:
    """``md`` for a GFM table cell (pipes escaped too)."""
    return md(x).replace("|", "\\|")


def md_join(items, sep: str = ", ") -> str:
    return sep.join(md(i) for i in (items or []))


def _fence_len(s: str) -> int:
    return max((len(m) for m in _TICKS.findall(s)), default=0) + 1


def md_code(x, *, table: bool = False) -> str:
    """A code span holding ``x`` literally, whatever backticks it contains."""
    s = one_line(x)
    if table:
        s = s.replace("|", "\\|")  # GFM splits cells before parsing code spans
    if not s:
        return ""
    fence = "`" * _fence_len(s)
    if s.startswith("`") or s.endswith("`"):
        s = f" {s} "
    return f"{fence}{s}{fence}"


def md_fence(text, lang: str = "") -> list:
    """Lines of a column-0 fenced code block containing ``text`` verbatim (control chars removed)."""
    body = [_CTRL.sub("", line) for line in str(text or "").splitlines()]
    fence = "`" * max(3, _fence_len("\n".join(body)))
    return [fence + lang, *body, fence]
