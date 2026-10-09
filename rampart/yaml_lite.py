"""A tiny, fail-closed YAML-subset loader.

The scope/authorization contract (``rampart.scope.yaml``) is safety-critical, so we want it
parseable even when PyYAML is not installed. This loader supports exactly the subset the
contract uses and **raises** :class:`YamlError` on anything else rather than guessing
(fail-closed). A silently mis-parsed ``paths_exclude`` widens the authorized scope, so the
rule is: every input either parses to the same value PyYAML would produce, or is rejected.

Supported:
  * block mappings and block sequences, indented with **spaces** (tabs are rejected),
    including a sequence at the same indent as its parent key (``key:\\n- a``);
  * a compact mapping on a sequence-item line (``- host: x``);
  * single-line flow sequences / mappings (``[a, "b"]``, ``{k: v}``), nested;
  * single- and double-quoted scalars (single line), plain scalars;
  * ``null``/``~``/empty, PyYAML's YAML 1.1 booleans, decimal ints, dotted floats;
  * ``#`` comments (only outside quotes, and only at line start or after whitespace),
    plus one leading ``---`` and one trailing ``...`` document marker.

Rejected (raises): tabs in indentation or outside quotes, anchors/aliases (``&``/``*``), tags
(``!``), block scalars (``|``/``>``), directives (``%``), complex keys (``?``), flow
collections that do not close on their own line, multi-line plain/quoted scalars, duplicate
keys, non-string keys, ambiguous numerics (``010``, ``0x1F``, ``1_000``, ``1e5``, ``.inf``,
``1:20``), and any trailing content after a value.

If PyYAML *is* installed, :func:`load` delegates to it (via a ``SafeLoader`` subclass that
additionally rejects duplicate keys, so a second ``out_of_scope:`` cannot silently replace
the first).
"""

from __future__ import annotations

import datetime
import re
from typing import Any

try:  # prefer the real thing when available
    import yaml as _pyyaml  # type: ignore
except Exception:  # pragma: no cover - exercised only without PyYAML
    _pyyaml = None


class YamlError(ValueError):
    pass


_strict_loader_cache: list = []


def _strict_loader():
    """A PyYAML SafeLoader that rejects duplicate mapping keys (fail-closed)."""
    if _strict_loader_cache:
        return _strict_loader_cache[0]

    class _StrictLoader(_pyyaml.SafeLoader):  # type: ignore[misc,name-defined]
        def construct_mapping(self, node, deep=False):
            seen = set()
            for key_node, _ in node.value:
                key = self.construct_object(key_node, deep=True)
                try:
                    dup = key in seen
                except TypeError:  # unhashable key — let PyYAML raise its own error
                    break
                if dup:
                    raise YamlError(f"duplicate key {key!r} (line {key_node.start_mark.line + 1})")
                seen.add(key)
            return super().construct_mapping(node, deep=deep)

    _strict_loader_cache.append(_StrictLoader)
    return _StrictLoader


def load(text: str) -> Any:
    if _pyyaml is not None:
        return _pyyaml.load(text, Loader=_strict_loader())  # noqa: S506 - SafeLoader subclass
    return _load_lite(text)


# --------------------------------------------------------------------------- #
# Fallback parser
# --------------------------------------------------------------------------- #
# Characters that may not start a plain scalar (YAML indicators). ``-``/``?``/``:`` are only
# indicators when followed by whitespace; they are handled separately.
_BAD_START = set("&*!|>%@`,[]{}#'\"")
_UNSUPPORTED = {
    "&": "anchors (&)",
    "*": "aliases (*)",
    "!": "tags (!)",
    "|": "block scalars (|)",
    ">": "block scalars (>)",
    "%": "directives (%)",
    "@": "reserved indicator (@)",
    "`": "reserved indicator (`)",
}

_INT_RE = re.compile(r"[-+]?(?:0|[1-9][0-9]*)\Z")
_FLOAT_RE = re.compile(r"[-+]?(?:[0-9]+\.[0-9]*|\.[0-9]+)(?:[eE][-+][0-9]+)?\Z")
# PyYAML's YAML 1.1 implicit int/float resolvers. A plain scalar PyYAML would turn into a number
# but which is not a plain decimal int / dotted float (octal 010, 0x1F, 1_000, sexagesimal 1:20,
# .inf, .nan) is rejected as ambiguous rather than given a possibly-different meaning.
_PYYAML_INT_RE = re.compile(
    r"(?:[-+]?0b[0-1_]+|[-+]?0[0-7_]+|[-+]?(?:0|[1-9][0-9_]*)|[-+]?0x[0-9a-fA-F_]+"
    r"|[-+]?[1-9][0-9_]*(?::[0-5]?[0-9])+)\Z"
)
_PYYAML_FLOAT_RE = re.compile(
    r"(?:[-+]?(?:[0-9][0-9_]*)\.[0-9_]*(?:[eE][-+][0-9]+)?|\.[0-9_]+(?:[eE][-+][0-9]+)?"
    r"|[-+]?[0-9][0-9_]*(?::[0-5]?[0-9])+\.[0-9_]*|[-+]?\.(?:inf|Inf|INF)|\.(?:nan|NaN|NAN))\Z"
)
# PyYAML's implicit timestamp resolver; matching scalars become date/datetime exactly as PyYAML does.
_TIMESTAMP_RE = re.compile(
    r"(?P<year>[0-9]{4})-(?P<month>[0-9][0-9]?)-(?P<day>[0-9][0-9]?)"
    r"(?:(?:[Tt]|[ ]+)(?P<hour>[0-9][0-9]?):(?P<minute>[0-9][0-9]):(?P<second>[0-9][0-9])"
    r"(?:\.(?P<fraction>[0-9]*))?"
    r"(?:[ ]*(?P<tz>Z|(?P<tz_sign>[-+])(?P<tz_hour>[0-9][0-9]?)(?::(?P<tz_minute>[0-9][0-9]))?))?)?\Z"
)
_DATE_ONLY_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}\Z")
_TRUE = {"true", "True", "TRUE", "yes", "Yes", "YES", "on", "On", "ON"}
_FALSE = {"false", "False", "FALSE", "no", "No", "NO", "off", "Off", "OFF"}
_NULL = {"null", "Null", "NULL", "~"}
_ESCAPES = {
    "0": "\0",
    "a": "\a",
    "b": "\b",
    "t": "\t",
    "\t": "\t",
    "n": "\n",
    "v": "\v",
    "f": "\f",
    "r": "\r",
    "e": "\x1b",
    " ": " ",
    '"': '"',
    "/": "/",
    "\\": "\\",
    "N": "\x85",
    "_": "\xa0",
    "L": " ",
    "P": " ",
}
_HEX_ESC = {"x": 2, "u": 4, "U": 8}


class _Line:
    __slots__ = ("indent", "text", "no")

    def __init__(self, indent: int, text: str, no: int):
        self.indent = indent
        self.text = text
        self.no = no


def _err(msg: str, line: _Line | None = None) -> YamlError:
    if line is not None:
        return YamlError(f"line {line.no}: {msg}: {line.text!r}")
    return YamlError(msg)


def _load_lite(text: str):
    if text.startswith("﻿"):
        text = text[1:]
    lines: list[_Line] = []
    for no, raw in enumerate(text.splitlines(), start=1):
        body = raw.rstrip(" \r")
        j = 0
        while j < len(body) and body[j] in " \t":
            j += 1
        if "\t" in body[:j]:
            raise YamlError(f"line {no}: tab characters are not allowed in indentation")
        content = body[j:]
        if not content or content.startswith("#"):
            continue
        lines.append(_Line(j, content, no))

    # document markers: one leading '---' and one trailing '...', nothing else
    def _is_marker(ln: _Line, m: str) -> bool:
        if ln.indent != 0 or not ln.text.startswith(m):
            return False
        rest = ln.text[3:]
        if rest == "":
            return True
        if rest[0] in " \t":
            if rest.strip().startswith("#") or rest.strip() == "":
                return True
            raise _err("content after a document marker is not supported", ln)
        return False

    if lines and _is_marker(lines[0], "---"):
        lines = lines[1:]
    if lines and _is_marker(lines[-1], "..."):
        lines = lines[:-1]
    for ln in lines:
        if _is_marker(ln, "---") or _is_marker(ln, "..."):
            raise _err("multiple YAML documents are not supported", ln)
        if ln.indent == 0 and ln.text.startswith("%"):
            raise _err("YAML directives are not supported", ln)
    if not lines:
        return None
    p = _Parser(lines)
    value = p.block(0, lines[0].indent)
    if p.i != len(lines):
        raise _err("unparsed trailing content (bad indentation?)", lines[p.i])
    return value


def _is_item(text: str) -> bool:
    return text == "-" or text.startswith("- ")


def _skip_ws(s: str, pos: int) -> int:
    while pos < len(s) and s[pos] in " \t":
        if s[pos] == "\t":
            raise YamlError(f"tab characters are not supported here: {s!r}")
        pos += 1
    return pos


def _only_comment_left(s: str, pos: int) -> bool:
    pos = _skip_ws(s, pos)
    return pos >= len(s) or s[pos] == "#"


class _Parser:
    def __init__(self, lines: list[_Line]):
        self.lines = lines
        self.i = 0

    def _next(self) -> _Line | None:
        return self.lines[self.i] if self.i < len(self.lines) else None

    def block(self, idx: int, indent: int):
        self.i = idx
        if _is_item(self.lines[idx].text):
            return self.seq(indent)
        return self.mapping(indent)

    def _nested_or_null(self, parent: _Line, allow_same_indent_seq: bool):
        nxt = self._next()
        if nxt is not None and nxt.indent > parent.indent:
            return self.block(self.i, nxt.indent)
        if nxt is not None and allow_same_indent_seq and nxt.indent == parent.indent and _is_item(nxt.text):
            return self.seq(parent.indent)
        return None

    def _no_continuation(self, ln: _Line) -> None:
        nxt = self._next()
        if nxt is not None and nxt.indent > ln.indent:
            raise _err("unexpected indentation (multi-line values are not supported)", nxt)

    def seq(self, indent: int) -> list:
        items: list = []
        while self.i < len(self.lines):
            ln = self.lines[self.i]
            if ln.indent < indent:
                break
            if ln.indent > indent:
                raise _err("unexpected indentation in sequence", ln)
            if not _is_item(ln.text):
                break
            rest = ln.text[1:]
            spaces = len(rest) - len(rest.lstrip(" "))
            body = rest[spaces:]
            if "\t" in rest[:spaces] or body.startswith("\t"):
                raise _err("tab characters are not supported", ln)
            if body == "" or body.startswith("#"):
                self.i += 1
                items.append(self._nested_or_null(ln, allow_same_indent_seq=False))
                continue
            if _is_item(body):
                raise _err("compact nested sequences ('- - x') are not supported", ln)
            col = indent + 1 + spaces
            if _split_key(body, ln) is not None:
                # "- key: value [more keys on following lines at the same column]"
                self.lines[self.i] = _Line(col, body, ln.no)
                items.append(self.mapping(col))
                continue
            value = _parse_value(body, ln)
            self.i += 1
            self._no_continuation(ln)
            items.append(value)
        return items

    def mapping(self, indent: int) -> dict:
        result: dict[str, Any] = {}
        while self.i < len(self.lines):
            ln = self.lines[self.i]
            if ln.indent < indent:
                break
            if ln.indent > indent:
                raise _err("unexpected indentation", ln)
            if _is_item(ln.text):
                break
            kv = _split_key(ln.text, ln)
            if kv is None:
                raise _err("expected 'key: value'", ln)
            key, rest = kv
            if key in result:
                raise _err(f"duplicate key {key!r}", ln)
            self.i += 1
            if _only_comment_left(rest, 0):
                result[key] = self._nested_or_null(ln, allow_same_indent_seq=True)
            else:
                result[key] = _parse_value(rest, ln)
                self._no_continuation(ln)
        return result


def _split_key(text: str, ln: _Line):
    """If ``text`` is a ``key: value`` entry return (key, rest-after-colon), else None."""
    c = text[0]
    if c in "\"'":
        key, pos = _parse_quoted(text, 0, ln)
        pos = _skip_ws(text, pos)
        if pos < len(text) and text[pos] == ":" and (pos + 1 == len(text) or text[pos + 1] in " \t"):
            return key, text[pos + 1 :]
        return None
    if c in "[{":
        return None  # a flow value; a flow *key* is rejected by _parse_value's trailing check
    if c in _UNSUPPORTED:
        raise _err(f"unsupported YAML construct: {_UNSUPPORTED[c]}", ln)
    if c in "?" and (len(text) == 1 or text[1] in " \t"):
        raise _err("complex mapping keys ('?') are not supported", ln)
    if c in ",]}#":
        raise _err("unexpected indicator", ln)
    for j, ch in enumerate(text):
        if ch == "\t":
            raise _err("tab characters are not supported", ln)
        if ch == "#" and j > 0 and text[j - 1] == " ":
            return None
        if ch == ":" and (j + 1 == len(text) or text[j + 1] == " "):
            raw_key = text[:j].rstrip()
            if not raw_key:
                raise _err("empty mapping key", ln)
            key = _resolve_plain(raw_key, ln)
            if not isinstance(key, str):
                raise _err(f"non-string mapping key {raw_key!r} is not supported", ln)
            return key, text[j + 1 :]
    return None


def _parse_value(s: str, ln: _Line):
    """Parse one inline value (everything after ``key:`` / ``- ``) and require that only
    whitespace and an optional comment follow it."""
    pos = _skip_ws(s, 0)
    if pos >= len(s) or s[pos] == "#":
        return None
    c = s[pos]
    if c in "[{":
        value, end = _parse_flow(s, pos, ln)
    elif c in "\"'":
        value, end = _parse_quoted(s, pos, ln)
    else:
        return _parse_block_plain(s[pos:], ln)
    if not _only_comment_left(s, end):
        raise _err("unexpected content after value", ln)
    return value


def _check_plain_start(s: str, ln: _Line) -> None:
    c = s[0]
    if c in _UNSUPPORTED:
        raise _err(f"unsupported YAML construct: {_UNSUPPORTED[c]}", ln)
    if c in _BAD_START:
        raise _err(f"unexpected indicator {c!r}", ln)
    if c in "-?:" and (len(s) == 1 or s[1] in " \t,[]{}"):
        raise _err(f"unsupported use of indicator {c!r}", ln)


def _parse_block_plain(s: str, ln: _Line):
    _check_plain_start(s, ln)
    end = len(s)
    for j, ch in enumerate(s):
        if ch == "\t":
            raise _err("tab characters are not supported", ln)
        if ch == "#" and s[j - 1] == " ":
            end = j
            break
    raw = s[:end].rstrip(" ")
    if ": " in raw or raw.endswith(":"):
        raise _err("mapping values are not allowed here (quote the value)", ln)
    return _resolve_plain(raw, ln)


def _resolve_plain(raw: str, ln: _Line):
    if raw == "" or raw in _NULL:
        return None
    if raw in _TRUE:
        return True
    if raw in _FALSE:
        return False
    if raw in ("<<", "="):
        raise _err(f"unsupported YAML construct {raw!r}", ln)
    ts = _TIMESTAMP_RE.match(raw)
    if ts and (ts.group("hour") or _DATE_ONLY_RE.match(raw)):
        return _timestamp(ts, ln)
    if _PYYAML_INT_RE.match(raw):
        if _INT_RE.match(raw):
            return int(raw)
        raise _err(f"ambiguous numeric scalar {raw!r} (quote it)", ln)
    if _PYYAML_FLOAT_RE.match(raw):
        if _FLOAT_RE.match(raw):
            return float(raw)
        raise _err(f"ambiguous numeric scalar {raw!r} (quote it)", ln)
    return raw


def _timestamp(m: re.Match, ln: _Line):
    v = m.groupdict()
    try:
        if not v["hour"]:
            return datetime.date(int(v["year"]), int(v["month"]), int(v["day"]))
        fraction = int(v["fraction"][:6].ljust(6, "0")) if v["fraction"] else 0
        tzinfo = None
        if v["tz_sign"]:
            delta = datetime.timedelta(hours=int(v["tz_hour"]), minutes=int(v["tz_minute"] or 0))
            tzinfo = datetime.timezone(-delta if v["tz_sign"] == "-" else delta)
        elif v["tz"]:
            tzinfo = datetime.timezone.utc
        return datetime.datetime(
            int(v["year"]),
            int(v["month"]),
            int(v["day"]),
            int(v["hour"]),
            int(v["minute"]),
            int(v["second"]),
            fraction,
            tzinfo=tzinfo,
        )
    except ValueError as exc:
        raise _err(f"invalid timestamp {m.group(0)!r}: {exc}", ln) from exc


def _parse_quoted(s: str, pos: int, ln: _Line) -> tuple[str, int]:
    q = s[pos]
    out: list[str] = []
    i = pos + 1
    while i < len(s):
        ch = s[i]
        if q == "'":
            if ch == "'":
                if i + 1 < len(s) and s[i + 1] == "'":
                    out.append("'")
                    i += 2
                    continue
                return "".join(out), i + 1
            out.append(ch)
            i += 1
            continue
        # double-quoted
        if ch == '"':
            return "".join(out), i + 1
        if ch == "\\":
            if i + 1 >= len(s):
                break
            e = s[i + 1]
            if e in _ESCAPES:
                out.append(_ESCAPES[e])
                i += 2
                continue
            if e in _HEX_ESC:
                n = _HEX_ESC[e]
                hexd = s[i + 2 : i + 2 + n]
                if len(hexd) != n or not all(h in "0123456789abcdefABCDEF" for h in hexd):
                    raise _err("bad escape in double-quoted scalar", ln)
                out.append(chr(int(hexd, 16)))
                i += 2 + n
                continue
            raise _err(f"unknown escape \\{e} in double-quoted scalar", ln)
        out.append(ch)
        i += 1
    raise _err("unterminated quoted scalar (multi-line quoted scalars are not supported)", ln)


def _parse_flow(s: str, pos: int, ln: _Line):
    """Parse a flow sequence/mapping starting at ``s[pos]``; must close on this line."""
    opener = s[pos]
    closer = "]" if opener == "[" else "}"
    pos += 1
    seq: list = []
    mp: dict = {}
    first = True
    while True:
        pos = _skip_ws(s, pos)
        if pos >= len(s) or s[pos] == "#":
            raise _err("unclosed flow collection (must close on the same line)", ln)
        if s[pos] == closer and first:
            pos += 1
            break
        if opener == "[":
            node, pos = _parse_flow_node(s, pos, ln, in_map_key=False)
            pos = _skip_ws(s, pos)
            if pos < len(s) and s[pos] == ":":
                raise _err("single-pair mappings inside flow sequences are not supported", ln)
            seq.append(node)
        else:
            if s[pos] in "[{":
                raise _err("flow collections as mapping keys are not supported", ln)
            key, pos = _parse_flow_node(s, pos, ln, in_map_key=True)
            if not isinstance(key, str):
                raise _err(f"non-string flow mapping key {key!r} is not supported", ln)
            pos = _skip_ws(s, pos)
            if pos >= len(s) or s[pos] != ":":
                raise _err(f"expected ':' after flow mapping key {key!r}", ln)
            pos = _skip_ws(s, pos + 1)
            if pos >= len(s) or s[pos] in ",}#":
                raise _err(f"missing value for flow mapping key {key!r}", ln)
            val, pos = _parse_flow_node(s, pos, ln, in_map_key=False)
            if key in mp:
                raise _err(f"duplicate key {key!r}", ln)
            mp[key] = val
        first = False
        pos = _skip_ws(s, pos)
        if pos >= len(s):
            raise _err("unclosed flow collection (must close on the same line)", ln)
        if s[pos] == ",":
            pos = _skip_ws(s, pos + 1)
            if pos < len(s) and s[pos] in "]}":
                raise _err("trailing comma in flow collection is not supported", ln)
            continue
        if s[pos] == closer:
            pos += 1
            break
        raise _err(f"unexpected {s[pos]!r} in flow collection", ln)
    return (seq if opener == "[" else mp), pos


def _parse_flow_node(s: str, pos: int, ln: _Line, in_map_key: bool):
    c = s[pos]
    if c in "[{":
        return _parse_flow(s, pos, ln)
    if c in "\"'":
        return _parse_quoted(s, pos, ln)
    _check_plain_start(s[pos:], ln)
    j = pos
    while j < len(s):
        ch = s[j]
        if ch == "\t":
            raise _err("tab characters are not supported", ln)
        if ch in ",[]{}":
            break
        if ch == "#" and s[j - 1] == " ":
            raise _err("unclosed flow collection (comment inside it)", ln)
        if ch == ":":
            if in_map_key and (j + 1 == len(s) or s[j + 1] in " ,]}"):
                break
            raise _err("':' inside an unquoted flow scalar is ambiguous (quote it)", ln)
        j += 1
    raw = s[pos:j].rstrip(" ")
    if raw == "":
        raise _err("empty flow entry", ln)
    return _resolve_plain(raw, ln), j
