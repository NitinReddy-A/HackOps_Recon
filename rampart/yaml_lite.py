"""A tiny, fail-closed YAML-subset loader.

The scope/authorization contract (``SECURITY.md``) is safety-critical, so we want it
parseable even when PyYAML is not installed. This loader supports exactly the subset
the contract uses — block maps, block lists, inline flow lists/maps, quoted and plain
scalars, ints/floats/bools/null, and ``#`` comments — and **raises** on anything it
does not understand rather than guessing (fail-closed).

If PyYAML *is* installed, :func:`load` delegates to it (it is a strict superset).
"""
from __future__ import annotations

from typing import Any

try:  # prefer the real thing when available
    import yaml as _pyyaml  # type: ignore
except Exception:  # pragma: no cover - exercised only without PyYAML
    _pyyaml = None


class YamlError(ValueError):
    pass


def load(text: str) -> Any:
    if _pyyaml is not None:
        return _pyyaml.safe_load(text)
    return _load_lite(text)


# --------------------------------------------------------------------------- #
# Fallback parser
# --------------------------------------------------------------------------- #
def _strip_comment(line: str) -> str:
    out, in_s, in_d = [], False, False
    i = 0
    while i < len(line):
        c = line[i]
        if c == "'" and not in_d:
            in_s = not in_s
        elif c == '"' and not in_s:
            in_d = not in_d
        elif c == "#" and not in_s and not in_d:
            # a comment starts only at start-of-line or after whitespace
            if i == 0 or line[i - 1] in " \t":
                break
        out.append(c)
        i += 1
    return "".join(out).rstrip()


def _load_lite(text: str):
    raw_lines = text.splitlines()
    lines: list[tuple[int, str]] = []
    for ln in raw_lines:
        stripped = _strip_comment(ln)
        if not stripped.strip():
            continue
        if stripped.lstrip().startswith("---") or stripped.lstrip().startswith("..."):
            continue
        indent = len(stripped) - len(stripped.lstrip(" "))
        lines.append((indent, stripped.strip()))
    if not lines:
        return None
    value, idx = _parse_block(lines, 0, lines[0][0])
    if idx != len(lines):
        raise YamlError(f"unparsed trailing content near: {lines[idx][1]!r}")
    return value


def _parse_block(lines, idx, indent):
    if lines[idx][1].startswith("- "):
        return _parse_list(lines, idx, indent)
    return _parse_map(lines, idx, indent)


def _parse_list(lines, idx, indent):
    items = []
    while idx < len(lines):
        cur_indent, content = lines[idx]
        if cur_indent < indent:
            break
        if cur_indent > indent:
            raise YamlError(f"unexpected indent in list at: {content!r}")
        if not content.startswith("- "):
            break
        item_body = content[2:].strip()
        if ":" in item_body and not _is_flow(item_body):
            # inline first map key on the dash line, e.g. "- host: x"
            synthetic = [(indent + 2, item_body)]
            j = idx + 1
            while j < len(lines) and lines[j][0] > indent:
                synthetic.append((lines[j][0], lines[j][1]))
                j += 1
            value, consumed = _parse_map(synthetic, 0, indent + 2)
            if consumed != len(synthetic):
                raise YamlError(f"could not fully parse list item near: {item_body!r}")
            items.append(value)
            idx = j
        else:
            items.append(_parse_scalar(item_body))
            idx += 1
    return items, idx


def _parse_map(lines, idx, indent):
    result: dict[str, Any] = {}
    while idx < len(lines):
        cur_indent, content = lines[idx]
        if cur_indent < indent:
            break
        if cur_indent > indent:
            raise YamlError(f"unexpected indent at: {content!r}")
        if content.startswith("- "):
            break
        if ":" not in content:
            raise YamlError(f"expected 'key: value' but got: {content!r}")
        key, _, rest = content.partition(":")
        key = key.strip().strip('"').strip("'")
        rest = rest.strip()
        if rest == "":
            # nested block on following, more-indented lines
            if idx + 1 < len(lines) and lines[idx + 1][0] > cur_indent:
                child_indent = lines[idx + 1][0]
                value, idx = _parse_block(lines, idx + 1, child_indent)
                result[key] = value
            else:
                result[key] = None
                idx += 1
        else:
            result[key] = _parse_scalar(rest)
            idx += 1
    return result, idx


def _is_flow(s: str) -> bool:
    return s.startswith("[") or s.startswith("{")


def _split_flow(inner: str) -> list[str]:
    parts, depth, buf, in_s, in_d = [], 0, [], False, False
    for c in inner:
        if c == "'" and not in_d:
            in_s = not in_s
        elif c == '"' and not in_s:
            in_d = not in_d
        if not in_s and not in_d:
            if c in "[{":
                depth += 1
            elif c in "]}":
                depth -= 1
            elif c == "," and depth == 0:
                parts.append("".join(buf).strip())
                buf = []
                continue
        buf.append(c)
    tail = "".join(buf).strip()
    if tail:
        parts.append(tail)
    return parts


def _parse_scalar(s: str):
    s = s.strip()
    if s.startswith("[") and s.endswith("]"):
        inner = s[1:-1].strip()
        return [_parse_scalar(p) for p in _split_flow(inner)] if inner else []
    if s.startswith("{") and s.endswith("}"):
        inner = s[1:-1].strip()
        out = {}
        for p in _split_flow(inner):
            if ":" not in p:
                raise YamlError(f"expected key: value in flow map: {p!r}")
            k, _, v = p.partition(":")
            out[k.strip().strip('"').strip("'")] = _parse_scalar(v)
        return out
    if (s.startswith('"') and s.endswith('"')) or (s.startswith("'") and s.endswith("'")):
        return s[1:-1]
    low = s.lower()
    if low in ("null", "~", ""):
        return None
    if low == "true":
        return True
    if low == "false":
        return False
    try:
        return int(s)
    except ValueError:
        pass
    try:
        return float(s)
    except ValueError:
        pass
    return s
