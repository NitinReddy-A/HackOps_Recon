"""Dependency-manifest parsers (stdlib only) that extract *exact* pinned versions.

Software Composition Analysis needs concrete ``name@version`` pairs to match against advisories;
version *ranges* (e.g. ``^1.2`` / ``>=2.0`` / ``==2.*``) can't be matched to a specific CVE, so only
lock / exact-pinned forms become :class:`Dep` records. Ranged / unpinned declarations are reported
separately (:func:`collect_unpinned`) so the dependency inventory can flag them without querying.

Each parser returns ``Dep`` records tagged with the OSV ecosystem, the manifest file, and the line
number (best effort; 0 when unknown) for the finding's ``affected_code``.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Dep:
    ecosystem: str  # OSV ecosystem: PyPI | npm | Go | Maven | RubyGems | crates.io
    name: str
    version: str
    manifest: str  # repo-relative manifest path
    line: int = 0

    def key(self) -> tuple:
        return (self.ecosystem, self.name, self.version)


@dataclass(frozen=True)
class Unpinned:
    """A declared dependency whose version is a range / wildcard / missing (not CVE-matchable)."""

    ecosystem: str
    name: str
    spec: str
    manifest: str
    line: int = 0


def normalize_pypi(name: str) -> str:
    """PEP 503 normalised project name (``Flask_Cors`` -> ``flask-cors``)."""
    return re.sub(r"[-_.]+", "-", name or "").lower()


def normalize_name(ecosystem: str, name: str) -> str:
    return normalize_pypi(name) if ecosystem == "PyPI" else name


def _rel(path: str, repo: str) -> str:
    return os.path.relpath(path, repo).replace("\\", "/")


def _read(path: str) -> str | None:
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return None


def _line_of(text: str, needle: str) -> int:
    """1-based line of the first occurrence of ``needle`` (0 if absent)."""
    i = text.find(needle)
    return text.count("\n", 0, i) + 1 if i >= 0 else 0


# --------------------------------------------------------------------------- PyPI
_REQ_LINE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*(.*)$")
_EXACT_PIN = re.compile(r"^===?\s*([A-Za-z0-9._+!-]+)$")


def _parse_pep508(spec: str):
    """Classify one PEP 508 requirement string.

    Returns ``(name, version_or_None, rest)``: version is set only for a single exact, non-wildcard
    pin (``==1.2.3`` / ``===1.2``). ``rest`` is the raw specifier (for the unpinned inventory).
    Returns None when the string is not a named requirement.
    """
    s = spec.split(";", 1)[0].strip()  # drop environment markers
    m = _REQ_LINE.match(s)
    if not m:
        return None
    name, rest = m.group(1), m.group(3).strip()
    if rest.startswith("@"):  # PEP 440 direct reference (name @ url) — pinned to an artifact
        return name, None, rest
    pin = _EXACT_PIN.match(rest)
    if pin and "*" not in pin.group(1) and "," not in rest:
        return name, pin.group(1), rest
    return name, None, rest


def _requirements(path: str, repo: str, _stack: frozenset = frozenset()):
    """(deps, unpinned) for a pip requirements file, following ``-r`` / ``--requirement`` includes."""
    deps: list[Dep] = []
    unpinned: list[Unpinned] = []
    real = os.path.realpath(path)
    if real in _stack:
        return deps, unpinned
    text = _read(path)
    if text is None:
        return deps, unpinned
    rel = _rel(path, repo)
    # join backslash line continuations, keeping the first line's number
    logical: list[tuple[int, str]] = []
    buf, start = "", 0
    for i, raw in enumerate(text.splitlines(), 1):
        if not buf:
            start = i
        if raw.rstrip().endswith("\\"):
            buf += raw.rstrip()[:-1] + " "
            continue
        logical.append((start, buf + raw))
        buf = ""
    if buf:
        logical.append((start, buf))
    for i, raw in logical:
        s = re.split(r"(?:^|\s)#", raw, maxsplit=1)[0].strip()
        if not s:
            continue
        inc = re.match(r"^(?:-r|--requirement)(?:\s+|=)(\S+)", s)
        if inc:
            target = os.path.join(os.path.dirname(path), inc.group(1))
            if os.path.isfile(target) and os.path.realpath(target).startswith(os.path.realpath(repo)):
                d2, u2 = _requirements(target, repo, _stack | {real})
                deps += d2
                unpinned += u2
            continue
        if s.startswith("-") or re.match(r"^[a-z][a-z0-9+.-]*://", s) or s.startswith("git+"):
            continue  # options, editable installs, bare URLs
        parsed = _parse_pep508(s)
        if not parsed:
            continue
        name, ver, rest = parsed
        if ver:
            deps.append(Dep("PyPI", normalize_pypi(name), ver, rel, i))
        elif not rest.startswith("@"):
            unpinned.append(Unpinned("PyPI", normalize_pypi(name), rest or "(any)", rel, i))
    return deps, unpinned


def parse_requirements(path: str, repo: str) -> list[Dep]:
    return _requirements(path, repo)[0]


def _is_requirements_file(path: str) -> bool:
    base = os.path.basename(path).lower()
    if not base.endswith(".txt"):
        return False
    if "requirements" in base:
        return True
    parent = os.path.basename(os.path.dirname(path)).lower()
    return parent in ("requirements", "reqs")


def parse_pipfile_lock(path: str, repo: str) -> list[Dep]:
    deps = []
    text = _read(path)
    try:
        data = json.loads(text or "")
    except ValueError:
        return deps
    rel = _rel(path, repo)
    for section in ("default", "develop"):
        for name, meta in (data.get(section) or {}).items():
            ver = (meta or {}).get("version", "")
            m = re.match(r"==\s*([A-Za-z0-9._+!-]+)$", ver or "")
            if m:
                deps.append(Dep("PyPI", normalize_pypi(name), m.group(1), rel, _line_of(text, f'"{name}"')))
    return deps


def parse_poetry_lock(path: str, repo: str) -> list[Dep]:
    # Light TOML reader (no tomllib needed): walk [[package]] blocks.
    deps = []
    text = _read(path)
    if text is None:
        return deps
    rel = _rel(path, repo)
    name = ver = None
    start = 0
    in_pkg = False
    for i, raw in enumerate(text.splitlines(), 1):
        s = raw.strip()
        if s == "[[package]]":
            if name and ver:
                deps.append(Dep("PyPI", normalize_pypi(name), ver, rel, start))
            name = ver = None
            start = i
            in_pkg = True
            continue
        if s.startswith("[") and s != "[[package]]":
            in_pkg = False
        if not in_pkg:
            continue
        mn = re.match(r'name\s*=\s*"([^"]+)"', s)
        mv = re.match(r'version\s*=\s*"([^"]+)"', s)
        if mn:
            name = mn.group(1)
        elif mv:
            ver = mv.group(1)
    if name and ver:
        deps.append(Dep("PyPI", normalize_pypi(name), ver, rel, start))
    return deps


def _pyproject_requirement_strings(text: str) -> list[str]:
    """PEP 621 ``[project] dependencies`` + ``[project.optional-dependencies]`` strings."""
    try:
        import tomllib  # Python 3.11+
    except ImportError:  # pragma: no cover - 3.10 fallback below
        tomllib = None
    if tomllib is not None:
        try:
            data = tomllib.loads(text)
        except (ValueError, TypeError):
            return []
        proj = data.get("project") or {}
        out = [d for d in proj.get("dependencies") or [] if isinstance(d, str)]
        for group in (proj.get("optional-dependencies") or {}).values():
            out += [d for d in group or [] if isinstance(d, str)]
        return out
    # Minimal fallback (3.10): collect quoted strings of arrays inside the two relevant tables.
    out: list[str] = []
    table = ""
    in_array = False
    for raw in text.splitlines():
        s = raw.split("#", 1)[0].strip() if not in_array else raw.strip()
        th = re.match(r"^\[([^\[\]]+)\]$", s)
        if th and not in_array:
            table = th.group(1).strip()
            continue
        if not in_array:
            want = (table == "project" and re.match(r"^dependencies\s*=\s*\[", s)) or (
                table == "project.optional-dependencies" and re.match(r"^[\w.-]+\s*=\s*\[", s)
            )
            if not want:
                continue
            in_array = True
            s = s.split("[", 1)[1]
        out += re.findall(r"""["']([^"']+)["']""", s.split("]", 1)[0])
        if "]" in s:
            in_array = False
    return out


def _pyproject(path: str, repo: str):
    deps: list[Dep] = []
    unpinned: list[Unpinned] = []
    text = _read(path)
    if not text:
        return deps, unpinned
    rel = _rel(path, repo)
    for req in _pyproject_requirement_strings(text):
        parsed = _parse_pep508(req)
        if not parsed:
            continue
        name, ver, rest = parsed
        line = _line_of(text, req)
        if ver:
            deps.append(Dep("PyPI", normalize_pypi(name), ver, rel, line))
        elif not rest.startswith("@"):
            unpinned.append(Unpinned("PyPI", normalize_pypi(name), rest or "(any)", rel, line))
    return deps, unpinned


def parse_pyproject(path: str, repo: str) -> list[Dep]:
    return _pyproject(path, repo)[0]


# --------------------------------------------------------------------------- npm
_SEMVER_EXACT = re.compile(r"^[=v]?(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?)$")
_NPM_NON_REGISTRY = ("file:", "link:", "workspace:", "portal:", "git", "http:", "https:", "github:", "npm:")


def parse_package_lock(path: str, repo: str) -> list[Dep]:
    deps = []
    text = _read(path)
    try:
        data = json.loads(text or "")
    except ValueError:
        return deps
    rel = _rel(path, repo)
    seen = set()

    def _add(name, ver, line=0):
        if name and ver and re.match(r"^[0-9]+\.[0-9]+", str(ver)) and (name, ver) not in seen:
            seen.add((name, ver))
            deps.append(Dep("npm", name, ver, rel, line))

    # lockfileVersion 2/3: "packages": { "node_modules/<name>": {version} }
    for pkgpath, meta in (data.get("packages") or {}).items():
        meta = meta or {}
        # "" is the root project; entries without node_modules/ are workspace/local folders;
        # link entries point at those folders — none are registry packages.
        if not pkgpath or "node_modules/" not in pkgpath or meta.get("link"):
            continue
        name = pkgpath.rsplit("node_modules/", 1)[-1]
        _add(name, meta.get("version"), _line_of(text, f'"{pkgpath}"'))

    # lockfileVersion 1: nested "dependencies"
    def _walk(d):
        for name, meta in (d or {}).items():
            meta = meta or {}
            ver = str(meta.get("version") or "")
            if not ver.startswith(_NPM_NON_REGISTRY):
                _add(name, ver)
            _walk(meta.get("dependencies"))

    if not data.get("packages"):
        _walk(data.get("dependencies"))
    return deps


def _package_json(path: str, repo: str):
    deps: list[Dep] = []
    unpinned: list[Unpinned] = []
    text = _read(path)
    try:
        data = json.loads(text or "")
    except ValueError:
        return deps, unpinned
    if not isinstance(data, dict):
        return deps, unpinned
    rel = _rel(path, repo)
    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        for name, spec in (data.get(section) or {}).items():
            if not isinstance(spec, str):
                continue
            spec = spec.strip()
            line = _line_of(text, f'"{name}"')
            if spec.startswith(_NPM_NON_REGISTRY) or "/" in spec:
                continue  # local / git / alias — not a registry version
            m = _SEMVER_EXACT.match(spec)
            if m:
                deps.append(Dep("npm", name, m.group(1), rel, line))
            else:
                unpinned.append(Unpinned("npm", name, spec or "(any)", rel, line))
    return deps, unpinned


def parse_package_json(path: str, repo: str) -> list[Dep]:
    return _package_json(path, repo)[0]


def parse_yarn_lock(path: str, repo: str) -> list[Dep]:
    """yarn.lock v1 (``version "x"``) and Berry (``version: x``) — best effort."""
    deps = []
    text = _read(path)
    if text is None:
        return deps
    rel = _rel(path, repo)
    name, start = None, 0
    for i, raw in enumerate(text.splitlines(), 1):
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        if not raw[0].isspace() and raw.rstrip().endswith(":"):
            first = raw.rstrip()[:-1].split(",")[0].strip().strip('"').strip("'")
            at = first.rfind("@")
            name = first[:at] if at > 0 else None
            spec = first[at + 1 :] if at > 0 else ""
            if name == "__metadata" or any(
                spec.startswith(p) for p in ("workspace:", "link:", "portal:", "file:")
            ):
                name = None
            start = i
            continue
        m = re.match(r'^\s+version:?\s+"?([^"\s]+)"?\s*$', raw)
        if m and name and re.match(r"^\d+\.\d+", m.group(1)):
            deps.append(Dep("npm", name, m.group(1), rel, start))
            name = None
    return deps


def parse_pnpm_lock(path: str, repo: str) -> list[Dep]:
    """pnpm-lock.yaml v5 / v6 / v9 ``packages:`` keys — best effort, no YAML parser."""
    deps = []
    text = _read(path)
    if text is None:
        return deps
    rel = _rel(path, repo)
    in_pkgs = False
    seen = set()
    for i, raw in enumerate(text.splitlines(), 1):
        if re.match(r"^\S", raw):
            in_pkgs = raw.strip() == "packages:"
            continue
        if not in_pkgs:
            continue
        m = re.match(r"^  (\S.*?):\s*$", raw)
        if not m:
            continue
        key = m.group(1).strip().strip("'\"").lstrip("/")
        key = re.sub(r"\(.*$", "", key)  # v6/v9 peer suffix "(react@18.0.0)"
        at = key.rfind("@")
        if at > 0:
            name, ver = key[:at], key[at + 1 :]
        elif "/" in key:  # v5: /name/1.2.3 or /@scope/name/1.2.3
            name, ver = key.rsplit("/", 1)
        else:
            continue
        ver = ver.split("_", 1)[0]  # v5 peer suffix "1.0.0_react@18.0.0"
        if re.match(r"^\d+\.\d+", ver) and (name, ver) not in seen:
            seen.add((name, ver))
            deps.append(Dep("npm", name, ver, rel, i))
    return deps


# --------------------------------------------------------------------------- Go
def parse_go_sum(path: str, repo: str) -> list[Dep]:
    """Fallback only (no go.mod alongside): go.sum lists every version consulted during module
    resolution, not just the selected build list, so report the highest version per module."""
    from .osv import _version_key

    text = _read(path)
    if text is None:
        return []
    rel = _rel(path, repo)
    best: dict[str, tuple[str, int]] = {}
    for i, raw in enumerate(text.splitlines(), 1):
        m = re.match(r"^(\S+)\s+(v\S+?)(/go\.mod)?\s+h1:", raw)
        if not m:
            continue
        name, ver = m.group(1), m.group(2)
        cur = best.get(name)
        if cur is None or _version_key(ver, "Go") > _version_key(cur[0], "Go"):
            best[name] = (ver, i)
    return [Dep("Go", n, v, rel, ln) for n, (v, ln) in best.items()]


def _go_directive_lines(text: str, keyword: str):
    """Yield (line_no, body) for single-line and block forms of a go.mod directive."""
    in_block = False
    for i, raw in enumerate(text.splitlines(), 1):
        s = raw.split("//", 1)[0].strip()
        if not s:
            continue
        if re.match(rf"^{keyword}\s*\($", s):
            in_block = True
            continue
        if in_block:
            if s == ")":
                in_block = False
                continue
            yield i, s
        elif s.startswith(keyword + " "):
            yield i, s[len(keyword) :].strip()


def parse_go_mod(path: str, repo: str) -> list[Dep]:
    """The module's build requirements from go.mod, with ``replace`` directives applied."""
    text = _read(path)
    if text is None:
        return []
    rel = _rel(path, repo)
    reqs: list[list] = []  # [name, version, line]
    for i, body in _go_directive_lines(text, "require"):
        m = re.match(r"^(\S+)\s+(v\S+)", body)
        if m:
            reqs.append([m.group(1), m.group(2), i])
    replaces = []  # (old, old_ver|None, new, new_ver|None)
    for _i, body in _go_directive_lines(text, "replace"):
        m = re.match(r"^(\S+)(?:\s+(v\S+))?\s*=>\s*(\S+)(?:\s+(v\S+))?$", body)
        if m:
            replaces.append(m.groups())
    deps = []
    for name, ver, line in reqs:
        for old, old_ver, new, new_ver in replaces:
            if old == name and (old_ver is None or old_ver == ver):
                if new_ver is None:  # local filesystem replacement — not a registry module
                    name = ""
                else:
                    name, ver = new, new_ver
                break
        if name:
            deps.append(Dep("Go", name, ver, rel, line))
    return deps


# --------------------------------------------------------------------------- RubyGems
def parse_gemfile_lock(path: str, repo: str) -> list[Dep]:
    deps = []
    text = _read(path)
    if text is None:
        return deps
    rel = _rel(path, repo)
    for i, raw in enumerate(text.splitlines(), 1):
        # Gemfile.lock pins resolved gems at 4-space indent: "    name (1.2.3)".
        m = re.match(r"^\s{4}([A-Za-z0-9_.-]+) \(([^)]+)\)", raw)
        if m and not re.search(r"[<>=~]", m.group(2)):
            deps.append(Dep("RubyGems", m.group(1), m.group(2), rel, i))
    return deps


# --------------------------------------------------------------------------- crates.io
def parse_cargo_lock(path: str, repo: str) -> list[Dep]:
    deps = []
    text = _read(path)
    if text is None:
        return deps
    rel = _rel(path, repo)
    name = ver = None
    start = 0
    in_pkg = False
    for i, raw in enumerate(text.splitlines(), 1):
        s = raw.strip()
        if s == "[[package]]":
            if name and ver:
                deps.append(Dep("crates.io", name, ver, rel, start))
            name = ver = None
            start = i
            in_pkg = True
            continue
        if not in_pkg:
            continue
        mn = re.match(r'name\s*=\s*"([^"]+)"', s)
        mv = re.match(r'version\s*=\s*"([^"]+)"', s)
        if mn:
            name = mn.group(1)
        elif mv:
            ver = mv.group(1)
    if name and ver:
        deps.append(Dep("crates.io", name, ver, rel, start))
    return deps


# --------------------------------------------------------------------------- Maven
def parse_pom(path: str, repo: str) -> list[Dep]:
    import xml.etree.ElementTree as ET

    deps = []
    try:
        tree = ET.parse(path)
    except (OSError, ET.ParseError):
        return deps
    text = _read(path) or ""
    rel = _rel(path, repo)
    root = tree.getroot()
    ns = ""
    if root.tag.startswith("{"):
        ns = root.tag[: root.tag.index("}") + 1]
    props = {}
    pr = root.find(f"{ns}properties")
    if pr is not None:
        for el in list(pr):
            props[el.tag.replace(ns, "")] = (el.text or "").strip()
    for dep in root.iter(f"{ns}dependency"):
        gid = dep.findtext(f"{ns}groupId", "").strip()
        aid = dep.findtext(f"{ns}artifactId", "").strip()
        ver = dep.findtext(f"{ns}version", "").strip()
        m = re.match(r"\$\{([^}]+)\}", ver)
        if m:
            ver = props.get(m.group(1), "")
        if gid and aid and ver and "${" not in ver and not ver.startswith(("[", "(")):
            deps.append(
                Dep("Maven", f"{gid}:{aid}", ver, rel, _line_of(text, f"<artifactId>{aid}</artifactId>"))
            )
    return deps


# ------------------------------------------------------------------------------ discovery
# Manifest file name -> parser (requirements files and pyproject are matched by pattern below).
_MANIFESTS = {
    "Pipfile.lock": parse_pipfile_lock,
    "poetry.lock": parse_poetry_lock,
    "pyproject.toml": parse_pyproject,
    "package-lock.json": parse_package_lock,
    "npm-shrinkwrap.json": parse_package_lock,
    "package.json": parse_package_json,
    "yarn.lock": parse_yarn_lock,
    "pnpm-lock.yaml": parse_pnpm_lock,
    "go.mod": parse_go_mod,
    "go.sum": parse_go_sum,
    "Gemfile.lock": parse_gemfile_lock,
    "Cargo.lock": parse_cargo_lock,
    "pom.xml": parse_pom,
}
_NPM_LOCKS = ("package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml")

_SKIP_DIRS = {".git", "__pycache__", "node_modules", ".venv", "venv", ".rampart", "dist", "build"}

# Notes from the most recent collect_dependencies() call (e.g. manifest cap reached).
last_collect_notes: list[str] = []


def _parser_for(fn: str, files: list[str]):
    if fn == "go.sum" and "go.mod" in files:
        return None  # go.mod (+ replace directives) is the authoritative build list
    if fn in _MANIFESTS:
        return _MANIFESTS[fn]
    if _is_requirements_file(fn) or fn.lower().endswith(".txt"):
        return parse_requirements
    return None


def _walk_manifests(repo_path: str, max_files: int):
    scanned = 0
    for root, dirs, files in os.walk(repo_path):
        dirs[:] = sorted(d for d in dirs if d not in _SKIP_DIRS)
        # lockfiles first so their (resolved) versions win the de-dup over looser manifests
        order = sorted(files, key=lambda n: (n in ("go.mod", "package.json", "pyproject.toml"), n))
        for fn in order:
            path = os.path.join(root, fn)
            if fn.lower().endswith(".txt") and not _is_requirements_file(path):
                continue
            parser = _parser_for(fn, files)
            if parser is None:
                continue
            scanned += 1
            if scanned > max_files:
                note = (
                    f"SCA manifest cap reached: parsed the first {max_files} manifests; the rest were skipped"
                )
                last_collect_notes.append(note)
                return
            yield root, fn, files, parser


def collect_dependencies(repo_path: str, max_files: int = 2000) -> list[Dep]:
    """Walk the repo, parse every recognised manifest, and return de-duplicated exact deps."""
    deps: list[Dep] = []
    last_collect_notes.clear()
    if not repo_path or not os.path.isdir(repo_path):
        return deps
    seen = set()
    for root, fn, _files, parser in _walk_manifests(repo_path, max_files):
        for d in parser(os.path.join(root, fn), repo_path):
            if d.key() not in seen and d.name and d.version:
                seen.add(d.key())
                deps.append(d)
    return deps


def collect_unpinned(repo_path: str, max_files: int = 2000) -> list[Unpinned]:
    """Declared-but-unpinned dependencies (ranges / wildcards / bare names) — not CVE-queryable.

    npm ranges in a package.json are only reported when no lockfile pins them in that directory.
    """
    out: list[Unpinned] = []
    if not repo_path or not os.path.isdir(repo_path):
        return out
    seen = set()
    for root, fn, files, parser in _walk_manifests(repo_path, max_files):
        path = os.path.join(root, fn)
        if parser is parse_requirements:
            items = _requirements(path, repo_path)[1]
        elif parser is parse_pyproject:
            items = _pyproject(path, repo_path)[1]
        elif parser is parse_package_json and not any(lock in files for lock in _NPM_LOCKS):
            items = _package_json(path, repo_path)[1]
        else:
            continue
        for u in items:
            k = (u.manifest, u.name, u.line)
            if k not in seen:
                seen.add(k)
                out.append(u)
    return out
