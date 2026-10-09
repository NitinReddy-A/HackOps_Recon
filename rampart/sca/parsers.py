"""Dependency-manifest parsers (stdlib only) that extract *exact* pinned versions.

Software Composition Analysis needs concrete ``name@version`` pairs to match against advisories;
version *ranges* (e.g. ``^1.2``) can't be matched to a specific CVE, so we parse only the lock /
pinned forms that resolve to one version. Each parser returns a list of ``Dep`` records tagged with
the OSV ecosystem, the manifest file, and the line number for the finding's ``affected_code``.
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


def _rel(path: str, repo: str) -> str:
    return os.path.relpath(path, repo).replace("\\", "/")


# --------------------------------------------------------------------------- PyPI
def parse_requirements(path: str, repo: str) -> list[Dep]:
    deps = []
    try:
        lines = open(path, encoding="utf-8", errors="ignore").read().splitlines()
    except OSError:
        return deps
    for i, raw in enumerate(lines, 1):
        s = raw.split("#", 1)[0].strip()
        if not s or s.startswith("-") or s.startswith("git+") or s.startswith("http"):
            continue
        # Only exact pins (== or ===) resolve to a single version we can match.
        m = re.match(r"^([A-Za-z0-9._-]+)\s*(?:\[[^\]]*\])?\s*===?\s*([A-Za-z0-9._+!-]+)", s)
        if m:
            deps.append(Dep("PyPI", m.group(1).lower(), m.group(2), _rel(path, repo), i))
    return deps


def parse_pipfile_lock(path: str, repo: str) -> list[Dep]:
    deps = []
    try:
        data = json.load(open(path, encoding="utf-8", errors="ignore"))
    except (OSError, ValueError):
        return deps
    rel = _rel(path, repo)
    for section in ("default", "develop"):
        for name, meta in (data.get(section) or {}).items():
            ver = (meta or {}).get("version", "")
            m = re.match(r"==\s*([A-Za-z0-9._+!-]+)", ver or "")
            if m:
                deps.append(Dep("PyPI", name.lower(), m.group(1), rel, 0))
    return deps


def parse_poetry_lock(path: str, repo: str) -> list[Dep]:
    # Light TOML reader (avoids a tomllib/py-version dependency): walk [[package]] blocks.
    deps = []
    try:
        lines = open(path, encoding="utf-8", errors="ignore").read().splitlines()
    except OSError:
        return deps
    rel = _rel(path, repo)
    name = ver = None
    start = 0
    in_pkg = False
    for i, raw in enumerate(lines, 1):
        s = raw.strip()
        if s == "[[package]]":
            if name and ver:
                deps.append(Dep("PyPI", name.lower(), ver, rel, start))
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
        deps.append(Dep("PyPI", name.lower(), ver, rel, start))
    return deps


# --------------------------------------------------------------------------- npm
def parse_package_lock(path: str, repo: str) -> list[Dep]:
    deps = []
    try:
        data = json.load(open(path, encoding="utf-8", errors="ignore"))
    except (OSError, ValueError):
        return deps
    rel = _rel(path, repo)
    seen = set()

    def _add(name, ver):
        if name and ver and re.match(r"^[0-9]+\.[0-9]+", str(ver)) and (name, ver) not in seen:
            seen.add((name, ver))
            deps.append(Dep("npm", name, ver, rel, 0))

    # lockfileVersion 2/3: "packages": { "node_modules/<name>": {version} }
    for pkgpath, meta in (data.get("packages") or {}).items():
        if not pkgpath:
            continue  # the root project itself
        name = pkgpath.split("node_modules/")[-1]
        _add(name, (meta or {}).get("version"))

    # lockfileVersion 1: nested "dependencies"
    def _walk(d):
        for name, meta in (d or {}).items():
            _add(name, (meta or {}).get("version"))
            _walk((meta or {}).get("dependencies"))

    _walk(data.get("dependencies"))
    return deps


# --------------------------------------------------------------------------- Go
def parse_go_sum(path: str, repo: str) -> list[Dep]:
    deps = []
    try:
        lines = open(path, encoding="utf-8", errors="ignore").read().splitlines()
    except OSError:
        return deps
    rel = _rel(path, repo)
    seen = set()
    for i, raw in enumerate(lines, 1):
        m = re.match(r"^(\S+)\s+v(\S+?)(?:/go\.mod)?\s+h1:", raw)
        if m:
            name, ver = m.group(1), m.group(2)
            if (name, ver) not in seen:
                seen.add((name, ver))
                deps.append(Dep("Go", name, "v" + ver, rel, i))
    return deps


def parse_go_mod(path: str, repo: str) -> list[Dep]:
    deps = []
    try:
        lines = open(path, encoding="utf-8", errors="ignore").read().splitlines()
    except OSError:
        return deps
    rel = _rel(path, repo)
    in_block = False
    for i, raw in enumerate(lines, 1):
        s = raw.strip()
        if s.startswith("require ("):
            in_block = True
            continue
        if in_block and s == ")":
            in_block = False
            continue
        if s.startswith("require ") and not s.startswith("require ("):
            body = s[len("require ") :].strip()
        elif in_block:
            body = s
        else:
            continue
        m = re.match(r"^(\S+)\s+v(\S+)", body)
        if m:
            deps.append(Dep("Go", m.group(1), "v" + m.group(2), rel, i))
    return deps


# --------------------------------------------------------------------------- RubyGems
def parse_gemfile_lock(path: str, repo: str) -> list[Dep]:
    deps = []
    try:
        lines = open(path, encoding="utf-8", errors="ignore").read().splitlines()
    except OSError:
        return deps
    rel = _rel(path, repo)
    for i, raw in enumerate(lines, 1):
        # Gemfile.lock pins resolved gems at 4-space indent: "    name (1.2.3)".
        m = re.match(r"^\s{4}([A-Za-z0-9_.-]+) \(([^)]+)\)", raw)
        if m and not re.search(r"[<>=~]", m.group(2)):
            deps.append(Dep("RubyGems", m.group(1), m.group(2), rel, i))
    return deps


# --------------------------------------------------------------------------- crates.io
def parse_cargo_lock(path: str, repo: str) -> list[Dep]:
    deps = []
    try:
        lines = open(path, encoding="utf-8", errors="ignore").read().splitlines()
    except OSError:
        return deps
    rel = _rel(path, repo)
    name = ver = None
    start = 0
    in_pkg = False
    for i, raw in enumerate(lines, 1):
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
        if gid and aid and ver and "${" not in ver:
            deps.append(Dep("Maven", f"{gid}:{aid}", ver, rel, 0))
    return deps


# Manifest file name -> parser
_MANIFESTS = {
    "requirements.txt": parse_requirements,
    "Pipfile.lock": parse_pipfile_lock,
    "poetry.lock": parse_poetry_lock,
    "package-lock.json": parse_package_lock,
    "go.sum": parse_go_sum,
    "go.mod": parse_go_mod,
    "Gemfile.lock": parse_gemfile_lock,
    "Cargo.lock": parse_cargo_lock,
    "pom.xml": parse_pom,
}

_SKIP_DIRS = {".git", "__pycache__", "node_modules", ".venv", "venv", ".rampart", "dist", "build"}


def collect_dependencies(repo_path: str, max_files: int = 2000) -> list[Dep]:
    """Walk the repo, parse every recognised manifest, and return de-duplicated exact deps.

    When both a lockfile and its looser manifest exist (go.sum + go.mod), the lockfile wins by
    being parsed first; duplicates by (ecosystem, name, version) are collapsed.
    """
    deps: list[Dep] = []
    if not repo_path or not os.path.isdir(repo_path):
        return deps
    seen = set()
    scanned = 0
    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
        # Parse lockfiles before their loose manifests for the same ecosystem.
        for fn in sorted(files, key=lambda n: (n == "go.mod", n)):
            parser = _MANIFESTS.get(fn)
            if parser is None:
                continue
            scanned += 1
            if scanned > max_files:
                return deps
            for d in parser(os.path.join(root, fn), repo_path):
                if d.key() not in seen and d.name and d.version:
                    seen.add(d.key())
                    deps.append(d)
    return deps
