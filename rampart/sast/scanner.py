"""Native, dependency-free Python source scanner (stdlib ``ast``).

High-signal sink patterns only, and — to keep false positives low — a risky call is flagged
only when its dangerous argument is NON-CONSTANT (i.e. could carry tainted input) and, for the
noisier sinks (file paths, SQL), only when the argument is *shaped* like injection: a string built
from dynamic parts, or an identifier that looks request-derived. Each hit is a STATIC finding
(``method='static-analysis'``, not ``validated``); it is correlated with runtime DAST findings by
CWE to raise confidence.

Analysis is purely structural (AST node types + identifier names), never ``ast.dump`` text, so
results do not depend on the running Python version.
"""

from __future__ import annotations

import ast
import io
import logging
import os
import re
import tokenize

from ..schemas.finding import AffectedCode, Finding, Remediation, Reproduction, State, Verification
from ..util import now_iso

_log = logging.getLogger(__name__)

_SKIP_DIRS = {".git", "__pycache__", "node_modules", ".venv", "venv", ".rampart", "dist", "build"}

# Notes from the most recent scan_source() call (e.g. "file cap hit"), for callers that want to
# surface coverage limits. Reset on every call.
last_scan_notes: list[str] = []


# --------------------------------------------------------------------------- name helpers
def _call_name(func) -> str:
    """Dotted name for a call target: subprocess.run, os.system, cursor.execute, eval, …"""
    parts = []
    node = func
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


def _collect_aliases(tree) -> dict[str, str]:
    """Local name -> fully-qualified module/symbol for every import in the module.

    ``import pickle as pk`` -> {"pk": "pickle"}; ``from subprocess import run`` -> {"run":
    "subprocess.run"}; ``from yaml import load as yload`` -> {"yload": "yaml.load"}.
    """
    out: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.asname:
                    out[a.asname] = a.name
        elif isinstance(node, ast.ImportFrom):
            if node.level or not node.module:
                continue
            for a in node.names:
                if a.name != "*":
                    out[a.asname or a.name] = f"{node.module}.{a.name}"
    return out


def _resolve(name: str, aliases: dict[str, str]) -> str:
    if not name:
        return name
    head, _, rest = name.partition(".")
    full = aliases.get(head)
    if not full:
        return name
    return f"{full}.{rest}" if rest else full


def _nonconst(node) -> bool:
    return node is not None and not isinstance(node, ast.Constant)


def _kw(call, name):
    for k in call.keywords:
        if k.arg == name:
            return k.value
    return None


def _identifiers(node) -> list[str]:
    """Every Name.id / Attribute.attr inside an expression (structural walk, no text matching)."""
    out = []
    for n in ast.walk(node):
        if isinstance(n, ast.Name):
            out.append(n.id)
        elif isinstance(n, ast.Attribute):
            out.append(n.attr)
    return out


def _tokens(ident: str) -> list[str]:
    return [t for t in re.split(r"_+", re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", ident).lower()) if t]


# Identifiers that look like they carry request / user-controlled input.
_REQ_TOKENS = {"request", "req", "params", "param", "query", "form", "input", "upload", "uploaded"}


def _request_shaped(node) -> bool:
    for ident in _identifiers(node):
        low = ident.lower()
        if low.startswith("user_") or low.startswith("userinput"):
            return True
        if any(t in _REQ_TOKENS for t in _tokens(ident)):
            return True
    return False


# Names that hold SQL placeholder markup ("?, ?, ?" / "%s"), not data — the standard safe idiom.
_PLACEHOLDER_NAMES = {"ph", "placeholder", "placeholders", "qmarks", "marks", "param_marks", "binds"}


def _const_like(node) -> bool:
    """Constant, or a name we can treat as non-tainted (ALL_CAPS module constant / placeholder)."""
    if isinstance(node, ast.Constant):
        return True
    if isinstance(node, ast.Name):
        return (node.id.isupper() and len(node.id) > 1) or node.id.lower() in _PLACEHOLDER_NAMES
    if isinstance(node, ast.Attribute):
        return node.attr.isupper() and len(node.attr) > 1
    if isinstance(node, ast.JoinedStr):
        return all(_const_like(v) for v in node.values)
    if isinstance(node, ast.FormattedValue):
        return _const_like(node.value)
    if isinstance(node, ast.BinOp):
        return _const_like(node.left) and _const_like(node.right)
    if isinstance(node, (ast.Tuple, ast.List)):
        return all(_const_like(e) for e in node.elts)
    return False


def _dynamic_string(node) -> bool:
    """A string built from at least one non-constant part (f-string / + / % / .format)."""
    if isinstance(node, ast.JoinedStr):
        return any(isinstance(v, ast.FormattedValue) and not _const_like(v.value) for v in node.values)
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        if not (_stringish(node.left) or _stringish(node.right)):
            return False
        return not (_const_like(node.left) and _const_like(node.right))
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
        args = list(node.args) + [k.value for k in node.keywords]
        return bool(args) and not all(_const_like(a) for a in args)
    return False


def _stringish(node) -> bool:
    if isinstance(node, ast.Constant):
        return isinstance(node.value, str)
    if isinstance(node, ast.JoinedStr):
        return True
    if isinstance(node, ast.BinOp):
        return _stringish(node.left) or _stringish(node.right)
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
        return True
    return isinstance(node, (ast.Name, ast.Attribute, ast.Subscript, ast.Call))


_SQL_RE = re.compile(r"(?i)\b(select|insert|update|delete|create|drop|alter|replace|merge|pragma|with)\b")


def _const_text(node) -> str:
    """Concatenated constant string fragments inside an expression."""
    return " ".join(
        n.value for n in ast.walk(node) if isinstance(n, ast.Constant) and isinstance(n.value, str)
    )


_DB_RECEIVERS = {"cursor", "cur", "conn", "connection", "db", "database", "session", "engine", "con", "cnx"}


def _db_receiver(func) -> bool:
    if not isinstance(func, ast.Attribute):
        return False
    recv = func.value
    if isinstance(recv, ast.Call):  # conn.cursor().execute(...)
        recv = recv.func
    ident = recv.attr if isinstance(recv, ast.Attribute) else getattr(recv, "id", "")
    toks = _tokens(ident or "")
    return any(t in _DB_RECEIVERS for t in toks) or (ident or "").lower().endswith(("cursor", "conn", "db"))


_UNSAFE_YAML_LOADERS = {"Loader", "FullLoader", "UnsafeLoader", "CLoader", "CFullLoader", "CUnsafeLoader"}
_SAFE_YAML_LOADERS = {"SafeLoader", "CSafeLoader", "BaseLoader", "CBaseLoader"}

_SHELL_FUNCS = {
    "subprocess.run",
    "subprocess.call",
    "subprocess.Popen",
    "subprocess.check_output",
    "subprocess.check_call",
}
_OS_CMD_FUNCS = {
    "os.system",
    "os.popen",
    "os.popen2",
    "commands.getoutput",
    "subprocess.getoutput",
    "subprocess.getstatusoutput",
}
_DESER_FUNCS = {
    "pickle.loads",
    "pickle.load",
    "pickle.Unpickler",
    "cPickle.loads",
    "cPickle.load",
    "_pickle.loads",
    "dill.loads",
    "dill.load",
    "marshal.loads",
    "marshal.load",
    "shelve.open",
}
_SSRF_FUNCS = {
    "requests.get",
    "requests.post",
    "requests.put",
    "requests.request",
    "requests.head",
    "urllib.request.urlopen",
    "httpx.get",
    "httpx.post",
    "aiohttp.request",
}


def _fixed_host_url(node) -> bool:
    """An URL whose scheme+host are pinned by a leading constant (f"https://api.x/{id}")."""
    first = None
    if isinstance(node, ast.JoinedStr) and node.values:
        first = node.values[0]
        if isinstance(first, ast.FormattedValue):
            first = first.value
    elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = node.left
        while isinstance(left, ast.BinOp) and isinstance(left.op, ast.Add):
            left = left.left
        first = left
    if isinstance(first, ast.Constant) and isinstance(first.value, str):
        return bool(re.match(r"(?i)^https?://[^/?#{}\s:@]+", first.value))
    if isinstance(first, ast.Name):
        return first.id.isupper()
    return False


class _Visitor(ast.NodeVisitor):
    def __init__(self, aliases: dict[str, str] | None = None):
        self.hits = []  # (lineno, end, cwe, severity, vuln_class, title, desc, remediation)
        self.aliases = aliases or {}
        # Stack of per-scope assignment tables: name -> [(lineno, value_node, is_aug)]
        self._scopes: list[dict] = [{}]

    def _add(self, node, cwe, sev, klass, title, desc, rem):
        self.hits.append(
            (node.lineno, getattr(node, "end_lineno", node.lineno), cwe, sev, klass, title, desc, rem)
        )

    # ---- scope tracking (simple intra-function var -> string-built value) ----
    @staticmethod
    def _assignments(body_nodes) -> dict:
        table: dict = {}
        stack = list(body_nodes)
        while stack:
            n = stack.pop()
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
                continue
            if isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name):
                table.setdefault(n.targets[0].id, []).append((n.lineno, n.value, False))
            elif isinstance(n, ast.AnnAssign) and isinstance(n.target, ast.Name) and n.value is not None:
                table.setdefault(n.target.id, []).append((n.lineno, n.value, False))
            elif isinstance(n, ast.AugAssign) and isinstance(n.target, ast.Name):
                table.setdefault(n.target.id, []).append((n.lineno, n.value, True))
            stack.extend(ast.iter_child_nodes(n))
        return table

    def visit_Module(self, node):
        self._scopes = [self._assignments(node.body)]
        self.generic_visit(node)

    def _enter(self, node):
        self._scopes.append(self._assignments(node.body))
        self.generic_visit(node)
        self._scopes.pop()

    visit_FunctionDef = _enter
    visit_AsyncFunctionDef = _enter

    def _string_built_var(self, name_node, before_line: int) -> ast.AST | None:
        """If ``name_node`` is a local assigned from a dynamic string before ``before_line``, return
        that value expression (the SQL text it was built from)."""
        if not isinstance(name_node, ast.Name):
            return None
        entries = [e for e in self._scopes[-1].get(name_node.id, []) if e[0] <= before_line]
        if not entries:
            return None
        entries.sort(key=lambda e: e[0])
        # any dynamic append (q += uid) or a dynamic last assignment taints the variable
        built = base = None
        for _ln, val, aug in entries:
            if not aug:
                base = val
                built = val if _dynamic_string(val) else None
            elif not _const_like(val) and built is None:
                built = ast.BinOp(
                    left=base if base is not None else ast.Constant(""), op=ast.Add(), right=val
                )
        return built

    # ---- sinks ----
    def visit_Call(self, node):
        raw = _call_name(node.func)
        name = _resolve(raw, self.aliases)
        last = name.split(".")[-1]
        a0 = node.args[0] if node.args else None

        if name in _OS_CMD_FUNCS and _nonconst(a0):
            self._add(
                node,
                "CWE-78",
                "high",
                "sast-command-injection",
                "OS command built from a non-literal value",
                f"{name}(...) is called with a non-constant argument — OS command injection risk.",
                "Avoid the shell; pass an argument vector (execve-style) and validate input.",
            )
        elif name in _SHELL_FUNCS or last == "Popen":
            shell = _kw(node, "shell")
            cmd = a0 if a0 is not None else _kw(node, "args")
            if (
                isinstance(shell, ast.Constant)
                and shell.value is True
                and _nonconst(cmd)
                and not _const_like(cmd)
            ):
                self._add(
                    node,
                    "CWE-78",
                    "high",
                    "sast-command-injection",
                    "subprocess called with shell=True",
                    "subprocess(..., shell=True) runs a non-constant command through the shell — "
                    "command injection risk.",
                    "Use shell=False with an argument list; never build shell strings from input.",
                )
        elif name in ("eval", "exec") and raw in ("eval", "exec") and _nonconst(a0):
            self._add(
                node,
                "CWE-95",
                "high",
                "sast-code-injection",
                f"{name}() on a non-literal value",
                f"{name}() evaluates a non-constant expression — code injection / RCE risk.",
                "Never eval/exec untrusted input; use a safe parser or an explicit dispatch table.",
            )
        elif name in _DESER_FUNCS:
            self._add(
                node,
                "CWE-502",
                "high",
                "sast-insecure-deserialization",
                f"Insecure deserialization via {name}",
                f"{name}() deserializes data that may be attacker-controlled — RCE risk.",
                "Do not deserialize untrusted data; use a safe format (JSON) with a schema.",
            )
        elif name in ("yaml.load", "yaml.load_all") and self._unsafe_yaml_loader(node):
            self._add(
                node,
                "CWE-502",
                "high",
                "sast-insecure-deserialization",
                "yaml.load without SafeLoader",
                "yaml.load() without Loader=SafeLoader can construct arbitrary objects — RCE risk.",
                "Use yaml.safe_load() or pass Loader=yaml.SafeLoader.",
            )
        elif name in ("yaml.unsafe_load", "yaml.unsafe_load_all", "yaml.full_load", "yaml.full_load_all"):
            self._add(
                node,
                "CWE-502",
                "high",
                "sast-insecure-deserialization",
                f"Unsafe YAML deserialization via {name}",
                f"{name}() uses a loader that can construct arbitrary Python objects — RCE risk.",
                "Use yaml.safe_load() (SafeLoader) for any data that is not fully trusted.",
            )
        elif last in ("execute", "executemany", "executescript") and self._sql_injection(node, a0):
            self._add(
                node,
                "CWE-89",
                "high",
                "sast-sql-injection",
                "SQL statement built by string formatting",
                "A SQL statement is constructed with f-string/concatenation/.format and executed — SQLi risk.",
                "Use parameterized queries (bound parameters), never string interpolation.",
            )
        elif name in ("hashlib.md5", "hashlib.sha1"):
            ufs = _kw(node, "usedforsecurity")
            if not (isinstance(ufs, ast.Constant) and ufs.value is False):
                self._add(
                    node,
                    "CWE-327",
                    "low",
                    "sast-weak-crypto",
                    f"Weak hash function {name}",
                    f"{name}() is cryptographically weak; unsafe for passwords/signatures.",
                    "Use SHA-256+ for integrity and a slow KDF (bcrypt/scrypt/argon2) for passwords.",
                )
        elif name in _SSRF_FUNCS and _nonconst(a0) and not _const_like(a0) and not _fixed_host_url(a0):
            self._add(
                node,
                "CWE-918",
                "medium",
                "sast-ssrf",
                "Server-side request to a non-literal URL",
                f"{name}(...) fetches a non-constant URL — SSRF risk if it is user-controlled.",
                "Allow-list destinations; block internal/link-local/metadata ranges; disable redirects.",
            )
        elif name in ("open", "io.open", "codecs.open") and _nonconst(a0) and _request_shaped(a0):
            self._add(
                node,
                "CWE-22",
                "medium",
                "sast-path-traversal",
                "File opened from a non-literal, request-shaped path",
                "open(...) uses a dynamic, request-shaped path — path traversal risk.",
                "Canonicalise and contain the path within an allowed base directory; reject '..'.",
            )

        # Flask/werkzeug debug server
        if last == "run":
            dbg = _kw(node, "debug")
            if isinstance(dbg, ast.Constant) and dbg.value is True:
                self._add(
                    node,
                    "CWE-489",
                    "medium",
                    "sast-debug-enabled",
                    "Debug mode enabled (app.run(debug=True))",
                    "Running with debug=True exposes an interactive debugger / code execution.",
                    "Never enable debug in production; gate it behind an env flag.",
                )
        self.generic_visit(node)

    @staticmethod
    def _unsafe_yaml_loader(node) -> bool:
        loader = _kw(node, "Loader")
        if loader is None and len(node.args) >= 2:
            loader = node.args[1]
        if loader is None:
            return True  # PyYAML < 6 default loader is unsafe; >= 6 raises — flag either way
        lname = _call_name(loader).split(".")[-1]
        return lname in _UNSAFE_YAML_LOADERS

    def _sql_injection(self, node, a0) -> bool:
        if a0 is None:
            return False
        db = _db_receiver(node.func)
        built = a0 if _dynamic_string(a0) else self._string_built_var(a0, node.lineno)
        if built is not None:
            # String-built statement: require it to look like SQL or go to a DB-shaped receiver.
            return db or bool(_SQL_RE.search(_const_text(built)))
        # Not string-built: only a DB cursor fed a request-shaped value directly is suspicious.
        return db and _nonconst(a0) and _request_shaped(a0)


def _finding(engagement_id, repo, rel, lines, hit) -> Finding:
    lineno, end, cwe, sev, klass, title, desc, rem = hit
    snippet = "".join(lines[max(0, lineno - 1) : end]).rstrip()[:600]
    f = Finding(
        engagement_id=engagement_id,
        title=f"{title} ({rel}:{lineno})",
        vuln_class=klass,
        severity=sev,
        confidence="firm",
        state=State.EVIDENCE_FOUND,
        cwe=[cwe],
        owasp={"web_2025": ["A03:2025-Injection"]} if "injection" in klass else {},
        asset={"type": "source", "application": "", "environment": "authorized", "target": repo},
        description=desc,
        root_cause="Detected by static analysis of the source (AST sink pattern).",
        affected_code=AffectedCode(
            detected_by="rampart-sast-ast",
            repo=repo,
            file=rel,
            start_line=lineno,
            end_line=end,
            snippet=snippet,
        ),
        reproduction=Reproduction(
            prerequisites=["Source access"], steps=[f"Inspect {rel}:{lineno}"], deterministic=True
        ),
        remediation=Remediation(summary=rem, type="code_patch", guidance=rem, effort="medium"),
        references=[f"https://cwe.mitre.org/data/definitions/{cwe.split('-')[1]}.html"],
        compliance_control_refs=["SOC2:CC8.1"],
        dedupe_key=f"sast:{rel}:{lineno}:{cwe}",
        tags=["sast", "white-box", "static"],
        verification=Verification(
            method="static-analysis",
            validated=False,
            validated_at=now_iso(),
            validator="sast-ast",
            independent_reproduction=False,
            reproductions=0,
            false_positive_checks=[
                "static AST match — not runtime-proven; correlate with DAST / confirm manually"
            ],
            confidence_score=0.5,
        ),
    )
    return f


# ------------------------------------------------------------------------ diff-aware (--since)
def _git(repo_path: str, *args: str):
    import subprocess

    return subprocess.run(
        ["git", "-C", repo_path, "-c", "core.quotepath=off", *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
    )


def changed_py_files_status(repo_path: str, base_ref: str) -> tuple[set[str] | None, str]:
    """Diff-aware file selection for ``--since``.

    Returns ``(files, status)``. ``files`` are .py paths relative to ``repo_path`` (even when it is
    a sub-directory of the git work tree) that changed since ``base_ref`` — committed changes since
    the merge-base, plus uncommitted (staged/unstaged) edits and untracked files. ``status`` is one
    of ``ok`` | ``not-a-git-repo`` | ``invalid-ref`` | ``git-unavailable``; on anything but ``ok``
    ``files`` is None so the caller can warn and fall back to a full scan.
    """
    try:
        if not repo_path or not os.path.isdir(repo_path):
            return None, "not-a-git-repo"
        probe = _git(repo_path, "rev-parse", "--is-inside-work-tree")
        if probe.returncode != 0 or probe.stdout.strip() != "true":
            return None, "not-a-git-repo"
        if _git(repo_path, "rev-parse", "--verify", "--quiet", f"{base_ref}^{{commit}}").returncode != 0:
            return None, "invalid-ref"
        mb = _git(repo_path, "merge-base", base_ref, "HEAD")
        base = mb.stdout.strip() if mb.returncode == 0 and mb.stdout.strip() else base_ref
        # `git diff <base>` (no ...HEAD) compares against the WORKING TREE: committed + uncommitted.
        diff = _git(repo_path, "diff", "--name-only", "-z", "--relative", base)
        if diff.returncode != 0:
            return None, "invalid-ref"
        untracked = _git(repo_path, "ls-files", "--others", "--exclude-standard", "-z")
        names = [n for n in diff.stdout.split("\0") if n]
        if untracked.returncode == 0:
            names += [n for n in untracked.stdout.split("\0") if n]
        return {n.replace("\\", "/") for n in names if n.endswith(".py")}, "ok"
    except (OSError, ValueError, UnicodeError):
        return None, "git-unavailable"
    except Exception:  # noqa: BLE001 - e.g. TimeoutExpired; diff-awareness is best-effort
        return None, "git-unavailable"


def changed_py_files(repo_path: str, base_ref: str) -> set[str] | None:
    """Repo-relative .py files changed vs base_ref (diff-aware scanning). None if git/ref unavailable.

    The outcome is also recorded on ``changed_py_files.last_status`` (see
    :func:`changed_py_files_status`) so a caller can warn when the ref was invalid.
    """
    files, status = changed_py_files_status(repo_path, base_ref)
    changed_py_files.last_status = status
    return files


changed_py_files.last_status = ""


# --------------------------------------------------------------------------------- scanning
def _decode_source(raw: bytes) -> str:
    """Decode Python source bytes honouring a BOM / PEP 263 coding cookie (for snippets)."""
    try:
        enc, _ = tokenize.detect_encoding(io.BytesIO(raw).readline)
    except (SyntaxError, LookupError):
        enc = "utf-8"
    try:
        return raw.decode(enc, errors="replace").lstrip("\ufeff")
    except LookupError:
        return raw.decode("utf-8", errors="replace").lstrip("\ufeff")


# Inline suppressions a reviewer has already applied to this exact line: bandit's ``# nosec``, a
# ruff/flake8-bandit ``noqa`` S-code (e.g. S310), or Rampart's own ``# rampart: ignore``.
_SUPPRESS_RE = re.compile(r"#\s*(nosec\b|rampart:\s*ignore\b|noqa:[^#\n]*\bS\d{3}\b)", re.IGNORECASE)


def _suppressed(lines, start: int, end: int) -> bool:
    return any(_SUPPRESS_RE.search(ln) for ln in lines[max(0, start - 1) : max(start, end)])


def scan_source(
    repo_path: str, engagement_id: str = "", max_files: int = 2000, only_files: set | None = None
) -> list[Finding]:
    findings: list[Finding] = []
    last_scan_notes.clear()
    if not repo_path or not os.path.isdir(repo_path):
        return findings
    seen = 0
    skipped = 0
    for root, dirs, files in os.walk(repo_path):
        dirs[:] = sorted(d for d in dirs if d not in _SKIP_DIRS)
        for fn in sorted(files):
            if not fn.endswith(".py"):
                continue
            path = os.path.join(root, fn)
            if only_files is not None:
                rel = os.path.relpath(path, repo_path).replace("\\", "/")
                if rel not in only_files:
                    continue
            seen += 1
            if seen > max_files:
                note = f"SAST file cap reached: scanned the first {max_files} Python files; the rest were skipped"
                last_scan_notes.append(note)
                _log.warning(note)
                return findings
            try:
                with open(path, "rb") as fh:
                    raw = fh.read()
                # Parse BYTES so a UTF-8 BOM or a PEP 263 coding cookie (latin-1 …) is honoured.
                tree = ast.parse(raw, filename=path)
                v = _Visitor(_collect_aliases(tree))
                v.visit(tree)
            except (OSError, SyntaxError, ValueError, UnicodeError, RecursionError, MemoryError):
                # unreadable / invalid / pathologically deep source: skip this file, keep scanning
                skipped += 1
                continue
            lines = _decode_source(raw).splitlines(keepends=True)
            rel = os.path.relpath(path, repo_path).replace("\\", "/")
            for hit in v.hits:
                if _suppressed(lines, hit[0], hit[1]):
                    continue
                findings.append(_finding(engagement_id, repo_path, rel, lines, hit))
    if skipped:
        last_scan_notes.append(f"SAST skipped {skipped} unparseable Python file(s)")
    return findings
