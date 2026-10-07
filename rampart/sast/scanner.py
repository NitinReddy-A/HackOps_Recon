"""Native, dependency-free Python source scanner (stdlib ``ast``).

High-signal sink patterns only, and — to keep false positives low — a risky call is flagged
only when its dangerous argument is NON-CONSTANT (i.e. could carry tainted input). Each hit
is a STATIC finding (``method='static-analysis'``, not ``validated``); it is correlated with
runtime DAST findings by CWE to raise confidence.
"""
from __future__ import annotations

import ast
import os

from ..schemas.finding import AffectedCode, Finding, Reproduction, Remediation, State, Verification
from ..util import now_iso

_SKIP_DIRS = {".git", "__pycache__", "node_modules", ".venv", "venv", ".rampart", "dist", "build"}


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


def _nonconst(node) -> bool:
    return node is not None and not isinstance(node, ast.Constant)


def _kw(call, name):
    for k in call.keywords:
        if k.arg == name:
            return k.value
    return None


def _tainting_shape(node) -> bool:
    """A string built dynamically (f-string / concatenation / .format / %)—classic injection shape."""
    if isinstance(node, ast.JoinedStr):           # f"...{x}..."
        return True
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        return True
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
        return True
    return False


_HINT = ("request", "param", "path", "file", "name", "user", "input", "arg", "query", "data", "url")


def _hintish(node) -> bool:
    try:
        src = ast.dump(node).lower()
    except Exception:  # noqa: BLE001
        return False
    return any(h in src for h in _HINT)


class _Visitor(ast.NodeVisitor):
    def __init__(self):
        self.hits = []   # (lineno, end, cwe, severity, vuln_class, title, desc, remediation)

    def _add(self, node, cwe, sev, klass, title, desc, rem):
        self.hits.append((node.lineno, getattr(node, "end_lineno", node.lineno),
                          cwe, sev, klass, title, desc, rem))

    def visit_Call(self, node):
        name = _call_name(node.func)
        a0 = node.args[0] if node.args else None

        if name in ("os.system", "os.popen", "os.popen2", "commands.getoutput") and _nonconst(a0):
            self._add(node, "CWE-78", "high", "sast-command-injection",
                      "OS command built from a non-literal value",
                      f"{name}(...) is called with a non-constant argument — OS command injection risk.",
                      "Avoid the shell; pass an argument vector (execve-style) and validate input.")
        elif name.split(".")[-1] in ("run", "call", "Popen", "check_output", "check_call") and \
                ("subprocess" in name or name.endswith(("Popen",))):
            if isinstance(_kw(node, "shell"), ast.Constant) and _kw(node, "shell").value is True:
                self._add(node, "CWE-78", "high", "sast-command-injection",
                          "subprocess called with shell=True",
                          "subprocess(..., shell=True) enables shell interpretation — command injection risk.",
                          "Use shell=False with an argument list; never build shell strings from input.")
        elif name in ("eval", "exec") and _nonconst(a0):
            self._add(node, "CWE-95", "high", "sast-code-injection",
                      f"{name}() on a non-literal value",
                      f"{name}() evaluates a non-constant expression — code injection / RCE risk.",
                      "Never eval/exec untrusted input; use a safe parser or an explicit dispatch table.")
        elif name in ("pickle.loads", "pickle.load", "cPickle.loads", "marshal.loads", "shelve.open"):
            self._add(node, "CWE-502", "high", "sast-insecure-deserialization",
                      f"Insecure deserialization via {name}",
                      f"{name}() deserializes data that may be attacker-controlled — RCE risk.",
                      "Do not deserialize untrusted data; use a safe format (JSON) with a schema.")
        elif name in ("yaml.load",) and not any(k.arg == "Loader" for k in node.keywords):
            self._add(node, "CWE-502", "high", "sast-insecure-deserialization",
                      "yaml.load without SafeLoader",
                      "yaml.load() without Loader=SafeLoader can construct arbitrary objects — RCE risk.",
                      "Use yaml.safe_load() or pass Loader=yaml.SafeLoader.")
        elif name.split(".")[-1] in ("execute", "executemany") and (_tainting_shape(a0) or
                                                                     (_nonconst(a0) and _hintish(a0) and
                                                                      not isinstance(a0, ast.Name))):
            self._add(node, "CWE-89", "high", "sast-sql-injection",
                      "SQL statement built by string formatting",
                      "A SQL statement is constructed with f-string/concatenation/.format and executed — SQLi risk.",
                      "Use parameterized queries (bound parameters), never string interpolation.")
        elif name in ("hashlib.md5", "hashlib.sha1"):
            self._add(node, "CWE-327", "low", "sast-weak-crypto",
                      f"Weak hash function {name}",
                      f"{name}() is cryptographically weak; unsafe for passwords/signatures.",
                      "Use SHA-256+ for integrity and a slow KDF (bcrypt/scrypt/argon2) for passwords.")
        elif name in ("requests.get", "requests.post", "requests.request", "requests.head",
                      "urllib.request.urlopen", "httpx.get", "aiohttp.request") and _nonconst(a0):
            self._add(node, "CWE-918", "medium", "sast-ssrf",
                      "Server-side request to a non-literal URL",
                      f"{name}(...) fetches a non-constant URL — SSRF risk if it is user-controlled.",
                      "Allow-list destinations; block internal/link-local/metadata ranges; disable redirects.")
        elif name == "open" and _nonconst(a0) and (_tainting_shape(a0) or _hintish(a0)):
            self._add(node, "CWE-22", "medium", "sast-path-traversal",
                      "File opened from a non-literal, request-shaped path",
                      "open(...) uses a dynamic, request-shaped path — path traversal risk.",
                      "Canonicalise and contain the path within an allowed base directory; reject '..'.")

        # Flask/werkzeug debug server
        if name.split(".")[-1] == "run":
            dbg = _kw(node, "debug")
            if isinstance(dbg, ast.Constant) and dbg.value is True:
                self._add(node, "CWE-489", "medium", "sast-debug-enabled",
                          "Debug mode enabled (app.run(debug=True))",
                          "Running with debug=True exposes an interactive debugger / code execution.",
                          "Never enable debug in production; gate it behind an env flag.")
        self.generic_visit(node)


def _finding(engagement_id, repo, rel, lines, hit) -> Finding:
    lineno, end, cwe, sev, klass, title, desc, rem = hit
    snippet = "".join(lines[max(0, lineno - 1): end]).rstrip()[:600]
    f = Finding(
        engagement_id=engagement_id, title=f"{title} ({rel}:{lineno})", vuln_class=klass,
        severity=sev, confidence="firm", state=State.EVIDENCE_FOUND, cwe=[cwe],
        owasp={"web_2025": ["A03:2025-Injection"]} if "injection" in klass else {},
        asset={"type": "source", "application": "", "environment": "authorized", "target": repo},
        description=desc, root_cause="Detected by static analysis of the source (AST sink pattern).",
        affected_code=AffectedCode(detected_by="rampart-sast-ast", repo=repo, file=rel,
                                   start_line=lineno, end_line=end, snippet=snippet),
        reproduction=Reproduction(prerequisites=["Source access"],
                                  steps=[f"Inspect {rel}:{lineno}"], deterministic=True),
        remediation=Remediation(summary=rem, type="code_patch", guidance=rem, effort="medium"),
        references=[f"https://cwe.mitre.org/data/definitions/{cwe.split('-')[1]}.html"],
        compliance_control_refs=["SOC2:CC8.1"],
        dedupe_key=f"sast:{rel}:{lineno}:{cwe}",
        tags=["sast", "white-box", "static"],
        verification=Verification(method="static-analysis", validated=False, validated_at=now_iso(),
                                  validator="sast-ast", independent_reproduction=False, reproductions=0,
                                  false_positive_checks=["static AST match — not runtime-proven; "
                                                         "correlate with DAST / confirm manually"],
                                  confidence_score=0.5))
    return f


def scan_source(repo_path: str, engagement_id: str = "", max_files: int = 2000) -> list[Finding]:
    findings: list[Finding] = []
    if not repo_path or not os.path.isdir(repo_path):
        return findings
    seen = 0
    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
        for fn in sorted(files):
            if not fn.endswith(".py"):
                continue
            seen += 1
            if seen > max_files:
                return findings
            path = os.path.join(root, fn)
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    src = fh.read()
                lines = src.splitlines(keepends=True)
                tree = ast.parse(src, filename=path)
            except (OSError, SyntaxError, ValueError):
                continue
            v = _Visitor()
            v.visit(tree)
            rel = os.path.relpath(path, repo_path).replace("\\", "/")
            for hit in v.hits:
                f = _finding(engagement_id, repo_path, rel, lines, hit)
                findings.append(f)
    return findings
