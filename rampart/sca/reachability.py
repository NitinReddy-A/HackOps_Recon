"""Call-graph reachability analysis for Python dependencies (static, stdlib ``ast`` only).

Import-level reachability answers "is the package imported?". This goes further and answers
"is the vulnerable package actually **called**, from code **reachable from an entrypoint**, and
— when the advisory names the vulnerable symbol — is *that specific symbol* on a live path?".

How it works:
  1. Parse every first-party ``.py`` file. For each function (and each module's top-level code)
     record (a) the first-party functions it calls and (b) the dependency symbols it uses.
  2. Build a name-resolved call graph over first-party functions and compute the set reachable from
     entrypoints: module top-level code in non-test files, ``main``, ``if __name__ == '__main__'``,
     every *decorated* function (framework-registered handlers: Flask/FastAPI routes, Celery tasks,
     click commands, …) and every function *referenced* as a call argument (``path('x/', views.index)``,
     ``Thread(target=worker)``, ``add_url_rule(view_func=f)``), which frameworks invoke for us.
  3. A dependency symbol is *reachable* if it is used at an entrypoint or inside a reachable function
     in non-test code; *test-only* if only in tests; *imported-unused* if imported but never called;
     *unreachable* if never imported. When the advisory names affected symbols, a reachable use of
     one of them yields **function-reachable** (the vulnerable code path is actually exercised).

The call graph is name-resolved (no type inference), so it over-approximates edges — which is the
safe direction for reachability (we would rather call something reachable than wrongly drop it). We
say so in the finding; this is a static heuristic call graph, not a sound whole-program analysis.
"""

from __future__ import annotations

import ast
import os
import sys

_SKIP_DIRS = {
    ".git",
    "__pycache__",
    "node_modules",
    ".venv",
    "venv",
    ".rampart",
    "dist",
    "build",
    ".tox",
    ".eggs",
    "site-packages",
}
_TEST_HINTS = ("test", "tests", "conftest", "_spec", "fixture")


def _is_test_path(rel: str) -> bool:
    low = rel.lower().replace("\\", "/")
    base = low.rsplit("/", 1)[-1]
    return (
        base.startswith("test_")
        or base.endswith("_test.py")
        or base == "conftest.py"
        or any(seg in low.split("/") for seg in ("test", "tests"))
    )


class _Node:
    __slots__ = ("qual", "calls", "dep_uses", "file", "is_test", "is_entry")

    def __init__(self, qual, file, is_test, is_entry=False):
        self.qual = qual
        self.calls: set[str] = set()  # simple callee (or referenced-callback) names
        self.dep_uses: set[str] = set()  # full dependency symbols, e.g. "flask.render_template"
        self.file = file
        self.is_test = is_test
        self.is_entry = is_entry


class _ModuleVisitor(ast.NodeVisitor):
    """Collect per-node calls and dependency-symbol uses for one module."""

    def __init__(self, module: str, rel: str, is_test: bool):
        self.module = module
        self.rel = rel
        self.is_test = is_test
        self.imports: dict[str, tuple[str, str]] = {}  # local name -> (root_pkg, full_symbol)
        self.nodes: list[_Node] = []
        self._top = _Node(f"{module}:<module>", rel, is_test, is_entry=not is_test)
        self.nodes.append(self._top)
        self._stack = [self._top]
        self._main_guard_depth = 0

    # ---- imports ----
    def visit_Import(self, node):
        for a in node.names:
            root = a.name.split(".")[0]
            local = a.asname or a.name.split(".")[0]
            self.imports[local] = (root, a.name)
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        if node.level and not node.module:
            return  # relative import of nothing concrete
        mod = node.module or ""
        # relative imports are first-party: mark the root so it never matches a dependency name
        root = ("." if node.level else "") + mod.split(".")[0]
        for a in node.names:
            if a.name == "*":
                continue
            local = a.asname or a.name
            self.imports[local] = (root, f"{mod}.{a.name}" if mod else a.name)
        self.generic_visit(node)

    # ---- function scopes ----
    def _enter_func(self, node):
        parent = self._stack[-1]
        qual = f"{self.module}:{node.name}" if parent is self._top else f"{parent.qual}.{node.name}"
        # Decorated functions are registered with a framework (route / task / CLI command / signal
        # handler …) and invoked by it, not by a first-party call — treat them as entrypoints.
        entry = not self.is_test and (node.name == "main" or bool(node.decorator_list))
        n = _Node(qual, self.rel, self.is_test, is_entry=entry)
        self.nodes.append(n)
        # decorators and default values are evaluated in the PARENT scope
        for d in node.decorator_list:
            self.visit(d)
        for d in list(node.args.defaults) + [x for x in node.args.kw_defaults if x is not None]:
            self.visit(d)
        self._stack.append(n)
        for stmt in node.body:
            self.visit(stmt)
        self._stack.pop()

    def visit_FunctionDef(self, node):
        self._enter_func(node)

    def visit_AsyncFunctionDef(self, node):
        self._enter_func(node)

    def visit_ClassDef(self, node):
        # methods are visited with a Class-qualified name via the stack. The class BODY itself runs
        # when its enclosing scope runs (import time for a module-level class), so the holder node
        # is part of the graph: an entrypoint at module level, else reached from its parent scope.
        prev = self._stack[-1]
        holder = _Node(
            f"{prev.qual}.{node.name}" if prev is not self._top else f"{self.module}:{node.name}",
            self.rel,
            self.is_test,
            is_entry=(prev is self._top and not self.is_test)
            or (bool(node.decorator_list) and not self.is_test),
        )
        self.nodes.append(holder)
        if prev is not self._top:
            prev.calls.add(node.name)
        for d in node.decorator_list:
            self.visit(d)
        for b in list(node.bases) + [k.value for k in node.keywords]:
            self.visit(b)
        self._stack.append(holder)
        for stmt in node.body:
            self.visit(stmt)
        self._stack.pop()

    # ---- `if __name__ == "__main__":` block is an entrypoint ----
    def visit_If(self, node):
        if self._is_main_guard(node.test) and not self.is_test:
            self._top.is_entry = True
        self.generic_visit(node)

    @staticmethod
    def _is_main_guard(test) -> bool:
        return (
            isinstance(test, ast.Compare)
            and isinstance(test.left, ast.Name)
            and test.left.id == "__name__"
            and any(isinstance(c, ast.Constant) and c.value == "__main__" for c in test.comparators)
        )

    # ---- calls + dep usage ----
    def visit_Call(self, node):
        cur = self._stack[-1]
        callee = node.func
        if isinstance(callee, ast.Name):
            cur.calls.add(callee.id)
            sym = self._resolve(callee)
            if sym:
                cur.dep_uses.add(sym)
        elif isinstance(callee, ast.Attribute):
            cur.calls.add(callee.attr)
            sym = self._resolve(callee)
            if sym:
                cur.dep_uses.add(sym)
        # Functions passed as arguments (callbacks / URL-conf views / thread targets) are invoked by
        # the callee: record them as edges from the current scope.
        for arg in list(node.args) + [k.value for k in node.keywords]:
            if isinstance(arg, ast.Starred):
                arg = arg.value
            if isinstance(arg, ast.Name):
                cur.calls.add(arg.id)
            elif isinstance(arg, ast.Attribute):
                cur.calls.add(arg.attr)
        self.generic_visit(node)

    def visit_Attribute(self, node):
        cur = self._stack[-1]
        sym = self._resolve(node)
        if sym:
            cur.dep_uses.add(sym)
        self.generic_visit(node)

    def _resolve(self, node) -> str | None:
        """Resolve a Name/Attribute to a dependency full-symbol via the import map, else None."""
        if isinstance(node, ast.Name):
            hit = self.imports.get(node.id)
            return hit[1] if hit else None
        if isinstance(node, ast.Attribute):
            parts = []
            cur = node
            while isinstance(cur, ast.Attribute):
                parts.append(cur.attr)
                cur = cur.value
            if isinstance(cur, ast.Name):
                base = self.imports.get(cur.id)
                if base:
                    return ".".join([base[1]] + list(reversed(parts)))
        return None


_STDLIB = set(getattr(sys, "stdlib_module_names", ())) | {"__future__"}


class RepoGraph:
    def __init__(self):
        self.nodes: list[_Node] = []
        self.by_name: dict[str, list[_Node]] = {}  # simple func name -> nodes
        self.imports_by_root: dict[str, bool] = {}
        self.first_party: set[str] = set()  # module / package names defined in the repo itself
        self._reachable: set[str] | None = None

    def third_party_roots(self) -> set[str]:
        """Imported top-level modules that are neither stdlib, relative, nor first-party."""
        return {
            r
            for r in self.imports_by_root
            if r and not r.startswith(".") and r not in _STDLIB and r not in self.first_party
        }

    def _index(self):
        for n in self.nodes:
            simple = n.qual.split(":")[-1].split(".")[-1]
            self.by_name.setdefault(simple, []).append(n)

    def reachable_nodes(self) -> set[str]:
        if self._reachable is not None:
            return self._reachable
        frontier = [n for n in self.nodes if n.is_entry]
        seen: set[str] = {n.qual for n in frontier}
        while frontier:
            cur = frontier.pop()
            for callee in cur.calls:
                for tgt in self.by_name.get(callee, []):
                    if tgt.qual not in seen:
                        seen.add(tgt.qual)
                        frontier.append(tgt)
        self._reachable = seen
        return seen


def analyze_repo(repo_path: str, max_files: int = 6000) -> RepoGraph | None:
    if not repo_path or not os.path.isdir(repo_path):
        return None
    g = RepoGraph()
    seen = 0
    found_py = False
    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
        for fn in files:
            if not fn.endswith(".py"):
                continue
            found_py = True
            seen += 1
            if seen > max_files:
                break
            path = os.path.join(root, fn)
            rel = os.path.relpath(path, repo_path).replace("\\", "/")
            parts = rel[:-3].split("/")
            g.first_party.update(parts)
            try:
                with open(path, "rb") as fh:
                    raw = fh.read(800_000)
                # parse BYTES so a UTF-8 BOM / PEP 263 coding cookie (latin-1 …) is honoured
                tree = ast.parse(raw, filename=rel)
            except (OSError, SyntaxError, ValueError, UnicodeError, RecursionError, MemoryError):
                continue
            module = rel[:-3].replace("/", ".")
            v = _ModuleVisitor(module, rel, _is_test_path(rel))
            try:
                v.visit(tree)
            except (RecursionError, MemoryError):
                continue
            g.nodes.extend(v.nodes)
            for rootpkg, _full in v.imports.values():
                g.imports_by_root[rootpkg] = True
    if not found_py:
        return None
    g._index()
    return g


def _symbol_matches(used: str, affected: str) -> bool:
    a = affected.strip().lstrip(".")
    return bool(a) and (
        used == a
        or used.endswith("." + a)
        or used.endswith("." + a.split(".")[-1])
        or used == a.split(".")[-1]
    )


def reachability(graph: RepoGraph, import_names: list[str], affected_symbols=None) -> dict:
    """Classify reachability of a dependency given its import name(s) and (optional) vulnerable
    symbols. Returns {tier, imported, used_symbols, reachable_symbols, vulnerable_symbol_reachable}.
    """
    affected_symbols = affected_symbols or []
    roots = {n.split(".")[0] for n in import_names}
    imported = any(graph.imports_by_root.get(r) for r in roots)

    def _is_dep_sym(sym: str) -> bool:
        return sym.split(".")[0] in roots

    reachable_set = graph.reachable_nodes()
    used_any: set[str] = set()
    used_reachable: set[str] = set()
    used_nontest = False
    for n in graph.nodes:
        dep_syms = {s for s in n.dep_uses if _is_dep_sym(s)}
        if not dep_syms:
            continue
        used_any |= dep_syms
        if n.is_test:
            continue
        used_nontest = True
        if n.qual in reachable_set:
            used_reachable |= dep_syms

    # vulnerable-symbol reachability (strongest signal)
    vuln_reachable = None
    if affected_symbols:
        vuln_reachable = any(_symbol_matches(u, a) for u in used_reachable for a in affected_symbols)

    if not imported:
        tier = "unreachable"
    elif not used_any:
        tier = "imported-unused"
    elif not used_nontest:
        tier = "test-only"
    elif used_reachable:
        tier = "function-reachable" if vuln_reachable else "reachable"
    else:
        tier = "imported-not-on-live-path"  # used, but only in unreachable (dead) non-test code

    return {
        "tier": tier,
        "imported": imported,
        "used_symbols": sorted(used_any)[:20],
        "reachable_symbols": sorted(used_reachable)[:20],
        "vulnerable_symbol_reachable": vuln_reachable,
    }


# tiers that mean "the vulnerable code is actually exercised" (True), "unknown" (None), else de-prioritise
_REACHABLE_TRUE = {"function-reachable", "reachable"}
_REACHABLE_FALSE = {"unreachable", "imported-unused", "test-only", "imported-not-on-live-path"}


def tier_to_bool(tier: str):
    if tier in _REACHABLE_TRUE:
        return True
    if tier in _REACHABLE_FALSE:
        return False
    return None
