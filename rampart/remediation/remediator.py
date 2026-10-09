"""Remediation — runtime<->source correlation + an ADVISORY minimal patch (sections 18, 21).

Hard product invariant (R7): generated remediation is advisory only. Rampart never
auto-applies or auto-merges. When the defect is located in source and the fix is concrete it
writes a real unified diff (``.patch``, made with :mod:`difflib` against the located file);
otherwise it writes a Markdown advisory (``.md``) with an illustrative sketch. Either way it
populates the finding's ``affected_code``/``remediation`` blocks; opening a PR (and merging) is
left to the human / the CI GitHub Action. The correlator is a lightweight regex fallback for the
MVP; a production build runs Semgrep as a separate-process adapter and consumes its SARIF.
"""

from __future__ import annotations

import difflib
import os
import re

from ..schemas.finding import AffectedCode, Finding

_SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    "__pycache__",
    "node_modules",
    ".venv",
    "venv",
    ".tox",
    ".rampart",
    "dist",
    "build",
    "site-packages",
}
_PRINCIPAL_PARAMS = ("principal", "current_principal", "current_user", "user", "caller", "requester", "actor")


def _read_lines(path: str) -> list[str] | None:
    """Source lines, tolerant of non-UTF-8 files (latin-1 etc. never crash the run)."""
    try:
        # newline="" keeps the file's own line endings (CRLF/LF) so a generated diff applies as-is
        with open(path, encoding="utf-8", errors="replace", newline="") as fh:
            return fh.readlines()
    except (OSError, ValueError, UnicodeError):
        return None


class Remediator:
    def __init__(self, repo_path: str, intel, artifacts_dir: str):
        self.repo_path = repo_path
        self.intel = intel
        self.artifacts_dir = artifacts_dir
        os.makedirs(artifacts_dir, exist_ok=True)

    # ------------------------------------------------------------- correlate
    def correlate(self, finding: Finding, object_type: str) -> AffectedCode | None:
        """Find the source line where an object is fetched by id and returned without an
        ownership check. Heuristic, language: Python."""
        var = re.escape(object_type.lower())
        # A value fetched by id (possibly via a dotted repo chain) then returned, with no
        # ownership guard nearby. The return matcher is tight so it doesn't match the word
        # appearing inside an unrelated string/branch; comments are stripped before the guard
        # check so a comment like "no ownership check" can't be mistaken for a real guard.
        fetch_re = re.compile(rf"(\b{var}\b|\bobj\b|\brecord\b)\s*=\s*[\w.]+\.get\(", re.IGNORECASE)
        return_re = re.compile(
            rf"return\s+(self\.)?_?send\(\s*200\s*,\s*{var}\b"
            rf"|return\s+{var}\s*$"
            rf"|return\s+{var}\s*\)",
            re.IGNORECASE | re.MULTILINE,
        )
        guard_re = re.compile(r"owner|authoriz|is_owner|can_access|principal\s*(==|!=)", re.IGNORECASE)
        for root, dirs, files in os.walk(self.repo_path):
            # prune by path PART (".git" must not also match ".github")
            dirs[:] = sorted(d for d in dirs if d not in _SKIP_DIRS)
            for fn in sorted(files):
                if not fn.endswith(".py"):
                    continue
                path = os.path.join(root, fn)
                lines = _read_lines(path)
                if lines is None:
                    continue
                for i, line in enumerate(lines):
                    if not return_re.search(line):
                        continue
                    win_lines = lines[max(0, i - 12) : i + 1]
                    code_only = "".join(ln.split("#", 1)[0] for ln in win_lines)  # strip comments
                    if fetch_re.search(code_only) and not guard_re.search(code_only):
                        rel = os.path.relpath(path, self.repo_path).replace("\\", "/")
                        snippet = "".join(lines[max(0, i - 2) : i + 1]).rstrip()
                        return AffectedCode(
                            detected_by="rampart-regex-correlator",
                            repo=self.repo_path,
                            file=rel,
                            start_line=max(1, i - 1),
                            end_line=i + 1,
                            snippet=snippet,
                            commit=self._git_commit(),
                        )
        return None

    def _git_commit(self) -> str:
        try:
            import subprocess

            out = subprocess.run(
                ["git", "-C", self.repo_path, "rev-parse", "--short", "HEAD"],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=5,
            )
            return out.stdout.strip() if out.returncode == 0 else ""
        except (OSError, ValueError, UnicodeError):
            return ""
        except Exception:  # noqa: BLE001 - e.g. TimeoutExpired; the commit id is optional metadata
            return ""

    # ------------------------------------------------------------ diff build
    @staticmethod
    def _principal_param(lines: list[str], ret_idx: int) -> str | None:
        """A principal-like parameter of the function enclosing the return line, if any."""
        for j in range(ret_idx, -1, -1):
            m = re.match(r"\s*(?:async\s+)?def\s+\w+\s*\(([^)]*)\)?", lines[j])
            if m:
                params = [p.split(":")[0].split("=")[0].strip().lstrip("*") for p in m.group(1).split(",")]
                for p in params:
                    if p in _PRINCIPAL_PARAMS:
                        return p
                return None
        return None

    def _unified_diff(self, ac: AffectedCode, guard: list[str]) -> str:
        """A real unified diff inserting ``guard`` above the located return statement."""
        path = os.path.join(self.repo_path, ac.file)
        lines = _read_lines(path)
        if not lines:
            return ""
        idx = ac.end_line - 1
        if not (0 <= idx < len(lines)):
            return ""
        ret = lines[idx]
        eol = "\r\n" if ret.endswith("\r\n") else "\n"
        if not lines[-1].endswith("\n"):
            lines[-1] += eol
        indent = ret[: len(ret) - len(ret.lstrip())]
        new_lines = lines[:idx] + [f"{indent}{g}{eol}" for g in guard] + lines[idx:]
        return "".join(difflib.unified_diff(lines, new_lines, fromfile=f"a/{ac.file}", tofile=f"b/{ac.file}"))

    # --------------------------------------------------------------- propose
    def propose(self, finding: Finding, object_type: str) -> None:
        ac = self.correlate(finding, object_type)
        if ac:
            finding.affected_code = ac
        ctx = {
            "object_var": object_type.lower(),
            "object_type": object_type,
            "snippet": (ac.snippet if ac else ""),
            "file": (ac.file if ac else ""),
        }
        if ac:
            lines = _read_lines(os.path.join(self.repo_path, ac.file)) or []
            p = self._principal_param(lines, ac.end_line - 1) if lines else None
            if p:
                ctx["principal_expr"] = f"{p}.id"
        patch = self.intel.propose_patch(ctx)
        finding.remediation.type = "code_patch"
        finding.remediation.summary = (
            finding.remediation.summary or "Enforce an object-level ownership check."
        )
        finding.remediation.guidance = patch.get("explanation", finding.remediation.guidance)
        finding.remediation.effort = "low"

        guard = patch.get("insert_before_return")
        unified = self._unified_diff(ac, guard) if ac and isinstance(guard, list) and guard else ""
        # write the advisory artifact (never applied automatically)
        if unified:
            finding.remediation.proposed_diff = unified
            out_path = os.path.join(self.artifacts_dir, f"{finding.id}.patch")
            header = (
                f"# ADVISORY PATCH for {finding.id} — {finding.title}\n"
                f"# File: {ac.file}\n"
                f"# Rampart never auto-applies this. Review, open a PR, then let Rampart retest.\n"
            )
            body = header + unified
        elif patch.get("diff"):
            finding.remediation.proposed_diff = patch.get("diff", "")
            out_path = os.path.join(self.artifacts_dir, f"{finding.id}.md")
            body = (
                f"# Advisory remediation for {finding.id} — {finding.title}\n\n"
                f"File: {ac.file if ac else '(source not located)'}\n\n"
                "The vulnerable source could not be turned into an exact patch, so this is an "
                "**illustrative sketch, not an appliable diff**. Rampart never auto-applies fixes; "
                "adapt it, open a PR, then let Rampart retest.\n\n"
                f"{patch.get('explanation', '')}\n\n```diff\n{patch['diff'].rstrip()}\n```\n"
            )
        else:
            return
        with open(out_path, "w", encoding="utf-8", newline="") as fh:  # keep diff line endings exact
            fh.write(body)
        finding.remediation.pr_ref = f"file://{out_path}"
