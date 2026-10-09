"""Remediation — runtime<->source correlation + an ADVISORY minimal patch (sections 18, 21).

Hard product invariant (R7): generated remediation is advisory only. Rampart never
auto-applies or auto-merges. It writes a ``.patch`` and populates the finding's
``affected_code``/``remediation`` blocks; opening a PR (and merging) is left to the human /
the CI GitHub Action. The correlator is a lightweight regex fallback for the MVP; a
production build runs Semgrep as a separate-process adapter and consumes its SARIF.
"""

from __future__ import annotations

import os
import re

from ..schemas.finding import AffectedCode, Finding


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
        var = object_type.lower()
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
        for root, _dirs, files in os.walk(self.repo_path):
            if ".git" in root or "__pycache__" in root:
                continue
            for fn in sorted(files):
                if not fn.endswith(".py"):
                    continue
                path = os.path.join(root, fn)
                try:
                    with open(path, encoding="utf-8") as fh:
                        lines = fh.readlines()
                except OSError:
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
                timeout=5,
            )
            return out.stdout.strip() if out.returncode == 0 else ""
        except Exception:  # noqa: BLE001
            return ""

    # --------------------------------------------------------------- propose
    def propose(self, finding: Finding, object_type: str) -> None:
        ac = self.correlate(finding, object_type)
        if ac:
            finding.affected_code = ac
        patch = self.intel.propose_patch(
            {
                "object_var": object_type.lower(),
                "object_type": object_type,
                "snippet": (ac.snippet if ac else ""),
                "file": (ac.file if ac else ""),
            }
        )
        finding.remediation.type = "code_patch"
        finding.remediation.summary = (
            finding.remediation.summary or "Enforce an object-level ownership check."
        )
        finding.remediation.guidance = patch.get("explanation", finding.remediation.guidance)
        finding.remediation.proposed_diff = patch.get("diff", "")
        finding.remediation.effort = "low"

        # write the advisory patch artifact (never applied automatically)
        if patch.get("diff"):
            patch_path = os.path.join(self.artifacts_dir, f"{finding.id}.patch")
            header = (
                f"# ADVISORY PATCH for {finding.id} — {finding.title}\n"
                f"# File: {ac.file if ac else '(source not located)'}\n"
                f"# Rampart never auto-applies this. Review, open a PR, then let Rampart retest.\n\n"
            )
            with open(patch_path, "w", encoding="utf-8") as fh:
                fh.write(header + patch["diff"])
            finding.remediation.pr_ref = f"file://{patch_path}"
