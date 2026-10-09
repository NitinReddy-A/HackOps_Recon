"""Advisory remediation: tolerant of non-UTF-8 sources, prunes vendored/VCS dirs by path part,
emits a REAL unified diff (applies cleanly, never auto-applied) when the source is located, and a
Markdown advisory — not a fake ``.patch`` — when it is not."""

import os
import shutil
import subprocess

import pytest

from rampart.intelligence.deterministic import DeterministicProvider
from rampart.remediation import Remediator
from rampart.schemas.finding import Finding

SERVICE = (
    "class Forbidden(Exception):\n"
    "    pass\n"
    "\n"
    "\n"
    "class OrdersService:\n"
    "    def get_order(self, order_id, principal):\n"
    "        order = self.repo.get(order_id)\n"
    "        if order is None:\n"
    "            raise KeyError(order_id)\n"
    "        return order\n"
)


def _finding():
    return Finding(engagement_id="e", title="BOLA on /api/orders/{id}", vuln_class="IDOR/BOLA")


def test_latin1_file_does_not_crash_and_real_unified_diff_is_written(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "a_legacy.py").write_bytes(b'# -*- coding: latin-1 -*-\nNAME = "caf\xe9"\n')
    (repo / "orders_service.py").write_text(SERVICE)
    before = (repo / "orders_service.py").read_bytes()
    f = _finding()
    Remediator(str(repo), DeterministicProvider(), str(tmp_path / "art")).propose(f, "Order")

    assert f.affected_code.file == "orders_service.py"
    diff = f.remediation.proposed_diff
    assert diff.startswith("--- a/orders_service.py\n+++ b/orders_service.py\n@@ ")
    assert "+        if order.owner_id != principal.id:" in diff
    assert "+            raise Forbidden()" in diff
    path = f.remediation.pr_ref[len("file://") :]
    assert path.endswith(".patch") and os.path.isfile(path)
    assert (repo / "orders_service.py").read_bytes() == before  # advisory only, never applied

    if shutil.which("git"):
        p = subprocess.run(["git", "apply", "--check", path], cwd=repo, capture_output=True, text=True)
        assert p.returncode == 0, p.stderr


def test_unlocated_source_gets_markdown_advisory_not_patch(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "other.py").write_text("x = 1\n")
    f = _finding()
    Remediator(str(repo), DeterministicProvider(), str(tmp_path / "art")).propose(f, "Order")
    path = f.remediation.pr_ref[len("file://") :]
    assert path.endswith(".md")
    assert "illustrative sketch" in open(path, encoding="utf-8").read()
    assert "Forbidden" in f.remediation.proposed_diff


@pytest.mark.parametrize("skipped", [".git", "node_modules", ".venv", "__pycache__", "dist", "build"])
def test_correlator_prunes_dirs_by_path_part(tmp_path, skipped):
    repo = tmp_path / "repo"
    (repo / skipped).mkdir(parents=True)
    (repo / skipped / "orders_service.py").write_text(SERVICE)
    (repo / ".github").mkdir()
    (repo / ".github" / "orders_service.py").write_text(SERVICE)  # ".git" must not prune ".github"
    ac = Remediator(str(repo), DeterministicProvider(), str(tmp_path / "art")).correlate(_finding(), "Order")
    assert ac is not None and ac.file == ".github/orders_service.py"
