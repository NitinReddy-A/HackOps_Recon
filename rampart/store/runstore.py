"""Run store — a transparent, on-disk record of an engagement.

Everything is plain JSON/JSONL under ``<workdir>/.rampart`` so an operator (or an auditor)
can inspect exactly what happened: the hash-chained audit log, content-addressed evidence,
the application model, the hypotheses (PTT), the findings, and the generated reports. The
blueprint targets Postgres + object storage for a multi-tenant deployment; this file store
is the self-hostable single-node default.
"""

from __future__ import annotations

import json
import os

from ..schemas.appmodel import ApplicationModel
from ..schemas.finding import Finding


class RunStore:
    def __init__(self, base_dir: str):
        self.base = base_dir
        self.evidence_dir = os.path.join(base_dir, "evidence")
        self.artifacts_dir = os.path.join(base_dir, "artifacts")
        self.reports_dir = os.path.join(base_dir, "reports")
        self.audit_path = os.path.join(base_dir, "audit.jsonl")
        for d in (self.base, self.evidence_dir, self.artifacts_dir, self.reports_dir):
            os.makedirs(d, exist_ok=True)

    def _write_json(self, name, obj):
        with open(os.path.join(self.base, name), "w", encoding="utf-8") as fh:
            json.dump(obj, fh, indent=2, default=str)

    def _read_json(self, name, default=None):
        path = os.path.join(self.base, name)
        if not os.path.exists(path):
            return default
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)

    # findings
    def save_findings(self, findings: list[Finding]):
        self._write_json("findings.json", [f.to_dict() for f in findings])

    def load_findings(self) -> list[Finding]:
        return [Finding.from_dict(d) for d in (self._read_json("findings.json", []) or [])]

    # application model
    def save_appmodel(self, model: ApplicationModel):
        self._write_json("appmodel.json", model.to_dict())

    def load_appmodel(self) -> ApplicationModel | None:
        d = self._read_json("appmodel.json")
        return ApplicationModel.from_dict(d) if d else None

    # hypotheses (PTT)
    def save_hypotheses(self, hyps: list):
        self._write_json("hypotheses.json", hyps)

    def load_hypotheses(self) -> list:
        return self._read_json("hypotheses.json", []) or []

    # scan summary / metrics
    def save_scan(self, summary: dict):
        self._write_json("scan.json", summary)

    def load_scan(self) -> dict:
        return self._read_json("scan.json", {}) or {}
