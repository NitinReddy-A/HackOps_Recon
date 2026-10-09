"""SQL-backed run store for multi-tenant / multi-run deployments.

Drop-in for the file-based :class:`RunStore`: same method surface, but the run documents
(findings, app model, hypotheses, scan summary) are persisted to a SQL database keyed by
engagement id — so many engagements/tenants live in one queryable store. SQLite (stdlib) is
the zero-dependency default and is fully tested; pass a ``postgresql://`` URL to use Postgres
(needs the optional ``psycopg`` driver). Evidence blobs, reports and the hash-chained audit log
remain on the local filesystem under ``work_dir`` (content-addressed / append-only by design).
"""

from __future__ import annotations

import json
import os
from urllib.parse import urlparse

from ..schemas.appmodel import ApplicationModel
from ..schemas.finding import Finding


class SqlRunStore:
    def __init__(self, db_url: str, work_dir: str, engagement: str = "engagement"):
        self.db_url = db_url
        self.engagement = engagement or "engagement"
        # file-backed sidecars (evidence/reports/audit stay on disk, like RunStore)
        self.base = work_dir
        self.evidence_dir = os.path.join(work_dir, "evidence")
        self.artifacts_dir = os.path.join(work_dir, "artifacts")
        self.reports_dir = os.path.join(work_dir, "reports")
        self.audit_path = os.path.join(work_dir, "audit.jsonl")
        for d in (self.base, self.evidence_dir, self.artifacts_dir, self.reports_dir):
            os.makedirs(d, exist_ok=True)
        self._pg = urlparse(db_url).scheme in ("postgres", "postgresql")
        self._conn = self._connect()
        self._init_schema()

    # ---- connection (sqlite default; postgres via psycopg if available) ----
    def _connect(self):
        if self._pg:
            try:
                import psycopg  # type: ignore

                return psycopg.connect(self.db_url)
            except Exception as exc:  # noqa: BLE001 - fall back to a local sqlite mirror, fail-safe
                import sqlite3

                self._pg = False
                fallback = os.path.join(self.base, "rampart.db")
                print(f"[rampart] psycopg unavailable ({exc}); using sqlite at {fallback}")
                return sqlite3.connect(fallback)
        import sqlite3

        path = self.db_url.split("://", 1)[-1] if "://" in self.db_url else self.db_url
        path = path or os.path.join(self.base, "rampart.db")
        return sqlite3.connect(path)

    def _ph(self) -> str:
        return "%s" if self._pg else "?"

    def _init_schema(self):
        cur = self._conn.cursor()
        cur.execute(
            "CREATE TABLE IF NOT EXISTS rampart_documents ("
            "engagement TEXT NOT NULL, kind TEXT NOT NULL, body TEXT NOT NULL, "
            "updated_at TEXT, PRIMARY KEY (engagement, kind))"
        )
        self._conn.commit()

    # ---- document get/put (upsert on (engagement, kind)) ----
    def _put(self, kind: str, obj):
        from ..util import now_iso

        body = json.dumps(obj, default=str)
        ph = self._ph()
        sql = (
            f"INSERT INTO rampart_documents (engagement, kind, body, updated_at) "
            f"VALUES ({ph}, {ph}, {ph}, {ph}) "
            f"ON CONFLICT (engagement, kind) DO UPDATE SET body = EXCLUDED.body, "
            f"updated_at = EXCLUDED.updated_at"
        )
        cur = self._conn.cursor()
        cur.execute(sql, (self.engagement, kind, body, now_iso()))
        self._conn.commit()

    def _get(self, kind: str, default=None):
        ph = self._ph()
        cur = self._conn.cursor()
        cur.execute(
            f"SELECT body FROM rampart_documents WHERE engagement = {ph} AND kind = {ph}",
            (self.engagement, kind),
        )
        row = cur.fetchone()
        return json.loads(row[0]) if row else default

    # ---- RunStore-compatible surface ----
    def save_findings(self, findings):
        self._put("findings", [f.to_dict() for f in findings])

    def load_findings(self):
        return [Finding.from_dict(d) for d in (self._get("findings", []) or [])]

    def save_appmodel(self, model):
        self._put("appmodel", model.to_dict())

    def load_appmodel(self):
        d = self._get("appmodel")
        return ApplicationModel.from_dict(d) if d else None

    def save_hypotheses(self, hyps):
        self._put("hypotheses", hyps)

    def load_hypotheses(self):
        return self._get("hypotheses", []) or []

    def save_scan(self, summary):
        self._put("scan", summary)

    def load_scan(self):
        return self._get("scan", {}) or {}

    # ---- multi-tenant helpers ----
    def list_engagements(self):
        cur = self._conn.cursor()
        cur.execute("SELECT DISTINCT engagement FROM rampart_documents ORDER BY engagement")
        return [r[0] for r in cur.fetchall()]

    def close(self):
        try:
            self._conn.close()
        except Exception:  # noqa: BLE001
            pass
