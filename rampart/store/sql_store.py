"""SQL-backed run store for multi-tenant / multi-run deployments.

Drop-in for the file-based :class:`RunStore`: same method surface, but the run documents
(findings, app model, hypotheses, scan summary) are persisted to a SQL database keyed by
engagement id — so many engagements/tenants live in one queryable store. SQLite (stdlib) is
the zero-dependency default and is fully tested; pass a ``postgresql://`` URL to use Postgres
(needs the optional ``psycopg`` driver). Evidence blobs, reports and the hash-chained audit log
remain on the local filesystem under ``work_dir`` (content-addressed / append-only by design).

**Fail-closed.** A configured Postgres store that cannot be reached (driver missing or connect
failure) aborts the run with a :class:`StoreError` rather than silently writing findings/evidence
to a local SQLite file — so data never lands somewhere other than where the operator configured.
To explicitly allow a local SQLite fallback, append ``?on_error=sqlite-fallback`` to the store URL
(e.g. ``postgresql://.../rampart?on_error=sqlite-fallback``); the fallback is then loud (a stderr
warning plus a recorded warning the engagement surfaces in ``scan.json`` under ``store_warnings``).
"""

from __future__ import annotations

import json
import os
import sys
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from ..schemas.appmodel import ApplicationModel
from ..schemas.finding import Finding

# Opt-in token (as the ``on_error`` query param on the store URL) that permits the
# otherwise fail-closed Postgres->SQLite fallback. Anything else means "abort".
_FALLBACK_TOKEN = "sqlite-fallback"


class StoreError(RuntimeError):
    """A configured run store cannot be used as configured (fail-closed).

    Raised, for example, when a ``postgres://`` / ``postgresql://`` store URL is configured
    but the connection cannot be established (driver missing or connect failure) and the
    operator has not explicitly opted in to a local SQLite fallback. Aborting here keeps
    evidence/findings from silently landing somewhere other than the configured store.
    """


def _split_store_url(db_url: str) -> tuple[str, bool]:
    """Split a store URL into (connection_url, fallback_opted_in).

    The ``on_error=sqlite-fallback`` query param is Rampart's own knob, not a driver option,
    so it is parsed out here and stripped from the URL handed to the driver. Any other value
    (or its absence) leaves the fallback disabled — the fail-closed default.
    """
    parsed = urlparse(db_url)
    if not parsed.query:
        return db_url, False
    fallback = False
    kept: list[tuple[str, str]] = []
    for key, value in parse_qsl(parsed.query, keep_blank_values=True):
        if key == "on_error":
            if value.strip().lower() == _FALLBACK_TOKEN:
                fallback = True
            continue  # drop Rampart's knob from the URL the driver sees
        kept.append((key, value))
    clean = urlunparse(parsed._replace(query=urlencode(kept)))
    return clean, fallback


def sqlite_path_from_url(db_url: str) -> str:
    """Map a SQLite URL to a filesystem path using the SQLAlchemy convention:

    * ``sqlite:///runs.db``        -> ``runs.db`` (RELATIVE to the current directory)
    * ``sqlite:////var/rampart.db`` -> ``/var/rampart.db`` (absolute: four slashes)
    * ``sqlite:///C:/data/runs.db`` -> ``C:/data/runs.db`` (Windows drive letter)
    * ``sqlite:///:memory:``       -> ``:memory:``
    * ``sqlite://`` / ``""``       -> ``""`` (caller picks the default in the work dir)
    * a bare path (no ``://``)     -> returned unchanged

    A URL with a host part (``sqlite://host/x``) is rejected rather than guessed at.
    """
    if "://" not in db_url:
        return db_url
    scheme, rest = db_url.split("://", 1)
    if scheme.lower() not in ("sqlite", "sqlite3"):
        raise ValueError(f"not a sqlite URL: {db_url!r}")
    rest = rest.split("?", 1)[0]
    if rest == "":
        return ""
    if not rest.startswith("/"):
        raise ValueError(
            f"sqlite URL must have an empty host (sqlite:///relative or sqlite:////abs): {db_url!r}"
        )
    return rest[1:]  # drop the separator after the empty host; what remains is the path


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
        # operator-facing store warnings (e.g. an opt-in fallback actually having fired),
        # surfaced in scan.json by the engagement so the report/caller can see it.
        self.warnings: list[str] = []
        self._conn_url, self._fallback_ok = _split_store_url(db_url)
        self._pg = urlparse(self._conn_url).scheme in ("postgres", "postgresql")
        self._conn = self._connect()
        self._init_schema()

    # ---- connection (sqlite default; postgres via psycopg if available) ----
    def _connect(self):
        if self._pg:
            try:
                import psycopg  # type: ignore
            except Exception as exc:  # noqa: BLE001 - driver not installed
                return self._pg_unavailable(f"psycopg driver not installed ({exc})")
            try:
                return psycopg.connect(self._conn_url)
            except Exception as exc:  # noqa: BLE001 - host/credentials/network
                return self._pg_unavailable(f"could not connect ({exc})")
        import sqlite3

        path = sqlite_path_from_url(self._conn_url) or os.path.join(self.base, "rampart.db")
        return sqlite3.connect(path)

    def _pg_unavailable(self, reason: str):
        """Fail closed: a configured Postgres store that cannot be reached aborts the run,
        UNLESS the operator explicitly opted in to a local SQLite fallback via
        ``?on_error=sqlite-fallback`` on the store URL. The opt-in path is loud (stderr +
        a recorded warning) so the data-location change can never pass unnoticed."""
        if not self._fallback_ok:
            raise StoreError(
                f"configured Postgres store unavailable: {reason}. "
                "Install psycopg (`pip install psycopg[binary]`) or fix the connection; "
                "append `?on_error=sqlite-fallback` to the store URL to allow a local SQLite fallback."
            )
        import sqlite3

        self._pg = False
        fallback = os.path.join(self.base, "rampart.db")
        warning = (
            f"configured Postgres store unavailable: {reason}; FELL BACK to a LOCAL SQLite file "
            f"at {fallback} (opt-in via ?on_error=sqlite-fallback). Findings/evidence for this run "
            "are NOT written to the shared Postgres store."
        )
        self.warnings.append(warning)
        print(f"[rampart] WARNING: {warning}", file=sys.stderr)
        return sqlite3.connect(fallback)

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
