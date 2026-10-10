"""Fail-closed behaviour for a configured Postgres run store.

A ``postgres://`` / ``postgresql://`` store URL whose connection cannot be established must
ABORT the run (so evidence never silently lands in a local SQLite file instead of the shared
store), unless the operator explicitly opts in to a local fallback via
``?on_error=sqlite-fallback`` — in which case the fallback must be loud and recorded.

psycopg-unavailable is simulated without a real Postgres: ``sys.modules["psycopg"] = None``
makes ``import psycopg`` raise, and a fake module with a raising ``connect`` simulates a
connect failure.
"""

import sys
import types

import pytest

from rampart.store import SqlRunStore, StoreError


def test_postgres_without_psycopg_fails_closed(tmp_path, monkeypatch):
    monkeypatch.setitem(sys.modules, "psycopg", None)  # force `import psycopg` to raise
    work = tmp_path / ".rampart"
    with pytest.raises(StoreError) as exc:
        SqlRunStore("postgresql://user:pw@db.example:5432/rampart", str(work), engagement="E1")
    msg = str(exc.value)
    assert "Postgres store unavailable" in msg
    assert "psycopg" in msg  # actionable: names the missing driver / install hint
    assert "on_error=sqlite-fallback" in msg  # actionable: names the opt-in
    # fail-closed: the default path must NOT create a local sqlite file
    assert not (work / "rampart.db").exists()


def test_postgres_connect_failure_fails_closed(tmp_path, monkeypatch):
    fake = types.ModuleType("psycopg")
    fake.connect = lambda url: (_ for _ in ()).throw(RuntimeError("connection refused"))
    monkeypatch.setitem(sys.modules, "psycopg", fake)
    work = tmp_path / ".rampart"
    with pytest.raises(StoreError) as exc:
        SqlRunStore("postgresql://db.example/rampart", str(work))
    assert "could not connect" in str(exc.value)
    assert not (work / "rampart.db").exists()


def test_postgres_fallback_opt_in_falls_back_loudly(tmp_path, monkeypatch, capsys):
    monkeypatch.setitem(sys.modules, "psycopg", None)
    work = tmp_path / ".rampart"
    url = "postgresql://user:pw@db.example:5432/rampart?on_error=sqlite-fallback"
    store = SqlRunStore(url, str(work), engagement="E1")
    # it fell back to a real, usable local sqlite store
    assert (work / "rampart.db").exists()
    store.save_hypotheses([{"vuln_class": "XSS"}])
    assert len(store.load_hypotheses()) == 1
    # the fallback is signalled: a recorded warning (for scan.json) ...
    assert store.warnings and "FELL BACK" in store.warnings[0]
    # ... and a loud stderr message
    err = capsys.readouterr().err
    assert "WARNING" in err and "Postgres store unavailable" in err


def test_on_error_knob_stripped_from_driver_url(tmp_path, monkeypatch):
    """Rampart's own ``on_error`` knob must never reach the driver, but real libpq params must."""
    seen = {}

    def _connect(url):
        seen["url"] = url
        raise RuntimeError("connection refused")  # fail -> loud fallback below

    fake = types.ModuleType("psycopg")
    fake.connect = _connect
    monkeypatch.setitem(sys.modules, "psycopg", fake)
    work = tmp_path / ".rampart"
    SqlRunStore("postgresql://db.example/rampart?on_error=sqlite-fallback&sslmode=require", str(work))
    assert "on_error" not in seen["url"]  # knob stripped
    assert "sslmode=require" in seen["url"]  # genuine driver param preserved


def test_sqlite_url_is_unchanged_and_has_no_warnings(tmp_path):
    db = tmp_path / "runs.db"
    store = SqlRunStore(f"sqlite:///{db}", str(tmp_path / ".rampart"), engagement="E1")
    assert store.warnings == []  # the sqlite path never warns/falls back
    store.save_hypotheses([{"vuln_class": "SQLI"}])
    assert len(store.load_hypotheses()) == 1
    assert "E1" in store.list_engagements()
    # the configured sqlite db is used (not the rampart.db postgres-fallback name)
    assert db.exists()
