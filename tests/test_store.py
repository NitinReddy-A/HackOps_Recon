"""SQL (SQLite) multi-tenant run store — persists runs keyed by engagement, round-trips findings."""
from conftest import write_engagement
from rampart.engagement import Engagement, EngagementConfig
from rampart.store import SqlRunStore


def _sql_eng(tmp_path, port, db):
    scope = write_engagement(tmp_path, port)
    cfg = EngagementConfig(scope_file=scope, target=f"http://127.0.0.1:{port}",
                           work_dir=str(tmp_path / ".rampart"),
                           openapi=str(tmp_path / "openapi.json"), appmodel_seed=str(tmp_path / "seed.json"),
                           application="demo-shop-api", store_url=f"sqlite:///{db}")
    return Engagement(cfg)


def test_sql_store_persists_and_reloads_a_run(tmp_path, vuln_server):
    db = str(tmp_path / "runs.db")
    eng = _sql_eng(tmp_path, vuln_server.port, db)
    result = eng.run_scan()
    confirmed = [f for f in result.findings if f.verification.validated]
    assert confirmed, "scan should confirm findings"
    # a fresh store over the same DB reloads the persisted run
    store = SqlRunStore(f"sqlite:///{db}", str(tmp_path / ".rampart2"), engagement="TEST-0001")
    reloaded = store.load_findings()
    assert len(reloaded) == len(result.findings)
    assert store.load_scan().get("correlation", {}).get("risk_score", 0) >= 55
    assert "TEST-0001" in store.list_engagements()


def test_sql_store_is_multi_tenant(tmp_path):
    db = str(tmp_path / "multi.db")
    a = SqlRunStore(f"sqlite:///{db}", str(tmp_path / "a"), engagement="tenant-A")
    b = SqlRunStore(f"sqlite:///{db}", str(tmp_path / "b"), engagement="tenant-B")
    a.save_hypotheses([{"vuln_class": "XSS"}])
    b.save_hypotheses([{"vuln_class": "SQLI"}, {"vuln_class": "SSRF"}])
    assert len(a.load_hypotheses()) == 1 and len(b.load_hypotheses()) == 2   # isolated by engagement
    assert set(a.list_engagements()) == {"tenant-A", "tenant-B"}             # one shared DB
