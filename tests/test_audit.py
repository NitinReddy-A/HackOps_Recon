"""Append-only, hash-chained audit log integrity."""

import json

from rampart.audit import AuditLog
from rampart.schemas.audit import AuditEvent


def _ev(engagement="E"):
    return AuditEvent(
        engagement_id=engagement, phase="test", actor={"type": "system"}, action={"tool": "http_request"}
    )


def test_chain_intact(tmp_path):
    log = AuditLog(str(tmp_path / "a.jsonl"))
    for _ in range(5):
        log.append(_ev())
    ok, msg = log.verify_chain()
    assert ok, msg
    assert len(log.read_all()) == 5


def test_chain_links_prev_hash(tmp_path):
    log = AuditLog(str(tmp_path / "a.jsonl"))
    e1 = log.append(_ev())
    e2 = log.append(_ev())
    assert e2.prev_hash == e1.event_hash


def test_tamper_is_detected(tmp_path):
    path = str(tmp_path / "a.jsonl")
    log = AuditLog(path)
    for _ in range(3):
        log.append(_ev())
    # tamper: rewrite the middle record's action
    lines = open(path, encoding="utf-8").read().splitlines()
    rec = json.loads(lines[1])
    rec["action"]["tool"] = "malicious"
    lines[1] = json.dumps(rec)
    open(path, "w", encoding="utf-8").write("\n".join(lines) + "\n")

    ok, msg = AuditLog(path).verify_chain()
    assert not ok and "mismatch" in msg
