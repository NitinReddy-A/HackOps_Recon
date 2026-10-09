"""Audit-log tamper evidence (reviewer finding A9): truncation, torn/garbage lines, injected
fields and re-chained forgeries are reported — never a traceback — and a corrupt log refuses
appends with a catchable error."""

import json
import os

import pytest

from rampart.audit import AuditLog, AuditLogCorrupt
from rampart.schemas.audit import AuditEvent
from rampart.util import GENESIS_HASH, canonical_json


def _ev(i=0):
    return AuditEvent(engagement_id="E", phase="test", actor={"type": "system"}, action={"tool": "t", "i": i})


@pytest.fixture
def log10(tmp_path):
    path = str(tmp_path / "audit.jsonl")
    log = AuditLog(path)
    for i in range(10):
        log.append(_ev(i))
    assert os.path.exists(str(tmp_path / "audit.head.json"))
    return path


def _lines(path):
    return open(path, encoding="utf-8").read().splitlines()


def _write(path, lines, raw=None):
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(raw if raw is not None else "".join(ln + "\n" for ln in lines))


def _verify(path):
    return AuditLog(path).verify_chain()  # opening a damaged log must never raise


def test_intact_log_verifies(log10):
    ok, msg = _verify(log10)
    assert ok and "10 events" in msg


@pytest.mark.parametrize("drop", [1, 5, 10])
def test_truncation_detected(log10, drop):
    _write(log10, _lines(log10)[:-drop])
    ok, msg = _verify(log10)
    assert not ok and "truncated" in msg


def test_emptied_file_detected(log10):
    _write(log10, [], raw="")
    ok, msg = _verify(log10)
    assert not ok and "truncated" in msg


def test_deleted_log_detected(log10):
    os.remove(log10)
    assert not _verify(log10)[0]


def test_torn_last_line_reported_not_raised(log10):
    raw = open(log10, encoding="utf-8").read()
    _write(log10, None, raw=raw[:-20] + "\n")
    ok, msg = _verify(log10)
    assert not ok and "line 10 unparsable" in msg
    assert len(AuditLog(log10).read_all()) == 9  # display paths skip, never crash


def test_garbage_line_reported(log10):
    lines = _lines(log10)
    lines.insert(3, "garbage")
    _write(log10, lines)
    ok, msg = _verify(log10)
    assert not ok and "line 4 unparsable" in msg


def test_injected_field_rejected(log10):
    lines = _lines(log10)
    ev = json.loads(lines[5])
    ev["note"] = "injected"
    lines[5] = json.dumps(ev)
    _write(log10, lines)
    ok, msg = _verify(log10)
    assert not ok and "unknown audit event field" in msg
    with pytest.raises(ValueError):
        AuditEvent.from_dict(ev)


@pytest.mark.parametrize("mutate", ["delete", "swap", "edit"])
def test_middle_edits_detected(log10, mutate):
    lines = _lines(log10)
    if mutate == "delete":
        del lines[4]
    elif mutate == "swap":
        lines[2], lines[3] = lines[3], lines[2]
    else:
        lines[4] = lines[4].replace('"i":4', '"i":44')
    _write(log10, lines)
    assert not _verify(log10)[0]


def test_whitespace_reformat_is_not_tampering(log10):
    lines = _lines(log10)
    lines[5] = json.dumps(json.loads(lines[5]), separators=(", ", ": "))
    _write(log10, lines)
    assert _verify(log10)[0]


def test_rechained_forgery_detected_by_head_anchor(log10):
    prev, out = GENESIS_HASH, []
    for i, ln in enumerate(_lines(log10)):
        e = AuditEvent.from_dict(json.loads(ln))
        if i == 4:
            e.action["i"] = "FORGED"
        e.finalize(prev)
        prev = e.event_hash
        out.append(canonical_json(e.to_dict()))
    _write(log10, out)
    ok, msg = _verify(log10)
    assert not ok and "head" in msg


def test_documented_limit_full_rewrite_of_both_files_is_not_detectable(log10):
    """An attacker with write access to BOTH the log and the anchor can rewrite history; the
    docstring says so. This test pins that limitation so nobody oversells the guarantee."""
    prev, out = GENESIS_HASH, []
    for ln in _lines(log10)[:3]:
        e = AuditEvent.from_dict(json.loads(ln))
        e.finalize(prev)
        prev = e.event_hash
        out.append(canonical_json(e.to_dict()))
    _write(log10, out)
    anchor = os.path.join(os.path.dirname(log10), "audit.head.json")
    with open(anchor, "w", encoding="utf-8") as fh:
        json.dump({"count": 3, "head": prev}, fh)
    assert _verify(log10)[0]


def test_corrupt_log_refuses_append_with_catchable_error(log10):
    lines = _lines(log10)
    _write(log10, lines[:-1] + [lines[-1][:30]])
    log = AuditLog(log10)  # opening never raises
    with pytest.raises(AuditLogCorrupt):
        log.ensure_appendable()
    with pytest.raises(AuditLogCorrupt):
        log.append(_ev())
    assert open(log10, encoding="utf-8").read().count("\n") == 10  # nothing appended


def test_legacy_log_without_anchor_is_flagged_then_anchored_on_append(log10):
    os.remove(os.path.join(os.path.dirname(log10), "audit.head.json"))
    ok, msg = _verify(log10)
    assert not ok and "anchor" in msg and "missing" in msg
    log = AuditLog(log10)
    log.ensure_appendable()  # an intact legacy chain may be continued
    log.append(_ev(10))
    ok, msg = log.verify_chain()
    assert ok and "11 events" in msg


def test_reopen_and_continue(log10):
    log = AuditLog(log10)
    log.append(_ev(10))
    assert AuditLog(log10).verify_chain()[0]
    assert log.count == 11
