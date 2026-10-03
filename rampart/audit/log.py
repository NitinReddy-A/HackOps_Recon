"""Append-only, hash-chained audit log backed by a JSONL file.

Fail-closed: if the log cannot be written, the caller must treat the action as denied
(the policy pipeline enforces this). The chain lets a reviewer reconstruct *why* any
action was permitted and detect tampering.
"""
from __future__ import annotations

import json
import os
import threading

from ..schemas.audit import AuditEvent
from ..util import GENESIS_HASH, canonical_json


class AuditLogError(RuntimeError):
    pass


class AuditLog:
    def __init__(self, path: str):
        self.path = path
        self._lock = threading.Lock()
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        self._head = self._load_head()

    def _load_head(self) -> str:
        if not os.path.exists(self.path):
            return GENESIS_HASH
        last = None
        with open(self.path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    last = line
        if not last:
            return GENESIS_HASH
        try:
            return json.loads(last)["event_hash"]
        except Exception as exc:  # noqa: BLE001
            raise AuditLogError(f"corrupt audit log tail in {self.path}: {exc}") from exc

    def append(self, event: AuditEvent) -> AuditEvent:
        with self._lock:
            event.finalize(self._head)
            line = canonical_json(event.to_dict())
            try:
                with open(self.path, "a", encoding="utf-8") as fh:
                    fh.write(line + "\n")
                    fh.flush()
                    os.fsync(fh.fileno())
            except OSError as exc:
                raise AuditLogError(f"could not write audit event (fail-closed): {exc}") from exc
            self._head = event.event_hash
            return event

    def read_all(self) -> list[AuditEvent]:
        if not os.path.exists(self.path):
            return []
        out = []
        with open(self.path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    out.append(AuditEvent.from_dict(json.loads(line)))
        return out

    def verify_chain(self) -> tuple[bool, str]:
        """Return (ok, message). Recomputes the whole chain from genesis."""
        prev = GENESIS_HASH
        for i, ev in enumerate(self.read_all()):
            if ev.prev_hash != prev:
                return False, f"event #{i} ({ev.event_id}) prev_hash mismatch"
            if not ev.verify():
                return False, f"event #{i} ({ev.event_id}) event_hash mismatch (tampered)"
            prev = ev.event_hash
        return True, "chain intact"

    @property
    def head(self) -> str:
        return self._head
