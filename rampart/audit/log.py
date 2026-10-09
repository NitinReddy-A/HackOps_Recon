"""Append-only, hash-chained audit log backed by a JSONL file + a head-anchor sidecar.

Fail-closed: if the log cannot be written, the caller must treat the action as denied
(the policy pipeline enforces this: the BEFORE event is written before execution, and a
write error propagates instead of executing).

Integrity model — what :meth:`AuditLog.verify_chain` detects, precisely:

* **edits** to any field of any event (each ``event_hash`` covers the whole event and the
  previous hash), **deletion** of a middle event and **reordering** (``prev_hash`` links
  break), **injected fields** (unknown keys are rejected), and **torn / garbage lines**
  (reported as "line N unparsable", never a traceback);
* **truncation** — dropping the last N events, or emptying the file — via the head anchor
  ``<log>.head.json`` (``{"count", "head"}``), rewritten atomically after every append:
  the log must contain exactly ``count`` events ending at ``head``.

What it does NOT detect: a **full rewrite by someone with write access to both files**
(re-chaining forged events from genesis and rewriting the anchor to match). The chain uses
no secret; a keyed MAC whose key lives next to the log would not change that against a local
attacker either. For tamper-evidence against a local administrator, ship the anchor (or the
whole log) to append-only storage the scanner host cannot rewrite (WORM bucket, remote
syslog, a transparency log) and compare against that copy.

Opening a log never raises. A log whose chain or anchor is broken is opened read-only:
:meth:`AuditLog.append` raises :class:`AuditLogCorrupt` (callers should check
:meth:`AuditLog.ensure_appendable` up front, e.g. when an engagement starts, so the CLI can
report it cleanly instead of failing on the first request).
"""

from __future__ import annotations

import json
import os
import threading
import time

from ..schemas.audit import AuditEvent
from ..util import GENESIS_HASH, canonical_json, now_iso


class AuditLogError(RuntimeError):
    pass


class AuditLogCorrupt(AuditLogError):
    """The existing log failed verification; appending to it is refused (use a fresh work dir,
    or inspect it with ``rampart verify-audit``)."""


def anchor_path_for(path: str) -> str:
    root, _ext = os.path.splitext(path)
    return root + ".head.json"


class AuditLog:
    def __init__(self, path: str):
        self.path = path
        self.anchor_path = anchor_path_for(path)
        self._lock = threading.Lock()
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        ok, msg, count, head, legacy = self._scan()
        self._count = count
        self._head = head if (ok or legacy) else GENESIS_HASH
        self.corrupt_reason = "" if ok else msg
        # a pre-anchor (legacy) log whose chain is intact gets anchored on the next append
        self._legacy_unanchored = legacy

    # ------------------------------------------------------------ anchor I/O
    def _read_anchor(self):
        """Return (anchor_dict | None, error_message)."""
        if not os.path.exists(self.anchor_path):
            return None, ""
        try:
            with open(self.anchor_path, encoding="utf-8") as fh:
                a = json.load(fh)
            if (
                not isinstance(a, dict)
                or not isinstance(a.get("count"), int)
                or not isinstance(a.get("head"), str)
            ):
                return None, f"head anchor {self.anchor_path} is malformed"
            return a, ""
        except (OSError, ValueError) as exc:
            return None, f"head anchor {self.anchor_path} unreadable: {exc}"

    def _write_anchor(self, count: int, head: str) -> None:
        data = canonical_json({"version": 1, "count": count, "head": head, "updated": now_iso()})
        tmp = f"{self.anchor_path}.{os.getpid()}.{threading.get_ident()}.tmp"
        last_exc: Exception | None = None
        for attempt in range(8):  # Windows: a concurrent reader can briefly block os.replace
            try:
                with open(tmp, "w", encoding="utf-8") as fh:
                    fh.write(data)
                os.replace(tmp, self.anchor_path)
                return
            except OSError as exc:
                last_exc = exc
                time.sleep(0.01 * (attempt + 1))
        try:
            os.remove(tmp)
        except OSError:
            pass
        raise AuditLogError(f"could not update audit head anchor (fail-closed): {last_exc}")

    # ---------------------------------------------------------------- verify
    def _scan(self):
        """Verify the file. Returns (ok, message, count, head, legacy_unanchored)."""
        anchor, anchor_err = self._read_anchor()
        if anchor_err:
            return False, anchor_err, 0, GENESIS_HASH, False
        prev, n = GENESIS_HASH, 0
        if os.path.exists(self.path):
            try:
                fh = open(self.path, encoding="utf-8", errors="strict")
            except OSError as exc:
                return False, f"audit log unreadable: {exc}", 0, GENESIS_HASH, False
            with fh:
                lineno = 0
                while True:
                    try:
                        raw = fh.readline()
                    except UnicodeDecodeError:
                        return False, f"line {lineno + 1} unparsable (invalid UTF-8)", n, prev, False
                    if not raw:
                        break
                    lineno += 1
                    line = raw.strip()
                    if not line:
                        continue
                    try:
                        d = json.loads(line)
                    except ValueError:
                        return False, f"line {lineno} unparsable (torn write or tampering)", n, prev, False
                    try:
                        ev = AuditEvent.from_dict(d)
                    except (TypeError, ValueError) as exc:
                        return False, f"line {lineno}: invalid audit event ({exc})", n, prev, False
                    if ev.prev_hash != prev:
                        return (
                            False,
                            f"event #{n} ({ev.event_id}) prev_hash mismatch (line {lineno})",
                            n,
                            prev,
                            False,
                        )
                    if not ev.verify():
                        return (
                            False,
                            f"event #{n} ({ev.event_id}) event_hash mismatch (tampered)",
                            n,
                            prev,
                            False,
                        )
                    prev = ev.event_hash
                    n += 1
        if anchor is None:
            if n == 0:
                return True, "chain intact (empty log)", 0, GENESIS_HASH, False
            return (
                False,
                f"head anchor {os.path.basename(self.anchor_path)} missing — truncation cannot be ruled out "
                f"({n} events; chain otherwise intact)",
                n,
                prev,
                True,
            )
        if anchor["count"] != n or anchor["head"] != prev:
            if n < anchor["count"]:
                why = f"log truncated: head anchor records {anchor['count']} events, log has {n}"
            elif n > anchor["count"]:
                why = f"log has {n} events but head anchor records {anchor['count']} (unanchored events)"
            else:
                why = "head hash does not match the head anchor"
            return False, why, n, prev, False
        return True, f"chain intact ({n} events match the head anchor)", n, prev, False

    def verify_chain(self) -> tuple[bool, str]:
        """Return (ok, message). Recomputes the whole chain from genesis and checks the head
        anchor. Never raises on malformed content."""
        with self._lock:
            ok, msg, _n, _h, _legacy = self._scan()
        return ok, msg

    def ensure_appendable(self) -> None:
        """Raise :class:`AuditLogCorrupt` if this log may not be appended to."""
        if self.corrupt_reason and not self._legacy_unanchored:
            raise AuditLogCorrupt(
                f"existing audit log {self.path} failed verification ({self.corrupt_reason}); "
                "refusing to append — use a fresh --work-dir or inspect it with `rampart verify-audit`"
            )

    # ---------------------------------------------------------------- append
    def append(self, event: AuditEvent) -> AuditEvent:
        with self._lock:
            self.ensure_appendable()
            event.finalize(self._head)
            line = canonical_json(event.to_dict())
            try:
                with open(self.path, "a", encoding="utf-8", newline="\n") as fh:
                    fh.write(line + "\n")
                    fh.flush()
                    os.fsync(fh.fileno())
            except OSError as exc:
                raise AuditLogError(f"could not write audit event (fail-closed): {exc}") from exc
            self._head = event.event_hash
            self._count += 1
            self._write_anchor(self._count, self._head)
            if self._legacy_unanchored:
                self._legacy_unanchored = False
                self.corrupt_reason = ""
            return event

    def read_all(self) -> list[AuditEvent]:
        """Every parsable event, in order. Malformed lines are skipped here — integrity is
        :meth:`verify_chain`'s job, and a display/count path must not crash on a torn line."""
        if not os.path.exists(self.path):
            return []
        out = []
        with open(self.path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(AuditEvent.from_dict(json.loads(line)))
                except (TypeError, ValueError):
                    continue
        return out

    @property
    def head(self) -> str:
        return self._head

    @property
    def count(self) -> int:
        return self._count
