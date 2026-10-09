"""Small, dependency-free helpers shared across the platform.

Everything here is deterministic (no randomness in hashing, canonical JSON with
sorted keys) so that an engagement can be replayed and audited byte-for-byte.
"""

from __future__ import annotations

import hashlib
import json
import re
import secrets
import time
from datetime import datetime, timezone
from typing import Any

GENESIS_HASH = "0" * 64

# Headers whose values must never be written to logs/evidence in the clear.
SENSITIVE_HEADERS = {
    "authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
    "proxy-authorization",
}

_SECRET_PATTERNS = [
    re.compile(r"(?i)(bearer\s+)[A-Za-z0-9\-._~+/]+=*"),
    re.compile(r"(?i)(api[_-]?key\"?\s*[:=]\s*\"?)[A-Za-z0-9\-._]{8,}"),
    re.compile(r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+"),  # JWT
]


def now_iso() -> str:
    """RFC3339 UTC timestamp."""
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def monotonic_ms() -> float:
    return time.monotonic() * 1000.0


def canonical_json(obj: Any) -> str:
    """Stable JSON encoding used for hashing (sorted keys, no whitespace)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def sha256_hex(data: str | bytes) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def chain_hash(event_without_hash: dict, prev_hash: str) -> str:
    """Hash for the append-only audit chain: sha256(prev_hash || canonical(event))."""
    return sha256_hex(prev_hash + canonical_json(event_without_hash))


def gen_id(prefix: str) -> str:
    """Short, sortable-ish unique id, e.g. ``fnd_a1b2c3d4e5``."""
    return f"{prefix}_{secrets.token_hex(6)}"


def redact_headers(headers: dict[str, str]) -> dict[str, str]:
    out = {}
    for k, v in headers.items():
        if k.lower() in SENSITIVE_HEADERS:
            out[k] = f"<redacted:sha256:{sha256_hex(v)[:12]}>"
        else:
            out[k] = v
    return out


def _redact_value(v: Any) -> str:
    return f"<redacted:sha256:{sha256_hex(str(v))[:12]}>"


def redact_params(params: dict) -> dict:
    """Keep parameter NAMES, replace every value (or each item of a list value) with a short
    hash marker, so audit logs show which parameters were sent without leaking tokens,
    credentials or payloads that may be personal data."""
    out: dict[str, Any] = {}
    for k, v in (params or {}).items():
        if isinstance(v, (list, tuple)):
            out[str(k)] = [_redact_value(x) for x in v]
        else:
            out[str(k)] = _redact_value(v)
    return out


def scrub_secrets(text: str) -> str:
    """Best-effort redaction of secret-looking substrings before persisting text."""
    if not text:
        return text
    for pat in _SECRET_PATTERNS:
        text = pat.sub(lambda m: (m.group(1) if m.groups() else "") + "<redacted>", text)
    return text
