"""Content-addressed evidence store.

Every artifact is secret-scrubbed, hashed, and written under its own sha256 so an evidence
reference in a finding resolves to an immutable, verifiable blob. Redaction is on by default
(blueprint section 23, threats #7/#9).
"""

from __future__ import annotations

import os
import secrets as _secrets

from ..schemas.finding import Evidence
from ..util import redact_headers, scrub_secrets, sha256_hex


class EvidenceStore:
    def __init__(self, base_dir: str):
        self.base_dir = base_dir
        os.makedirs(base_dir, exist_ok=True)

    def _write(self, content: str) -> str:
        digest = sha256_hex(content)
        path = os.path.join(self.base_dir, digest[:2], digest)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        if not os.path.exists(path):
            # Content-addressed + idempotent: safe for concurrent writers. Write to a unique
            # temp file then atomically replace, so two threads racing on the same digest can
            # never leave a torn/half-written blob (os.replace is atomic on POSIX and Windows).
            tmp = f"{path}.{_secrets.token_hex(4)}.tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                fh.write(content)
            try:
                os.replace(tmp, path)
            except OSError:
                # Lost the race (another thread already produced the identical blob); drop temp.
                try:
                    os.remove(tmp)
                except OSError:
                    pass
        return digest

    def put_text(self, kind: str, summary: str, text: str) -> Evidence:
        safe = scrub_secrets(text or "")
        digest = self._write(safe)
        return Evidence(
            type=kind, summary=summary, storage_uri=f"evidence://{digest}", sha256=digest, redacted=True
        )

    def put_request(self, action, resolved_ip: str, summary: str = "") -> Evidence:
        lines = [
            f"{action.method} {action.path} HTTP/1.1",
            f"Host: {action.target_host}:{action.port}",
            f"(resolved-ip: {resolved_ip})",
            f"(session: {action.use_session}, payload_class: {action.payload_class})",
        ]
        if action.query:
            lines.append(f"Query: {action.query}")
        if action.body:
            lines.append("")
            lines.append(action.body)
        return self.put_text("http_request", summary or f"{action.method} {action.path}", "\n".join(lines))

    def put_response(self, response, summary: str = "") -> Evidence:
        hdrs = redact_headers(response.headers or {})
        header_txt = "\n".join(f"{k}: {v}" for k, v in hdrs.items())
        text = f"HTTP {response.status}\n{header_txt}\n\n{response.body}"
        return self.put_text("http_response", summary or f"HTTP {response.status}", text)

    def read(self, uri_or_digest: str) -> str:
        digest = uri_or_digest.replace("evidence://", "")
        path = os.path.join(self.base_dir, digest[:2], digest)
        with open(path, encoding="utf-8") as fh:
            return fh.read()
