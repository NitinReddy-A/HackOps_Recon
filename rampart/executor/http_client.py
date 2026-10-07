"""Deterministic HTTP client — the ONLY component that touches the network.

Design points that make it safe and replayable:

* connects to the *resolved IP* the allowlist approved, sending an explicit ``Host``
  header — so a DNS rebind between check and connect cannot redirect us (section 23);
* never auto-follows redirects — a 3xx to another host would be a *new* request that must
  re-enter the policy pipeline;
* injects seeded-account sessions from the :class:`SessionManager` (the model passes a
  session *reference*, never a raw token);
* returns a hashed, sized, timed response suitable for the audit log and evidence store.
"""
from __future__ import annotations

import http.client
import time
from dataclasses import dataclass, field
from urllib.parse import urlencode

from ..util import sha256_hex
from ..schemas.toolcall import ToolAction


@dataclass
class HttpResponse:
    status: int
    headers: dict = field(default_factory=dict)
    body: str = ""
    url: str = ""
    duration_ms: float = 0.0

    @property
    def size(self) -> int:
        return len(self.body.encode("utf-8", errors="replace"))

    @property
    def body_sha256(self) -> str:
        return sha256_hex(self.body)


def raw_request(scheme, host, port, resolved_ip, method, path, query=None,
                headers=None, body=None, timeout=10.0) -> HttpResponse:
    headers = dict(headers or {})
    path_q = path
    if query:
        path_q = f"{path}?{urlencode(query, doseq=True)}"
    # Connect to the vetted IP; assert the intended Host explicitly.
    connect_host = resolved_ip or host
    headers.setdefault("Host", host if port in (80, 443) else f"{host}:{port}")
    headers.setdefault("User-Agent", "Rampart/0.1 (+authorized-security-testing)")
    if scheme == "https":
        conn = http.client.HTTPSConnection(connect_host, port, timeout=timeout)
    else:
        conn = http.client.HTTPConnection(connect_host, port, timeout=timeout)
    start = time.monotonic()
    try:
        conn.request(method, path_q, body=body, headers=headers)
        resp = conn.getresponse()
        raw = resp.read()
        dur = (time.monotonic() - start) * 1000.0
        text = raw.decode("utf-8", errors="replace")
        hdrs = {k: v for k, v in resp.getheaders()}
        return HttpResponse(status=resp.status, headers=hdrs, body=text,
                            url=f"{scheme}://{host}:{port}{path_q}", duration_ms=dur)
    finally:
        conn.close()


class HttpExecutor:
    """Executes a vetted :class:`ToolAction`. Instantiated once per engagement."""

    def __init__(self, session_manager=None, timeout: float = 10.0):
        self.sessions = session_manager
        self.timeout = timeout

    def execute(self, action: ToolAction, resolved_ip: str) -> HttpResponse:
        headers: dict[str, str] = {}
        if action.use_session and self.sessions is not None:
            headers.update(self.sessions.auth_headers(action.use_session))
        # Extra headers (e.g. a crafted test token from a deterministic oracle) override session auth.
        if action.headers:
            headers.update(action.headers)
        body = action.body
        if body is not None and "Content-Type" not in headers:
            headers["Content-Type"] = "application/json"
        return raw_request(
            scheme=action.scheme,
            host=action.target_host,
            port=action.port,
            resolved_ip=resolved_ip,
            method=action.method,
            path=action.path,
            query=action.query,
            headers=headers,
            body=body,
            timeout=self.timeout,
        )
