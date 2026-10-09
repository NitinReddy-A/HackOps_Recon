"""Deterministic HTTP client — the ONLY component that touches the network.

Design points that make it safe and replayable:

* connects to the *resolved IP* the allowlist approved, sending an explicit ``Host``
  header — so a DNS rebind between check and connect cannot redirect us (section 23).
  For HTTPS the TCP socket still goes to the vetted IP, but TLS SNI and certificate
  verification use the original *hostname*, so real certificates validate;
* never auto-follows redirects — a 3xx to another host would be a *new* request that must
  re-enter the policy pipeline;
* bounded: every request has a wall-clock deadline (not just a per-read socket timeout) and
  a response-body size cap, so a slow-drip or huge endpoint cannot stall or bloat a scan;
* injects seeded-account sessions from the :class:`SessionManager` (the model passes a
  session *reference*, never a raw token);
* returns a hashed, sized, timed response suitable for the audit log and evidence store.
"""

from __future__ import annotations

import http.client
import socket
import ssl
import threading
import time
from dataclasses import dataclass, field
from urllib.parse import urlencode

from ..schemas.toolcall import ToolAction
from ..util import sha256_hex

DEFAULT_MAX_BODY_BYTES = 5 * 1024 * 1024
_READ_CHUNK = 64 * 1024


@dataclass
class HttpResponse:
    status: int
    headers: dict = field(default_factory=dict)  # last value wins for repeated names
    body: str = ""
    url: str = ""
    duration_ms: float = 0.0
    truncated: bool = False  # body was cut at the client's size cap
    header_list: list = field(default_factory=list)  # every (name, value) pair, in order

    @property
    def size(self) -> int:
        return len(self.body.encode("utf-8", errors="replace"))

    @property
    def body_sha256(self) -> str:
        return sha256_hex(self.body)

    @property
    def set_cookies(self) -> list:
        """All ``Set-Cookie`` values (``headers`` alone keeps only the last one)."""
        return [v for k, v in self.header_list if str(k).lower() == "set-cookie"]


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS to a pre-vetted IP while TLS uses the real hostname for SNI + cert checks."""

    def __init__(self, hostname, connect_ip, port, timeout, context=None):
        super().__init__(hostname, port, timeout=timeout, context=context or ssl.create_default_context())
        self._connect_ip = connect_ip
        self._sni_host = hostname

    def connect(self):
        sock = socket.create_connection((self._connect_ip, self.port), self.timeout, self.source_address)
        try:
            self.sock = self._context.wrap_socket(sock, server_hostname=self._sni_host)
        except BaseException:
            sock.close()
            raise


def _bracket(host: str) -> str:
    """IPv6 literals must be bracketed in a Host header / URL authority (RFC 7230 section 5.4)."""
    return f"[{host}]" if ":" in host and not host.startswith("[") else host


def _host_header(host: str, port: int) -> str:
    h = _bracket(host)
    return h if port in (80, 443) else f"{h}:{port}"


# RFC 2606 / RFC 6761 reserved names: guaranteed never to be a real virtual host, so a test oracle
# may present one as a crafted Host (host-header-injection canary) without any scope impact.
_RESERVED_TLDS = (".example", ".invalid", ".test")


def is_reserved_canary_host(value) -> bool:
    name = str(value or "").strip().lower().rstrip(".")
    name = name.rsplit(":", 1)[0] if name.count(":") == 1 else name
    return bool(name) and name.endswith(_RESERVED_TLDS) and all(c.isalnum() or c in "-." for c in name)


def raw_request(
    scheme,
    host,
    port,
    resolved_ip,
    method,
    path,
    query=None,
    headers=None,
    body=None,
    timeout=10.0,
    max_body_bytes=DEFAULT_MAX_BODY_BYTES,
    ssl_context=None,
    host_header_override=None,
) -> HttpResponse:
    # The Host header is always derived from the vetted target; a Host in ``headers`` is dropped.
    # The only exception is an explicit ``host_header_override`` naming a reserved (non-routable)
    # canary domain, used by the host-header-injection oracle.
    headers = {k: v for k, v in (headers or {}).items() if str(k).lower() != "host"}
    if host_header_override is not None and not is_reserved_canary_host(host_header_override):
        raise ValueError("host_header_override must be a reserved .example/.invalid/.test canary name")
    path_q = path
    if query:
        path_q = f"{path}?{urlencode(query, doseq=True)}"
    # Connect to the vetted IP; assert the intended Host explicitly.
    connect_host = resolved_ip or host
    headers["Host"] = host_header_override or _host_header(host, port)
    headers.setdefault("User-Agent", "Rampart/0.1 (+authorized-security-testing)")
    if scheme == "https":
        conn = _PinnedHTTPSConnection(host, connect_host, port, timeout=timeout, context=ssl_context)
    else:
        conn = http.client.HTTPConnection(connect_host, port, timeout=timeout)

    start = time.monotonic()
    deadline = start + timeout
    timed_out = threading.Event()

    def _expire():
        # Backstop for phases we cannot chunk (TLS handshake, status line, headers): shut the
        # socket so any blocked read returns immediately once the wall-clock deadline passes.
        timed_out.set()
        sock = conn.sock
        if sock is not None:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

    watchdog = threading.Timer(timeout, _expire)
    watchdog.daemon = True
    watchdog.start()

    def _remaining() -> float:
        left = deadline - time.monotonic()
        if left <= 0 or timed_out.is_set():
            raise TimeoutError(f"request exceeded {timeout:.1f}s wall-clock deadline")
        return left

    try:
        try:
            conn.request(method, path_q, body=body, headers=headers)
            if conn.sock is not None:
                conn.sock.settimeout(_remaining())
            resp = conn.getresponse()
            chunks: list[bytes] = []
            got = 0
            truncated = False
            while True:
                left = _remaining()
                if conn.sock is not None:
                    conn.sock.settimeout(left)
                want = min(_READ_CHUNK, max_body_bytes + 1 - got)
                part = resp.read1(want)
                if not part:
                    break
                chunks.append(part)
                got += len(part)
                if got > max_body_bytes:
                    truncated = True
                    break
            if not truncated and not resp.chunked and resp.length:
                # Server closed before sending Content-Length bytes (same as resp.read() would raise).
                raise http.client.IncompleteRead(b"".join(chunks), resp.length)
        except (OSError, http.client.HTTPException):
            if timed_out.is_set() or time.monotonic() >= deadline:
                raise TimeoutError(f"request exceeded {timeout:.1f}s wall-clock deadline") from None
            raise
        raw = b"".join(chunks)[:max_body_bytes]
        dur = (time.monotonic() - start) * 1000.0
        text = raw.decode("utf-8", errors="replace")
        pairs = [(str(k), str(v)) for k, v in resp.getheaders()]
        return HttpResponse(
            status=resp.status,
            headers=dict(pairs),
            body=text,
            url=f"{scheme}://{_bracket(host)}:{port}{path_q}",
            duration_ms=dur,
            truncated=truncated,
            header_list=pairs,
        )
    finally:
        watchdog.cancel()
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
        # Never let a supplied Host re-target the request; only a reserved canary name passes through.
        override = None
        for k in [k for k in headers if str(k).lower() == "host"]:
            v = headers.pop(k)
            if is_reserved_canary_host(v):
                override = v
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
            host_header_override=override,
        )
