"""The OOB collaborator server (stdlib only)."""

from __future__ import annotations

import ipaddress
import secrets
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit


def _is_loopback_host(host: str) -> bool:
    h = (host or "").strip("[]").lower()
    if h in ("localhost", "localhost.localdomain") or h.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(h).is_loopback
    except ValueError:
        return False


def oob_skip_reason(target_url: str, collaborator) -> str:
    """ "" if the OOB pass can produce a meaningful result, else why it must be skipped.

    A loopback collaborator (the safe default) can only be called back by a target running on
    this same machine. Injecting ``http://127.0.0.1:<port>/…`` into a REMOTE target would make
    that target request its OWN loopback interface — never our listener — so every probe would
    be a guaranteed miss (and a pointless request into the target's internal services). In that
    case we skip with this reason instead of injecting.
    """
    target_host = urlsplit(target_url or "").hostname or ""
    if getattr(collaborator, "is_loopback", True) and not _is_loopback_host(target_host):
        return (
            f"oob: skipped — target {target_host or target_url!r} is not loopback and no external "
            "collaborator is configured (the default 127.0.0.1 listener is unreachable from it); "
            "set an externally reachable collaborator URL to enable blind SSRF/XXE"
        )
    return ""


class OOBCollaborator:
    """A loopback HTTP server that records inbound hits keyed by a unique per-probe token.

    Usage:
        c = OOBCollaborator(); c.start()
        tok, url = c.new_token()          # inject `url` into the suspected SSRF/XXE sink
        ...                               # run the probe
        if c.wait_for(tok, timeout=3):    # target called back -> blind vuln confirmed
            ...
        c.stop()
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 0, public_url: str = ""):
        """``host``/``port``: where the listener binds (loopback by default — safe).

        ``public_url``: the externally reachable base URL injected into payloads when the
        listener sits behind NAT / a tunnel / a separate collaborator host (e.g.
        ``http://oob.example.net:8000``). Empty = advertise ``http://<host>:<port>``.
        """
        self.host = host
        self._want_port = port
        self.public_url = (public_url or "").rstrip("/")
        self._hits: dict[str, list] = {}
        self._lock = threading.Lock()
        self._httpd = None
        self._thread = None
        self.port = None

    def start(self):
        collaborator = self

        class _Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):
                pass

            def _record(self):
                token = self.path.strip("/").split("/", 1)[0].split("?", 1)[0]
                with collaborator._lock:
                    collaborator._hits.setdefault(token, []).append(
                        {"at": time.time(), "path": self.path, "ua": self.headers.get("User-Agent", "")}
                    )
                body = b"rampart-oob-ok"
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                try:
                    self.wfile.write(body)
                except Exception:  # noqa: BLE001
                    pass

            def do_GET(self):
                self._record()

            def do_POST(self):
                self._record()

        self._httpd = ThreadingHTTPServer((self.host, self._want_port), _Handler)
        self.port = self._httpd.server_address[1]
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()
        return self

    @property
    def base_url(self) -> str:
        if self.public_url:
            return self.public_url
        return f"http://{self.host}:{self.port}"

    @property
    def advertised_host(self) -> str:
        return urlsplit(self.base_url).hostname or ""

    @property
    def is_loopback(self) -> bool:
        """True when the URL injected into payloads points at a loopback address."""
        return _is_loopback_host(self.advertised_host)

    def new_token(self) -> tuple[str, str]:
        tok = "oob" + secrets.token_hex(8)
        return tok, f"{self.base_url}/{tok}"

    def received(self, token: str) -> bool:
        with self._lock:
            return bool(self._hits.get(token))

    def hits(self, token: str) -> list:
        with self._lock:
            return list(self._hits.get(token, []))

    def wait_for(self, token: str, timeout: float = 3.0, interval: float = 0.1) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.received(token):
                return True
            time.sleep(interval)
        return self.received(token)

    def stop(self):
        if self._httpd is not None:
            self._httpd.shutdown()
            self._httpd.server_close()
            self._httpd = None
