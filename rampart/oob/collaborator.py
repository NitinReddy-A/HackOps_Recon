"""The OOB collaborator server (stdlib only)."""

from __future__ import annotations

import secrets
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


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

    def __init__(self, host: str = "127.0.0.1", port: int = 0):
        self.host = host
        self._want_port = port
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
        return f"http://{self.host}:{self.port}"

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
