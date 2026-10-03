"""An intentionally-vulnerable demo API — the isolated target we OWN and test against.

This is the offline analog of OWASP crAPI / Juice Shop's BOLA challenge (blueprint section 25):
a tiny, dependency-free HTTP API with a deliberate **object-level authorization (IDOR/BOLA)**
flaw and missing security headers, so Rampart can be validated end-to-end without ever
touching a third party. Run it, point Rampart at it, tear it down.

    python vulnerable_app.py --port 8080            # vulnerable (default)
    python vulnerable_app.py --port 8080 --fixed     # patched: enforces ownership -> retest passes

Auth IS enforced (bad token -> 401, missing order -> 404); only *ownership* is missing,
which is exactly what makes the BOLA differential oracle decidable.
"""
from __future__ import annotations

import argparse
import json
import os
import secrets
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# Seeded, non-production data. Each order carries a distinctive signature the oracle checks.
USERS = {
    "user_a": {"id": "u1", "password": "demo-pw-a", "email": "user_a@demo.local"},
    "user_b": {"id": "u2", "password": "demo-pw-b", "email": "user_b@demo.local"},
}
ORDERS = {
    "1043": {"id": "1043", "owner": "u1", "owner_email": "user_a@demo.local",
             "item": "Blue Widget", "total": "42.00",
             "secret_note": "SIGNATURE-A-4f9c1e77 (private to user_a)"},
    "2087": {"id": "2087", "owner": "u2", "owner_email": "user_b@demo.local",
             "item": "Red Gadget", "total": "17.50",
             "secret_note": "SIGNATURE-B-1a2b3c4d (private to user_b)"},
}

FIXED = os.environ.get("RAMPART_DEMO_FIXED") == "1"
_TOKENS: dict[str, str] = {}  # token -> user id

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Content-Security-Policy": "default-src 'none'",
    "Strict-Transport-Security": "max-age=63072000",
}


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):  # keep the demo quiet
        pass

    def _send(self, status, obj, secure_headers=False):
        body = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        # VULN (default): security headers are omitted. --fixed adds them.
        if secure_headers or FIXED:
            for k, v in SECURITY_HEADERS.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _auth_user(self):
        auth = self.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            return _TOKENS.get(auth[7:])
        return None

    def _authorize(self, record, uid):
        # object-level authorization — only invoked in the patched (--fixed) build
        return record["owner"] == uid

    def do_POST(self):
        if self.path == "/api/login":
            length = int(self.headers.get("Content-Length", 0))
            try:
                data = json.loads(self.rfile.read(length) or b"{}")
            except json.JSONDecodeError:
                return self._send(400, {"error": "bad json"})
            u = USERS.get(data.get("username", ""))
            if not u or u["password"] != data.get("password"):
                return self._send(401, {"error": "invalid credentials"})
            token = f"tok-{u['id']}-{secrets.token_hex(8)}"
            _TOKENS[token] = u["id"]
            return self._send(200, {"token": token, "user_id": u["id"]})
        return self._send(404, {"error": "not found"})

    def do_GET(self):
        if self.path == "/":
            return self._send(200, {"service": "demo-shop-api", "endpoints": ["/api/login", "/api/orders/{id}"]})
        if self.path.startswith("/api/orders/"):
            oid = self.path.rsplit("/", 1)[-1]
            uid = self._auth_user()
            if uid is None:
                return self._send(401, {"error": "authentication required"})   # auth IS enforced
            order = ORDERS.get(oid)
            if order is None:
                return self._send(404, {"error": "order not found"})           # absent -> 404
            if FIXED and not self._authorize(order, uid):
                return self._send(403, {"error": "forbidden"})                 # the fix (patched build)
            return self._send(200, order)                                      # VULN: no ownership check here
        return self._send(404, {"error": "not found"})


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--fixed", action="store_true", help="enable the ownership check (patched build)")
    args = ap.parse_args()
    global FIXED
    if args.fixed:
        FIXED = True
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    bound_port = server.server_address[1]
    mode = "FIXED (ownership enforced)" if FIXED else "VULNERABLE (IDOR/BOLA present)"
    print(f"demo-shop-api listening on http://{args.host}:{bound_port}  [{mode}]", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()


if __name__ == "__main__":
    main()
