"""An intentionally-vulnerable demo API — the isolated target we OWN and test against.

This is the offline analog of OWASP crAPI / Juice Shop (blueprint section 25): a tiny,
dependency-free HTTP API with a set of *deliberate, textbook* flaws, so Rampart can be
validated end-to-end without ever touching a third party. Every flaw has a matching clean
behaviour under ``--fixed`` so the false-positive gate and retest flow are provable too.

    python vulnerable_app.py --port 8080            # vulnerable (default)
    python vulnerable_app.py --port 8080 --fixed    # patched: every oracle drops -> retest passes

Planted flaws (each flips clean under --fixed):
  * IDOR / BOLA          GET  /api/orders/{id}     — auth enforced, ownership NOT checked
  * Reflected XSS        GET  /api/search?q=        — q reflected into HTML unescaped
  * SQL injection        GET  /api/products?id=     — id concatenated into a query (error + boolean)
  * Open redirect        GET  /api/go?next=         — Location set to an attacker URL
  * Missing sec-headers  (all responses)            — CSP/XFO/nosniff/HSTS omitted
  * Insecure cookie      POST /api/login            — session cookie without HttpOnly/Secure/SameSite
  * CORS misconfig       (API responses)            — ACAO:* together with ACAC:true
"""
from __future__ import annotations

import argparse
import html
import json
import os
import secrets
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

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
PRODUCTS = {
    "1": {"id": "1", "name": "Blue Widget", "price": "42.00"},
    "2": {"id": "2", "name": "Red Gadget", "price": "17.50"},
    "3": {"id": "3", "name": "Green Gizmo", "price": "9.99"},
}

FIXED = os.environ.get("RAMPART_DEMO_FIXED") == "1"
_TOKENS: dict[str, str] = {}  # token -> user id

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Content-Security-Policy": "default-src 'none'",
    "Strict-Transport-Security": "max-age=63072000",
}


class _FakeSQLError(Exception):
    """Stand-in for a backend DB driver error surfaced to the client (error-based SQLi)."""


def _fake_sql_select(raw: str, fixed: bool):
    """Model the classic ``SELECT * FROM products WHERE id = '<raw>'`` sink.

    Vulnerable: ``raw`` is concatenated into the predicate, so an unbalanced quote breaks
    the statement (error-based) and boolean conditions change the result set (boolean-based).
    Fixed: ``raw`` is a bound parameter — a literal id, never SQL — so it can neither error
    nor change the logic.
    """
    if fixed:
        row = PRODUCTS.get(raw)
        return [row] if row else []
    predicate = "'" + raw + "'"
    if predicate.count("'") % 2 == 1:  # unterminated string literal
        raise _FakeSQLError('SQLSTATE[42000]: syntax error at or near "\'" — unterminated quoted string')
    low = raw.lower()
    if "or '1'='1" in low or "or 1=1" in low:        # tautology -> dump every row
        return list(PRODUCTS.values())
    if "and '1'='2" in low or "and 1=2" in low:      # always-false condition -> empty
        return []
    if "and '1'='1" in low or "and 1=1" in low:      # always-true condition -> base row
        base = raw.split("'", 1)[0]
        row = PRODUCTS.get(base)
        return [row] if row else []
    row = PRODUCTS.get(raw)                           # benign lookup
    return [row] if row else []


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):  # keep the demo quiet
        pass

    def version_string(self):
        # VULN (default): leak software + version in the Server header. --fixed genericises it.
        return "demo-shop-api" if FIXED else "demo-shop-api/0.9 (Python/3.12 BaseHTTP/0.6)"

    # ---- response helpers --------------------------------------------------
    def _cors(self):
        # VULN (default): reflect any origin AND allow credentials (ACAO:* + ACAC:true is unsafe).
        if FIXED:
            return {"Access-Control-Allow-Origin": "https://demo.local"}
        return {"Access-Control-Allow-Origin": "*", "Access-Control-Allow-Credentials": "true"}

    def _send(self, status, obj, extra_headers=None):
        body = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        if FIXED:
            for k, v in SECURITY_HEADERS.items():
                self.send_header(k, v)
        for k, v in (self._cors()).items():
            self.send_header(k, v)
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, status, markup: str):
        body = markup.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        if FIXED:
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

    # ---- routes ------------------------------------------------------------
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
            # VULN (default): session cookie lacks HttpOnly/Secure/SameSite. --fixed adds them.
            if FIXED:
                cookie = f"session={token}; Path=/; HttpOnly; Secure; SameSite=Strict"
            else:
                cookie = f"session={token}; Path=/"
            return self._send(200, {"token": token, "user_id": u["id"]}, {"Set-Cookie": cookie})
        return self._send(404, {"error": "not found"})

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        q = {k: v[0] for k, v in parse_qs(parsed.query).items()}

        if path == "/":
            return self._send(200, {"service": "demo-shop-api",
                                    "endpoints": ["/api/login", "/api/orders/{id}",
                                                  "/api/search", "/api/products", "/api/go"]})

        # Reflected XSS: q echoed into an HTML page. Vulnerable: raw. Fixed: html-escaped.
        if path == "/api/search":
            term = q.get("q", "")
            shown = html.escape(term) if FIXED else term
            markup = (f"<!doctype html><html><body><h1>Results</h1>"
                      f"<p>You searched for: {shown}</p></body></html>")
            return self._send_html(200, markup)

        # SQL injection: id flows into a query sink. Vulnerable: concatenated. Fixed: bound.
        if path == "/api/products":
            raw = q.get("id", "")
            try:
                rows = _fake_sql_select(raw, FIXED)
            except _FakeSQLError as exc:
                # VULN: raw driver error leaked to the client (error-based signal).
                return self._send(500, {"error": "database error", "detail": str(exc),
                                        "sqlstate": "42000"})
            return self._send(200, {"results": rows, "count": len(rows)})

        # Open redirect: next reflected into Location. Vulnerable: any URL. Fixed: local only.
        if path == "/api/go":
            nxt = q.get("next", "/")
            if FIXED:
                # only same-site relative paths are allowed
                if nxt.startswith("/") and not nxt.startswith("//"):
                    return self._send(302, {"redirect": nxt}, {"Location": nxt})
                return self._send(400, {"error": "invalid redirect target"})
            return self._send(302, {"redirect": nxt}, {"Location": nxt})

        if path.startswith("/api/orders/"):
            oid = path.rsplit("/", 1)[-1]
            uid = self._auth_user()
            if uid is None:
                return self._send(401, {"error": "authentication required"})   # auth IS enforced
            order = ORDERS.get(oid)
            if order is None:
                return self._send(404, {"error": "order not found"})           # absent -> 404
            if FIXED and not self._authorize(order, uid):
                return self._send(403, {"error": "forbidden"})                 # the fix (patched build)
            return self._send(200, order)                                      # VULN: no ownership check
        return self._send(404, {"error": "not found"})


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--fixed", action="store_true", help="enable every fix (patched build)")
    args = ap.parse_args()
    global FIXED
    if args.fixed:
        FIXED = True
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    bound_port = server.server_address[1]
    mode = "FIXED (all controls enforced)" if FIXED else "VULNERABLE (planted flaws present)"
    print(f"demo-shop-api listening on http://{args.host}:{bound_port}  [{mode}]", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()


if __name__ == "__main__":
    main()
