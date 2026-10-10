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
import base64
import hashlib
import hmac
import html
import json
import os
import re
import secrets
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

# Seeded, non-production data. Each order carries a distinctive signature the oracle checks.
USERS = {
    "user_a": {"id": "u1", "password": "demo-pw-a", "email": "user_a@demo.local"},
    "user_b": {"id": "u2", "password": "demo-pw-b", "email": "user_b@demo.local"},
}
ORDERS = {
    "1043": {
        "id": "1043",
        "owner": "u1",
        "owner_email": "user_a@demo.local",
        "item": "Blue Widget",
        "total": "42.00",
        "secret_note": "SIGNATURE-A-4f9c1e77 (private to user_a)",
    },
    "2087": {
        "id": "2087",
        "owner": "u2",
        "owner_email": "user_b@demo.local",
        "item": "Red Gadget",
        "total": "17.50",
        "secret_note": "SIGNATURE-B-1a2b3c4d (private to user_b)",
    },
}
PRODUCTS = {
    "1": {"id": "1", "name": "Blue Widget", "price": "42.00"},
    "2": {"id": "2", "name": "Red Gadget", "price": "17.50"},
    "3": {"id": "3", "name": "Green Gizmo", "price": "9.99"},
}

FIXED = os.environ.get("RAMPART_DEMO_FIXED") == "1"
# HS256 signing key for /api/v2/me. Selected at REQUEST time (see the handler) because --fixed flips
# FIXED after this module loads: a guessable secret in VULN mode, a strong random one when FIXED.
_JWT_V2_STRONG = "a7f3c9e1b5d8402e6f1a9c4b7e2d8053a1c6f9b2e4d7018a3c5f8b1d6e9a2c4f7"
_JWT_V2_WEAK = "secret"
_TOKENS: dict[str, str] = {}  # token -> user id
_COMMENTS: list[str] = []  # stored-XSS sink (in-memory)

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Content-Security-Policy": "default-src 'none'",
    "Strict-Transport-Security": "max-age=63072000",
}


# Inert markers returned by the simulated sinks below (no real shell/network/filesystem).
SSRF_MARKER = "RAMPART-SSRF-INTERNAL iam-role=demo-admin;token=AKIA-DEMO"
TRAVERSAL_MARKER = "RAMPART-TRAVERSAL root:x:0:0:root:/root:/bin/bash"

# Sensitive files that must never be web-served (exposed only in VULN mode).
SENSITIVE_FILES = {
    "/.env": "DB_PASSWORD=sup3rs3cr3t\nAPI_KEY=RAMPART-ENV-LEAK-7f3a\nDEBUG=true",
    "/.git/config": "[core]\n repositoryformatversion = 0\n# RAMPART-GIT-LEAK remote origin url",
    "/backup.sql": "-- RAMPART-BACKUP-LEAK MySQL dump\nINSERT INTO users VALUES(1,'admin','hash');",
    "/config.json": '{"db":{"password":"RAMPART-CONFIG-LEAK"},"debug":true}',
}

_SSTI_EXPR = re.compile(r"\{\{\s*(\d+)\s*\*\s*(\d+)\s*\}\}")

# Command-injection sink: simulate a shell `echo <arg>` with no real shell and no eval. Only two
# tightly bounded forms are "executed": arithmetic expansion `$((int op int))` (op in + - *) and
# command substitution `$(echo text)`. Anything else is echoed literally, exactly as a reflecting
# `echo` would. This lets the demo's CMDI be confirmed by a COMPUTED proof (the product the probe
# itself never contains) instead of a magic marker a reflecting endpoint could fake.
_CMD_ARITH = re.compile(r"^\$\(\(\s*(-?\d+)\s*([+\-*])\s*(-?\d+)\s*\)\)$")
_CMD_ECHO_SUBST = re.compile(r"^\$\(\s*echo\s+(.*?)\s*\)$")


def _demo_shell_echo(arg: str) -> str:
    """Model what a real shell would print for the injected ``echo <arg>`` — safely (no shell, no
    eval): evaluate ``$((int op int))`` and ``$(echo text)``; otherwise echo the literal argument."""
    arg = arg.strip()
    m = _CMD_ARITH.match(arg)
    if m:
        a, op, b = int(m.group(1)), m.group(2), int(m.group(3))
        return str({"+": a + b, "-": a - b, "*": a * b}[op])
    m = _CMD_ECHO_SUBST.match(arg)
    if m:
        return m.group(1).strip(" `)'\"")
    return arg.strip(" `)'\"")


def _b64url_decode(s: str) -> bytes:
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s.encode())


_INTERNAL_HOSTS = {
    "127.0.0.1",
    "localhost",
    "169.254.169.254",
    "metadata.google.internal",
    "metadata",
    "0.0.0.0",
    "[::1]",
    "::1",
}


def _is_internal(host: str) -> bool:
    if not host:
        return False
    host = host.lower().strip("[]")
    if host in _INTERNAL_HOSTS:
        return True
    return (
        host.startswith("10.")
        or host.startswith("192.168.")
        or host.startswith("127.")
        or host.startswith("169.254.")
        or any(host.startswith(f"172.{n}.") for n in range(16, 32))
    )


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
    if "or '1'='1" in low or "or 1=1" in low:  # tautology -> dump every row
        return list(PRODUCTS.values())
    if "and '1'='2" in low or "and 1=2" in low:  # always-false condition -> empty
        return []
    if "and '1'='1" in low or "and 1=1" in low:  # always-true condition -> base row
        base = raw.split("'", 1)[0]
        row = PRODUCTS.get(base)
        return [row] if row else []
    row = PRODUCTS.get(raw)  # benign lookup
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
        for k, v in (self._cors()).items():
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

        # Mass assignment / BOPLA: profile update that honours client-supplied privileged fields.
        if self.path == "/api/account":
            length = int(self.headers.get("Content-Length", 0))
            try:
                data = json.loads(self.rfile.read(length) or b"{}")
            except json.JSONDecodeError:
                return self._send(400, {"error": "bad json"})
            resp = {"name": data.get("name", "user"), "role": "customer", "is_admin": False}
            if not FIXED:  # VULN: bind whatever the client sent
                for priv in ("role", "is_admin", "balance", "verified"):
                    if priv in data:
                        resp[priv] = data[priv]
            return self._send(200, resp)

        # XXE: parse user XML with external entities enabled (VULN) → fetches SYSTEM URL (blind).
        if self.path == "/api/import":
            length = int(self.headers.get("Content-Length", 0))
            raw = (self.rfile.read(length) or b"").decode("utf-8", "replace")
            m = re.search(r'SYSTEM\s+["\']([^"\']+)["\']', raw)
            if (not FIXED) and m:  # VULN: external entity resolution enabled
                host = urlparse(m.group(1)).hostname or ""
                if _is_internal(host):  # demo only fetches loopback/internal (safe)
                    try:
                        urllib.request.urlopen(m.group(1), timeout=2).read(64)
                    except Exception:  # noqa: BLE001
                        pass
            return self._send(200, {"status": "imported"})  # blind: same response either way

        # Stored XSS: persist a comment, rendered back (unescaped in VULN) on GET /api/comments.
        if self.path == "/api/comments":
            length = int(self.headers.get("Content-Length", 0))
            try:
                data = json.loads(self.rfile.read(length) or b"{}")
            except json.JSONDecodeError:
                return self._send(400, {"error": "bad json"})
            _COMMENTS.append(str(data.get("text", ""))[:2000])
            return self._send(200, {"stored": True, "count": len(_COMMENTS)})

        # GraphQL endpoint: introspection enabled in VULN mode.
        if self.path in ("/graphql", "/api/graphql"):
            length = int(self.headers.get("Content-Length", 0))
            try:
                data = json.loads(self.rfile.read(length) or b"{}")
            except json.JSONDecodeError:
                return self._send(400, {"error": "bad json"})
            query = str(data.get("query", ""))
            if "__schema" in query or "__type" in query:
                if FIXED:
                    return self._send(400, {"errors": [{"message": "introspection is disabled"}]})
                return self._send(
                    200,
                    {
                        "data": {
                            "__schema": {"types": [{"name": "Query"}, {"name": "Order"}, {"name": "User"}]}
                        }
                    },
                )
            return self._send(200, {"data": {}})

        return self._send(404, {"error": "not found"})

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        q = {k: v[0] for k, v in parse_qs(parsed.query).items()}

        if path == "/":
            # HTML landing page so the recon crawler can discover endpoints + params.
            page = (
                "<!doctype html><html><head><title>demo-shop-api</title></head><body>"
                "<h1>Demo Shop</h1><ul>"
                '<li><a href="/api/search?q=widget">Search</a></li>'
                '<li><a href="/api/products?id=1">Products</a></li>'
                '<li><a href="/api/go?next=/account">Continue</a></li>'
                '<li><a href="/api/orders/1043">Your order</a></li>'
                '<li><a href="/api/profile">Profile</a></li>'
                '<li><a href="/api/reports/orders">Reports</a></li>'
                '<li><a href="/api/fetch?url=https://example.com">Fetch</a></li>'
                '<li><a href="/api/ping?host=127.0.0.1">Ping</a></li>'
                '<li><a href="/api/file?name=readme.txt">File</a></li>'
                "</ul>"
                '<form action="/api/search" method="get">'
                '<input name="q" placeholder="search"><button>Go</button></form>'
                "</body></html>"
            )
            return self._send_html(200, page)

        # Stored-XSS display page: renders stored comments (unescaped in VULN mode).
        if path == "/api/comments":
            items = "".join(
                (f"<li>{c}</li>" if not FIXED else f"<li>{html.escape(c)}</li>") for c in _COMMENTS
            )
            return self._send_html(
                200,
                f"<!doctype html><html><body><h1>Comments</h1><ul id='comments'>{items}</ul></body></html>",
            )

        # Host-header injection: a password-reset link built from the incoming Host header.
        if path == "/api/reset":
            email = q.get("email", "user@demo.local")
            host = (
                self.headers.get("Host", "demo.local") if not FIXED else "demo.local"
            )  # VULN uses attacker Host
            link = f"https://{host}/reset?token=demo-reset-token&email={email}"
            return self._send(200, {"reset_link": link, "sent_to": email})

        # DOM XSS: a page whose client-side JS writes a URL param into the DOM via innerHTML.
        # The sink is in the browser (JS), so only a headless-browser oracle can confirm it.
        if path == "/dom":
            if FIXED:
                page = (
                    "<!doctype html><html><body><div id='out'></div>"
                    "<script>var p=new URLSearchParams(location.search).get('x')||'';"
                    "document.getElementById('out').textContent=p;</script></body></html>"
                )
            else:
                page = (
                    "<!doctype html><html><body><div id='out'></div>"
                    "<script>var p=new URLSearchParams(location.search).get('x')||'';"
                    "document.getElementById('out').innerHTML=p;</script></body></html>"
                )
            return self._send_html(200, page)

        # Reflected XSS: q echoed into an HTML page. Vulnerable: raw. Fixed: html-escaped.
        if path == "/api/search":
            term = q.get("q", "")
            shown = html.escape(term) if FIXED else term
            markup = (
                f"<!doctype html><html><body><h1>Results</h1><p>You searched for: {shown}</p></body></html>"
            )
            return self._send_html(200, markup)

        # SQL injection: id flows into a query sink. Vulnerable: concatenated. Fixed: bound.
        if path == "/api/products":
            raw = q.get("id", "")
            try:
                rows = _fake_sql_select(raw, FIXED)
            except _FakeSQLError as exc:
                # VULN: raw driver error leaked to the client (error-based signal).
                return self._send(500, {"error": "database error", "detail": str(exc), "sqlstate": "42000"})
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

        # SSRF: server-side fetch of a user-supplied URL (simulated — no real network call).
        if path == "/api/fetch":
            from urllib.parse import urlparse as _up

            target = q.get("url", "")
            host = _up(target).hostname or ""
            scheme = _up(target).scheme or ""
            internal = _is_internal(host) or scheme == "file"
            if FIXED:
                if internal or scheme not in ("http", "https"):
                    return self._send(400, {"error": "blocked: destination not allowed"})
                return self._send(200, {"fetched": target, "content": "external resource ok"})
            if internal:
                return self._send(200, {"fetched": target, "content": SSRF_MARKER})  # SSRF to internal
            return self._send(200, {"fetched": target, "content": "external resource ok"})

        # Blind SSRF: a "webhook" that fetches the URL server-side with NO response signal.
        # VULN actually performs the internal fetch (so an OOB collaborator gets a callback);
        # --fixed blocks internal destinations. Response is identical either way (blind).
        if path == "/api/webhook":
            target = q.get("url", "")
            host = urlparse(target).hostname or ""
            if FIXED:
                if _is_internal(host) or urlparse(target).scheme not in ("http", "https"):
                    return self._send(400, {"error": "destination not allowed"})
                return self._send(200, {"status": "queued"})
            if _is_internal(host):  # VULN: perform the server-side fetch (blind SSRF)
                try:
                    urllib.request.urlopen(target, timeout=2).read(64)
                except Exception:  # noqa: BLE001
                    pass
            return self._send(200, {"status": "queued"})  # blind: same response regardless

        # Command injection: simulated `ping <host>` that honours shell metacharacters.
        if path == "/api/ping":
            host = q.get("host", "")
            out = f"PING {host.split(';')[0].split('|')[0].split('&')[0].strip()} 56 bytes"
            if not FIXED:
                # naive concatenation: execute an injected `; echo X` / `| echo X` / `&& echo X`
                for sep in (";", "|", "&&", "&", "`", "$("):
                    if sep in host and "echo" in host:
                        injected = _demo_shell_echo(host.split("echo", 1)[1])
                        out += "\n" + injected
                        break
            return self._send(200, {"output": out})

        # Path traversal: simulated file read from a sandbox (markers, not real files).
        if path == "/api/file":
            name = q.get("name", "")
            escapes = ".." in name or name.startswith("/") or name.startswith("\\")
            if FIXED:
                if escapes or "/" in name or "\\" in name:
                    return self._send(400, {"error": "invalid file name"})
                return self._send(200, {"name": name, "content": "demo file contents"})
            if escapes:
                return self._send(200, {"name": name, "content": TRAVERSAL_MARKER})  # traversal!
            known = {"readme.txt": "demo file contents", "notes.txt": "some notes"}
            if name in known:
                return self._send(200, {"name": name, "content": known[name]})
            return self._send(404, {"error": "file not found"})

        # Business-logic flaw: a price quote that accepts a negative quantity -> negative total
        # (store-credit / refund abuse). No deterministic oracle catches this — it needs reasoning
        # about intended behaviour; the business-logic AGENT finds it.
        if path == "/api/checkout":
            item = q.get("item", "1")
            prod = PRODUCTS.get(item)
            try:
                qty = int(q.get("qty", "1"))
            except ValueError:
                return self._send(400, {"error": "bad quantity"})
            if prod is None:
                return self._send(404, {"error": "unknown item"})
            if FIXED and qty < 1:
                return self._send(400, {"error": "quantity must be >= 1"})  # the fix
            total = round(qty * float(prod["price"]), 2)  # VULN: negative qty allowed
            # total is an unquoted JSON number so the deterministic business-logic oracle can read
            # the server-computed economic result (a negative/zero total proves the tampering).
            return self._send(
                200, {"item": item, "qty": qty, "unit_price": float(prod["price"]), "total": total}
            )

        # Sensitive file exposure: serve dotfiles/backups/config in VULN mode only.
        if path in SENSITIVE_FILES:
            if FIXED:
                return self._send(404, {"error": "not found"})
            body = SENSITIVE_FILES[path].encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            return self.wfile.write(body)

        # Server-side template injection: name rendered into a template.
        if path == "/api/greet":
            name = q.get("name", "world")
            if not FIXED:
                m = _SSTI_EXPR.search(name)
                if m:  # VULN: evaluate the template expression
                    name = _SSTI_EXPR.sub(str(int(m.group(1)) * int(m.group(2))), name)
                return self._send_html(200, f"<p>Hello {name}</p>")
            return self._send_html(200, f"<p>Hello {html.escape(name)}</p>")  # fixed: escaped, not evaluated

        # Cookie hygiene: a GET that sets a session cookie (flags missing in VULN mode).
        if path == "/api/session":
            tok = secrets.token_hex(8)
            cookie = (
                f"session={tok}; Path=/; HttpOnly; Secure; SameSite=Strict"
                if FIXED
                else f"session={tok}; Path=/"
            )
            return self._send(200, {"session": "started"}, {"Set-Cookie": cookie})

        # JWT: /api/me trusts the token's identity. VULN accepts alg=none / unsigned tokens.
        if path == "/api/me":
            auth = self.headers.get("Authorization", "")
            if not auth.startswith("Bearer "):
                return self._send(401, {"error": "authentication required"})
            parts = auth[7:].split(".")
            if len(parts) != 3:
                return self._send(401, {"error": "malformed token"})
            try:
                header = json.loads(_b64url_decode(parts[0]))
                payload = json.loads(_b64url_decode(parts[1]))
            except Exception:  # noqa: BLE001
                return self._send(401, {"error": "bad token"})
            if FIXED:
                # require a real signed token; alg=none and unsigned are rejected
                if str(header.get("alg", "")).lower() == "none" or not parts[2]:
                    return self._send(401, {"error": "invalid token signature"})
                return self._send(200, {"user": payload.get("sub")})
            # VULN: trust the token's claims without verifying the signature
            return self._send(
                200,
                {
                    "user": payload.get("sub"),
                    "data": f"RAMPART-JWT-NOSIG authenticated as {payload.get('sub')}",
                },
            )

        # JWT v2: /api/v2/me DOES verify the HS256 signature — but VULN signs with a weak, guessable
        # secret ("secret") and never checks expiry. FIXED uses a long random key and enforces exp.
        if path == "/api/v2/me":
            auth = self.headers.get("Authorization", "")
            if not auth.startswith("Bearer "):
                return self._send(401, {"error": "authentication required"})
            parts = auth[7:].split(".")
            if len(parts) != 3:
                return self._send(401, {"error": "malformed token"})
            try:
                header = json.loads(_b64url_decode(parts[0]))
                payload = json.loads(_b64url_decode(parts[1]))
            except Exception:  # noqa: BLE001
                return self._send(401, {"error": "bad token"})
            if str(header.get("alg", "")).lower() != "hs256":
                return self._send(401, {"error": "unsupported alg"})
            secret = _JWT_V2_STRONG if FIXED else _JWT_V2_WEAK  # selected at request time
            signing_input = f"{parts[0]}.{parts[1]}".encode("ascii")
            expected = (
                base64.urlsafe_b64encode(hmac.new(secret.encode(), signing_input, hashlib.sha256).digest())
                .decode()
                .rstrip("=")
            )
            if not hmac.compare_digest(expected, parts[2]):
                return self._send(401, {"error": "invalid token signature"})
            if FIXED and int(payload.get("exp", 0)) < int(time.time()):
                return self._send(401, {"error": "token expired"})  # the fix: enforce expiry
            return self._send(
                200,
                {
                    "user": payload.get("sub"),
                    "data": f"RAMPART-JWT-HS256 authenticated as {payload.get('sub')}",
                },
            )

        # BFLA: a privileged "all orders" report that should be admin-only.
        if path == "/api/reports/orders":
            uid = self._auth_user()
            if uid is None:
                return self._send(401, {"error": "authentication required"})
            if FIXED:
                # function-level authorization: only admins (none seeded) may call this
                return self._send(403, {"error": "forbidden: admin role required"})
            return self._send(
                200, {"report": "RAMPART-BFLA all-customer-orders", "orders": list(ORDERS.values())}
            )  # VULN: no role check

        # Excessive data exposure: profile returns sensitive fields it shouldn't.
        if path == "/api/profile":
            uid = self._auth_user()
            if uid is None:
                return self._send(401, {"error": "authentication required"})
            email = next((u["email"] for u in USERS.values() if u["id"] == uid), "user@demo.local")
            if FIXED:
                return self._send(200, {"email": email, "role": "customer"})
            return self._send(
                200,
                {
                    "email": email,
                    "role": "customer",
                    "ssn": "123-45-6789",
                    "password_hash": "$2b$12$demohashdemohash",
                    "api_token": "sk-demo-01HZ0PRIVATE",
                    "credit_card": "4111111111111111",
                },
            )

        if path.startswith("/api/orders/"):
            oid = path.rsplit("/", 1)[-1]
            uid = self._auth_user()
            if uid is None:
                return self._send(401, {"error": "authentication required"})  # auth IS enforced
            order = ORDERS.get(oid)
            if order is None:
                return self._send(404, {"error": "order not found"})  # absent -> 404
            if FIXED and not self._authorize(order, uid):
                return self._send(403, {"error": "forbidden"})  # the fix (patched build)
            return self._send(200, order)  # VULN: no ownership check
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
