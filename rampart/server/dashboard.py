"""The dashboard HTTP handler (stdlib only).

The dashboard can launch scans, so it is hardened like any local admin UI:

* **Host allowlist** — every request must carry a ``Host`` naming the loopback interface (or the
  explicitly bound host) on the bound port, defeating DNS-rebinding reads of findings.
* **Launch token** — ``POST /api/run`` needs a per-process random token (embedded in the served
  page, sent back as ``X-Rampart-Token``), ``Content-Type: application/json`` (not a "simple"
  cross-site form type) and, when the browser sends one, a same-origin ``Origin``/``Referer``.
* **Headers** — nosniff, no-referrer, ``X-Frame-Options: DENY`` and a restrictive CSP.
* **Exclusive bind** — on Windows the port is bound exclusively, so a second ``rampart serve``
  fails loudly instead of silently sharing (or hijacking) the port.
"""

from __future__ import annotations

import base64
import errno
import hashlib
import hmac
import html
import json
import os
import secrets
import socket
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

from ..reporting.status import is_confirmed, is_fixed, norm_severity, sev_rank

_SEV_COLOR = {
    "critical": "#b4232c",
    "high": "#d1495b",
    "medium": "#e08a1e",
    "low": "#3a7ca5",
    "info": "#5b6570",
}
_run_lock = threading.Lock()
_MAX_BODY = 64 * 1024
_LOOPBACK = ("127.0.0.1", "localhost", "[::1]", "::1")
_TOKEN_HEADER = "X-Rampart-Token"
_GENERIC_SCOPE_ERROR = (
    "the scan was not started: the scope file could not be loaded, is not a valid "
    "rampart.scope.yaml, or does not authorize this target"
)


def _read_json(path, default):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:  # noqa: BLE001
        return default


def _esc(x):
    return html.escape(str(x if x is not None else ""))


def _report_script_hash() -> str:
    """CSP hash of the HTML report's only (static) inline script, so /report needs no unsafe-inline."""
    from ..reporting.html_report import _JS

    digest = hashlib.sha256(_JS.encode("utf-8")).digest()
    return "'sha256-" + base64.b64encode(digest).decode() + "'"


def _csp(script_src: str) -> str:
    return (
        "default-src 'none'; "
        f"script-src {script_src}; "
        "style-src 'unsafe-inline'; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "form-action 'self'; "
        "base-uri 'none'; "
        "frame-ancestors 'none'"
    )


def _dashboard_html(work_dir: str, token: str = "", nonce: str = "") -> str:
    findings = _read_json(os.path.join(work_dir, "findings.json"), [])
    if not isinstance(findings, list):
        findings = []
    findings = [f for f in findings if isinstance(f, dict)]
    scan = _read_json(os.path.join(work_dir, "scan.json"), {})
    if not isinstance(scan, dict):
        scan = {}
    corr = scan.get("correlation") or {}
    confirmed = [f for f in findings if is_confirmed(f)]
    fixed = [f for f in findings if is_fixed(f)]
    risk = corr.get("risk_score", 0)
    band = corr.get("risk_band", "Informational")
    chains = corr.get("chains", []) or []
    band_color = {
        "Critical": "#b4232c",
        "High": "#d1495b",
        "Medium": "#e08a1e",
        "Low": "#3a7ca5",
        "Informational": "#5b6570",
    }.get(band, "#5b6570")

    kpis = [
        (f"{risk}/100", f"Risk · {band}", band_color),
        (len(confirmed), "Confirmed", "#1f9d55"),
        (len(fixed), "Fixed (retest)", "#3a7ca5"),
        (len(chains), "Attack chains", "#5aa9d6"),
        (len(findings), "Total findings", "#5b6570"),
    ]
    kpi_html = "".join(
        f'<div class="kpi"><div class="n" style="color:{c}">{_esc(v)}</div>'
        f'<div class="l">{_esc(lbl)}</div></div>'
        for v, lbl, c in kpis
    )

    def _score(f):
        try:
            return float((f.get("cvss") or {}).get("base_score") or 0)
        except (TypeError, ValueError):
            return 0.0

    rows = []
    for f in sorted(confirmed, key=lambda f: (-_score(f), sev_rank(f.get("severity")))):
        sev = norm_severity(f.get("severity"))
        cwe = f.get("cwe") or []
        rows.append(
            f'<tr><td><span class="sev" style="background:{_SEV_COLOR[sev]}">{_esc(sev)}</span></td>'
            f'<td>{_esc(f.get("title"))}</td><td class="mono">'
            f"{_esc(', '.join(str(c) for c in cwe) if isinstance(cwe, list) else cwe)}</td>"
            f'<td class="mono">{_esc((f.get("endpoint") or {}).get("url", ""))}</td></tr>'
        )
    findings_table = (
        "".join(rows)
        if rows
        else '<tr><td colspan="4" class="sub">No confirmed findings yet — run a scan.</td></tr>'
    )
    fixed_html = "".join(
        f"<li>{_esc(f.get('title'))} <span class='sub'>(fixed on retest "
        f"{_esc(((f.get('verification') or {}).get('last_retest') or {}).get('at', ''))})</span></li>"
        for f in fixed
    )

    chain_html = "".join(
        f'<div class="chain" style="border-left-color:{_SEV_COLOR[norm_severity(c.get("severity"))]}">'
        f"<b>[{_esc(norm_severity(c.get('severity')).upper())}] {_esc(c.get('title'))}</b>"
        f'<div class="sub">{_esc(c.get("rationale", ""))}</div></div>'
        for c in chains
        if isinstance(c, dict)
    )

    has_report = os.path.exists(os.path.join(work_dir, "reports", "report.html"))
    report_link = (
        '<a class="btn" href="/report" target="_blank" rel="noopener">Open full HTML report ↗</a>'
        if has_report
        else '<span class="sub">No report generated yet.</span>'
    )

    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>Rampart dashboard</title>
<meta name="rampart-token" content="{_esc(token)}">
<style>
:root{{--bg:#f6f7f9;--card:#fff;--ink:#151922;--muted:#5b6570;--line:#e5e8ec;--accent:#3a7ca5;}}
@media(prefers-color-scheme:dark){{:root{{--bg:#0e1116;--card:#161b22;--ink:#e6edf3;--muted:#9aa4b2;--line:#232a33;--accent:#5aa9d6;}}}}
*{{box-sizing:border-box}} body{{margin:0;background:var(--bg);color:var(--ink);
font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;}}
.wrap{{max-width:1000px;margin:0 auto;padding:26px 16px 80px;}}
h1{{font-size:23px;margin:0 0 4px;}} .brand{{color:var(--accent);font-weight:700;}}
.sub{{color:var(--muted);font-size:13px;}}
.kpis{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin:18px 0;}}
.kpi{{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:14px 16px;}}
.kpi .n{{font-size:26px;font-weight:700;}} .kpi .l{{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.04em;}}
.panel{{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px 18px;margin:16px 0;}}
.panel h2{{font-size:14px;margin:0 0 12px;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);}}
table{{width:100%;border-collapse:collapse;font-size:14px;}} th,td{{text-align:left;padding:7px 8px;border-bottom:1px solid var(--line);vertical-align:top;}}
th{{color:var(--muted);font-size:12px;text-transform:uppercase;}}
.sev{{color:#fff;border-radius:999px;padding:2px 8px;font-size:11px;font-weight:700;text-transform:uppercase;}}
.mono{{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px;word-break:break-all;}}
.chain{{border-left:4px solid;padding:6px 12px;margin:8px 0;background:var(--card);}}
.btn{{display:inline-block;background:var(--accent);color:#fff;text-decoration:none;border:0;border-radius:8px;
padding:8px 14px;font-size:14px;cursor:pointer;}} input,label{{font-size:14px;}}
input[type=text]{{width:100%;padding:8px;border:1px solid var(--line);border-radius:8px;background:var(--bg);color:var(--ink);margin:4px 0 10px;}}
#msg{{margin-top:10px;}}
</style></head><body><div class="wrap">
<h1><span class="brand">Rampart</span> dashboard</h1>
<div class="sub">work-dir: <span class="mono">{_esc(os.path.abspath(work_dir))}</span></div>
<div class="kpis">{kpi_html}</div>
<div class="panel"><h2>Run a scan</h2>
  <form id="runform">
    <label>rampart.scope.yaml scope file</label><input type="text" name="scope_file" placeholder="examples/demo_target/rampart.scope.yaml" required>
    <label>Target base URL (must be in scope)</label><input type="text" name="target" placeholder="http://127.0.0.1:8080" required>
    <label><input type="checkbox" name="crawl" checked> crawl to discover endpoints</label><br>
    <button class="btn" type="submit">Run assessment</button>
    <span id="msg" class="sub"></span>
  </form>
</div>
<div class="panel"><h2>Attack chains</h2>{chain_html or '<div class="sub">None.</div>'}</div>
<div class="panel"><h2>Confirmed findings</h2>
  <table><thead><tr><th>Sev</th><th>Finding</th><th>CWE</th><th>Endpoint</th></tr></thead>
  <tbody>{findings_table}</tbody></table>
  <div style="margin-top:12px">{report_link}</div>
</div>
{f'<div class="panel"><h2>Fixed (verified by retest)</h2><ul>{fixed_html}</ul></div>' if fixed_html else ""}
<div class="sub">Rampart augments — not replaces — expert human pentesters. Only oracle-validated
findings are shown as confirmed. Every action passes the scope → policy → audit pipeline.</div>
</div>
<script nonce="{_esc(nonce)}">
(function(){{
  var form=document.getElementById('runform');
  var token=document.querySelector('meta[name="rampart-token"]').getAttribute('content');
  form.addEventListener('submit', async function(e){{
    e.preventDefault();
    var m=document.getElementById('msg'); m.textContent='running… (this can take a few seconds)';
    var body={{
      scope_file: form.elements['scope_file'].value,
      target: form.elements['target'].value,
      crawl: form.elements['crawl'].checked
    }};
    try{{
      var r=await fetch('/api/run',{{method:'POST',credentials:'same-origin',
        headers:{{'Content-Type':'application/json','{_TOKEN_HEADER}':token}},body:JSON.stringify(body)}});
      var j=await r.json();
      if(j.error){{m.textContent='✗ '+j.error;}} else {{m.textContent='✓ done — reloading…'; setTimeout(function(){{location.reload();}},800);}}
    }}catch(err){{m.textContent='✗ '+err;}}
  }});
}})();
</script></body></html>"""


def _split_host(value: str) -> tuple[str, int | None] | None:
    """Parse a Host header (``name``, ``name:port``, ``[v6]:port``) -> (lowercase host, port)."""
    value = (value or "").strip().lower()
    if not value or any(c in value for c in "/@ \t\\"):
        return None
    if value.startswith("["):
        end = value.find("]")
        if end < 0:
            return None
        host, rest = value[: end + 1], value[end + 1 :]
        if rest and not rest.startswith(":"):
            return None
        port_s = rest[1:] if rest else ""
    else:
        if value.count(":") > 1:
            return None
        host, _, port_s = value.partition(":")
    if port_s:
        if not port_s.isdigit():
            return None
        return host, int(port_s)
    return host, None


def _make_handler(work_dir: str, token: str, allowed_hosts: tuple = ()):
    report_hash = _report_script_hash()

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def version_string(self):
            return "Rampart"

        def log_message(self, *a):
            pass

        # ------------------------------------------------------------ helpers
        def _port(self) -> int:
            return int(self.server.server_address[1])

        def _host_names(self) -> set:
            names = {h.lower() for h in _LOOPBACK}
            bound = str(self.server.server_address[0]).lower()
            if bound not in ("", "0.0.0.0", "::"):
                names.add(f"[{bound}]" if ":" in bound and not bound.startswith("[") else bound)
            names.update(h.lower() for h in allowed_hosts)
            return names

        def _host_ok(self, value) -> bool:
            parsed = _split_host(value or "")
            if not parsed:
                return False
            host, port = parsed
            if host == "::1":
                host = "[::1]"
            if host not in self._host_names():
                return False
            return port == self._port() or (port is None and self._port() == 80)

        def _origin_ok(self, value: str) -> bool:
            u = urlparse(value)
            if u.scheme != "http" or not u.netloc:
                return False
            return self._host_ok(u.netloc)

        def _send(self, status, body, ctype="text/html; charset=utf-8", csp=None):
            data = body.encode() if isinstance(body, str) else body
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Security-Policy", csp or _csp("'none'"))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(data)

        def _json(self, status, obj):
            return self._send(status, json.dumps(obj), "application/json")

        def _guard_host(self) -> bool:
            if self._host_ok(self.headers.get("Host")):
                return True
            self.close_connection = True
            self._send(403, json.dumps({"error": "forbidden host"}), "application/json")
            return False

        # ------------------------------------------------------------ routes
        def do_GET(self):
            if not self._guard_host():
                return
            path = urlparse(self.path).path
            if path == "/":
                nonce = secrets.token_urlsafe(16)
                return self._send(200, _dashboard_html(work_dir, token, nonce), csp=_csp(f"'nonce-{nonce}'"))
            if path == "/api/findings":
                return self._send(
                    200,
                    json.dumps(_read_json(os.path.join(work_dir, "findings.json"), [])),
                    "application/json",
                )
            if path == "/api/scan":
                return self._send(
                    200, json.dumps(_read_json(os.path.join(work_dir, "scan.json"), {})), "application/json"
                )
            if path == "/report":
                rp = os.path.join(work_dir, "reports", "report.html")
                if os.path.exists(rp):
                    with open(rp, encoding="utf-8") as fh:
                        return self._send(200, fh.read(), csp=_csp(report_hash))
                return self._send(404, "<h1>No report yet</h1>")
            return self._send(404, "<h1>404</h1>")

        def do_HEAD(self):
            return self.do_GET()

        def do_POST(self):
            if not self._guard_host():
                return
            raw_len = self.headers.get("Content-Length", "0") or "0"
            try:
                length = int(raw_len)
                if length < 0:
                    raise ValueError
            except ValueError:
                self.close_connection = True
                return self._json(400, {"error": "invalid Content-Length"})
            if length > _MAX_BODY:
                self.close_connection = True
                return self._json(413, {"error": "request body too large"})
            raw = self.rfile.read(length) if length else b""

            if urlparse(self.path).path != "/api/run":
                return self._json(404, {"error": "not found"})

            # ---- CSRF defences: same-origin, JSON content type, per-launch token ----
            origin = self.headers.get("Origin")
            if origin is not None and not self._origin_ok(origin):
                return self._json(403, {"error": "cross-origin request refused"})
            referer = self.headers.get("Referer")
            if origin is None and referer and not self._origin_ok(referer):
                return self._json(403, {"error": "cross-origin request refused"})
            ctype = (self.headers.get("Content-Type") or "").split(";", 1)[0].strip().lower()
            if ctype != "application/json":
                return self._json(415, {"error": "Content-Type must be application/json"})
            sent = self.headers.get(_TOKEN_HEADER) or ""
            if not hmac.compare_digest(sent.encode(), token.encode()):
                return self._json(403, {"error": f"missing or invalid {_TOKEN_HEADER}"})

            try:
                form = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, ValueError):
                return self._json(400, {"error": "body must be a JSON object"})
            if not isinstance(form, dict):
                return self._json(400, {"error": "body must be a JSON object"})
            scope_file, target = form.get("scope_file"), form.get("target")
            if not isinstance(scope_file, str) or not isinstance(target, str) or not scope_file or not target:
                return self._json(400, {"error": "scope_file and target are required"})
            crawl = form.get("crawl", False)
            crawl = crawl is True or (isinstance(crawl, str) and crawl.lower() in ("on", "true", "1"))
            application = form.get("application") if isinstance(form.get("application"), str) else "target"

            if not _run_lock.acquire(blocking=False):
                return self._json(409, {"error": "a scan is already running"})
            try:
                from ..engagement import Engagement, EngagementConfig
                from ..schemas.scope import ScopeError

                try:
                    eng = Engagement(
                        EngagementConfig(
                            scope_file=scope_file,
                            target=target,
                            work_dir=work_dir,
                            crawl=crawl,
                            application=application or "target",
                        )
                    )
                except ScopeError as exc:
                    msg = str(exc)
                    # Only the target-not-in-scope verdict is safe to echo; anything about the
                    # file itself (missing, unreadable, malformed) would reveal file existence.
                    if msg.startswith("target host "):
                        return self._json(400, {"error": msg})
                    return self._json(400, {"error": _GENERIC_SCOPE_ERROR})
                except Exception:  # noqa: BLE001 - never echo paths/parse errors to the client
                    return self._json(400, {"error": _GENERIC_SCOPE_ERROR})
                try:
                    result = eng.run_scan()
                    eng.report(["html", "md", "json", "sarif"])
                except Exception as exc:  # noqa: BLE001
                    print(f"rampart dashboard: scan failed: {exc!r}", file=sys.stderr)
                    return self._json(500, {"error": "the scan failed; see the server console for details"})
                corr = result.correlation
                out = {
                    "ok": True,
                    "confirmed": len([f for f in result.findings if is_confirmed(f)]),
                    "risk_score": corr.risk_score,
                    "risk_band": corr.risk_band,
                    "chains": len(corr.chains),
                }
                return self._json(200, out)
            finally:
                _run_lock.release()

    return Handler


class DashboardServer(ThreadingHTTPServer):
    daemon_threads = True
    # On Windows SO_REUSEADDR lets a second process bind the *same* port (and steal requests);
    # use an exclusive bind there instead. POSIX keeps the usual TIME_WAIT-friendly reuse.
    allow_reuse_address = os.name != "nt"

    def server_bind(self):
        if os.name == "nt" and hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        super().server_bind()


def build_server(
    host: str = "127.0.0.1",
    port: int = 8787,
    work_dir: str = ".rampart",
    allowed_hosts: tuple = (),
):
    """Bind the dashboard. ``allowed_hosts`` adds extra acceptable ``Host`` names (e.g. a LAN name
    when bound to 0.0.0.0); loopback names and the bound host are always accepted."""
    os.makedirs(work_dir, exist_ok=True)
    token = secrets.token_urlsafe(32)
    cls = DashboardServer
    if ":" in host:

        class _V6(DashboardServer):
            address_family = socket.AF_INET6

        cls = _V6
    try:
        httpd = cls((host, port), _make_handler(work_dir, token, tuple(allowed_hosts)))
    except OSError as exc:
        # 10048 = WSAEADDRINUSE; 10013 = WSAEACCES (port held exclusively, or reserved by the OS)
        if exc.errno in (errno.EADDRINUSE, errno.EACCES) or getattr(exc, "winerror", None) in (10048, 10013):
            raise OSError(
                exc.errno,
                f"cannot bind the Rampart dashboard to {host}:{port}: the port is already in use "
                "(is another `rampart serve` running?) or reserved — pick another --port",
            ) from exc
        raise
    httpd.rampart_token = token
    return httpd


def serve(host: str = "127.0.0.1", port: int = 8787, work_dir: str = ".rampart"):
    build_server(host, port, work_dir).serve_forever()
