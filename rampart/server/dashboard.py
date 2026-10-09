"""The dashboard HTTP handler (stdlib only)."""

from __future__ import annotations

import html
import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

_SEV_COLOR = {
    "critical": "#b4232c",
    "high": "#d1495b",
    "medium": "#e08a1e",
    "low": "#3a7ca5",
    "info": "#5b6570",
}
_run_lock = threading.Lock()


def _read_json(path, default):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:  # noqa: BLE001
        return default


def _esc(x):
    return html.escape(str(x if x is not None else ""))


def _dashboard_html(work_dir: str) -> str:
    findings = _read_json(os.path.join(work_dir, "findings.json"), [])
    scan = _read_json(os.path.join(work_dir, "scan.json"), {})
    corr = scan.get("correlation") or {}
    confirmed = [
        f for f in findings if (f.get("verification") or {}).get("validated") and f.get("state") != "Dropped"
    ]
    risk = corr.get("risk_score", 0)
    band = corr.get("risk_band", "Informational")
    chains = corr.get("chains", [])
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
        (len(chains), "Attack chains", "#5aa9d6"),
        (len(findings), "Total findings", "#5b6570"),
    ]
    kpi_html = "".join(
        f'<div class="kpi"><div class="n" style="color:{c}">{_esc(v)}</div>'
        f'<div class="l">{_esc(lbl)}</div></div>'
        for v, lbl, c in kpis
    )

    rows = []
    for f in sorted(confirmed, key=lambda f: f.get("cvss", {}).get("base_score", 0), reverse=True):
        color = _SEV_COLOR.get(f.get("severity"), "#5b6570")
        rows.append(
            f'<tr><td><span class="sev" style="background:{color}">{_esc(f.get("severity"))}</span></td>'
            f'<td>{_esc(f.get("title"))}</td><td class="mono">{_esc(", ".join(f.get("cwe", [])))}</td>'
            f'<td class="mono">{_esc((f.get("endpoint") or {}).get("url", ""))}</td></tr>'
        )
    findings_table = (
        "".join(rows)
        if rows
        else '<tr><td colspan="4" class="sub">No confirmed findings yet — run a scan.</td></tr>'
    )

    chain_html = "".join(
        f'<div class="chain" style="border-left-color:{_SEV_COLOR.get(c["severity"], "#5b6570")}">'
        f"<b>[{_esc(c['severity'].upper())}] {_esc(c['title'])}</b>"
        f'<div class="sub">{_esc(c.get("rationale", ""))}</div></div>'
        for c in chains
    )

    has_report = os.path.exists(os.path.join(work_dir, "reports", "report.html"))
    report_link = (
        '<a class="btn" href="/report" target="_blank">Open full HTML report ↗</a>'
        if has_report
        else '<span class="sub">No report generated yet.</span>'
    )

    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>Rampart dashboard</title>
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
  <form id="runform" onsubmit="return runScan(event)">
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
<div class="sub">Rampart augments — not replaces — expert human pentesters. Only oracle-validated
findings are shown as confirmed. Every action passes the scope → policy → audit pipeline.</div>
</div>
<script>
async function runScan(e){{
  e.preventDefault();
  var m=document.getElementById('msg'); m.textContent='running… (this can take a few seconds)';
  var fd=new FormData(e.target);
  var body=new URLSearchParams(); fd.forEach((v,k)=>body.append(k,v));
  try{{
    var r=await fetch('/api/run',{{method:'POST',body:body}});
    var j=await r.json();
    if(j.error){{m.textContent='✗ '+j.error;}} else {{m.textContent='✓ done — reloading…'; setTimeout(()=>location.reload(),800);}}
  }}catch(err){{m.textContent='✗ '+err;}}
  return false;
}}
</script></body></html>"""


def _make_handler(work_dir: str):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *a):
            pass

        def _send(self, status, body, ctype="text/html; charset=utf-8"):
            data = body.encode() if isinstance(body, str) else body
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Content-Security-Policy", "default-src 'self' 'unsafe-inline'")
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            path = urlparse(self.path).path
            if path == "/":
                return self._send(200, _dashboard_html(work_dir))
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
                        return self._send(200, fh.read())
                return self._send(404, "<h1>No report yet</h1>")
            return self._send(404, "<h1>404</h1>")

        def do_POST(self):
            if urlparse(self.path).path != "/api/run":
                return self._send(404, json.dumps({"error": "not found"}), "application/json")
            length = int(self.headers.get("Content-Length", 0))
            raw = self.rfile.read(length).decode("utf-8", "replace")
            form = {k: v[0] for k, v in parse_qs(raw).items()}
            if not form.get("scope_file") or not form.get("target"):
                return self._send(
                    400, json.dumps({"error": "scope_file and target are required"}), "application/json"
                )
            if not _run_lock.acquire(blocking=False):
                return self._send(409, json.dumps({"error": "a scan is already running"}), "application/json")
            try:
                from ..engagement import Engagement, EngagementConfig

                cfg = EngagementConfig(
                    scope_file=form["scope_file"],
                    target=form["target"],
                    work_dir=work_dir,
                    crawl=(form.get("crawl") in ("on", "true", "1")),
                    application=form.get("application", "target"),
                )
                eng = Engagement(cfg)
                result = eng.run_scan()
                eng.report(["html", "md", "json", "sarif"])
                corr = result.correlation
                out = {
                    "ok": True,
                    "confirmed": len([f for f in result.findings if f.verification.validated]),
                    "risk_score": corr.risk_score,
                    "risk_band": corr.risk_band,
                    "chains": len(corr.chains),
                }
                return self._send(200, json.dumps(out), "application/json")
            except Exception as exc:  # noqa: BLE001 - surface scope/other errors to the UI
                return self._send(200, json.dumps({"error": str(exc)}), "application/json")
            finally:
                _run_lock.release()

    return Handler


def build_server(host: str = "127.0.0.1", port: int = 8787, work_dir: str = ".rampart"):
    os.makedirs(work_dir, exist_ok=True)
    return ThreadingHTTPServer((host, port), _make_handler(work_dir))


def serve(host: str = "127.0.0.1", port: int = 8787, work_dir: str = ".rampart"):
    build_server(host, port, work_dir).serve_forever()
