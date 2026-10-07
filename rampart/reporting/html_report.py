"""Self-contained HTML dashboard for an assessment (no external assets; works offline)."""
from __future__ import annotations

import html
from datetime import datetime, timezone

from ..version import __version__
from ..schemas.finding import State
from .report import owasp_tags

_CSS = """
:root{
  --bg:#f6f7f9; --card:#ffffff; --ink:#151922; --muted:#5b6570; --line:#e5e8ec;
  --accent:#3a7ca5; --good:#1f9d55; --code:#f2f4f7; --shadow:0 1px 3px rgba(20,25,34,.08);
}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){
  --bg:#0e1116; --card:#161b22; --ink:#e6edf3; --muted:#9aa4b2; --line:#232a33;
  --accent:#5aa9d6; --good:#3fb950; --code:#0b0e13; --shadow:0 1px 3px rgba(0,0,0,.4);
}}
:root[data-theme="dark"]{
  --bg:#0e1116; --card:#161b22; --ink:#e6edf3; --muted:#9aa4b2; --line:#232a33;
  --accent:#5aa9d6; --good:#3fb950; --code:#0b0e13; --shadow:0 1px 3px rgba(0,0,0,.4);
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);
  font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;}
.wrap{max-width:960px;margin:0 auto;padding:28px 16px 80px;}
header.top{display:flex;justify-content:space-between;align-items:flex-start;gap:16px;flex-wrap:wrap;margin-bottom:8px;}
h1{font-size:24px;margin:0 0 2px;letter-spacing:-.01em;}
.sub{color:var(--muted);font-size:13px;}
.brandmark{font-weight:700;color:var(--accent);}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin:20px 0;}
.kpi{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:14px 16px;box-shadow:var(--shadow);}
.kpi .n{font-size:26px;font-weight:700;letter-spacing:-.02em;}
.kpi .l{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.04em;}
.panel{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px 18px;margin:16px 0;box-shadow:var(--shadow);}
.panel h2{font-size:15px;margin:0 0 10px;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:8px 24px;}
@media(max-width:640px){.grid2{grid-template-columns:1fr;}}
.row{display:flex;justify-content:space-between;gap:12px;padding:4px 0;border-bottom:1px dashed var(--line);font-size:14px;}
.row b{font-weight:600;} .ok{color:var(--good);font-weight:600;}
.finding{background:var(--card);border:1px solid var(--line);border-left-width:5px;border-radius:12px;
  margin:14px 0;box-shadow:var(--shadow);overflow:hidden;}
.finding summary{cursor:pointer;list-style:none;padding:14px 18px;display:flex;gap:12px;align-items:center;}
.finding summary::-webkit-details-marker{display:none;}
.sev{font-size:11px;font-weight:700;color:#fff;border-radius:999px;padding:3px 9px;text-transform:uppercase;letter-spacing:.03em;}
.ftitle{font-weight:600;flex:1;}
.badge{font-size:11px;border-radius:999px;padding:3px 9px;border:1px solid var(--line);color:var(--muted);white-space:nowrap;}
.badge.cf{color:var(--good);border-color:var(--good);}
.fbody{padding:0 18px 18px;border-top:1px solid var(--line);}
.fbody h3{font-size:12px;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);margin:16px 0 6px;}
.mono,code,pre{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;}
pre{background:var(--code);border:1px solid var(--line);border-radius:8px;padding:12px;overflow:auto;font-size:12.5px;}
.diff .add{color:var(--good);} .diff .del{color:#d1495b;}
ul.checks{margin:6px 0;padding-left:18px;} ul.checks li{margin:2px 0;font-size:13.5px;}
.pill{display:inline-block;background:var(--code);border:1px solid var(--line);border-radius:6px;
  padding:1px 7px;margin:2px 4px 2px 0;font-size:12px;}
.foot{color:var(--muted);font-size:12.5px;margin-top:26px;border-top:1px solid var(--line);padding-top:14px;}
.themebtn{background:var(--card);border:1px solid var(--line);color:var(--muted);border-radius:8px;
  padding:6px 10px;cursor:pointer;font-size:12px;}
.dropped{opacity:.7;}
"""

_JS = """
(function(){
  var b=document.getElementById('themebtn');
  b&&b.addEventListener('click',function(){
    var r=document.documentElement;
    var cur=r.getAttribute('data-theme');
    var next=cur==='dark'?'light':(cur==='light'?'dark':((window.matchMedia&&window.matchMedia('(prefers-color-scheme:dark)').matches)?'light':'dark'));
    r.setAttribute('data-theme',next);
  });
})();
"""


def _esc(x) -> str:
    return html.escape(str(x if x is not None else ""))


def _diff_html(diff: str) -> str:
    out = []
    for line in diff.splitlines():
        cls = "add" if line.startswith("+") else ("del" if line.startswith("-") else "")
        out.append(f'<span class="{cls}">{_esc(line)}</span>')
    return "\n".join(out)


def render_html(rb) -> str:
    m = rb.metrics()
    sc = rb.scope
    sev_color = {"critical": "#b4232c", "high": "#d1495b", "medium": "#e08a1e",
                 "low": "#3a7ca5", "info": "#5b6570"}
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    kpis = [
        (f"{m['risk_score']}/100", f"Risk · {m['risk_band']}"),
        (m["confirmed"], "Confirmed findings"),
        (m["attack_chains"], "Attack chains"),
        (m["dropped_candidates"], "Dropped (FP gate)"),
        (f"{m['finding_validation_rate']*100:.0f}%", "Validation rate"),
        (f"{m['endpoints_tested']}/{m['endpoints_discovered']}", "Endpoints tested"),
        (m["audit_events"], "Audit events"),
        (f"${m['usd_spent']}", "LLM cost"),
    ]
    kpi_html = "".join(
        f'<div class="kpi"><div class="n">{_esc(v)}</div><div class="l">{_esc(l)}</div></div>'
        for v, l in kpis)

    hosts = ", ".join(h.host for h in sc.in_scope) or "—"
    posture = [
        ("In-scope hosts", hosts),
        ("Resolved-IP allowlist", ", ".join(sc.resolved_ip_allowlist) or "—"),
        ("Action tier ceiling", f"Tier {sc.action_policy.default_tier_ceiling} auto-allow; "
                                f"Tier 2 {'requires approval' if sc.action_policy.tier2_requires_approval else 'denied'}; "
                                f"Tier 3 denied"),
        ("Authorization", f"{sc.authorization.authorized_by} · ticket {sc.authorization.ticket}"),
        ("Scope expires", sc.authorization.expires),
        ("Audit chain", "hash-chained, append-only"),
    ]
    posture_html = "".join(
        f'<div class="row"><span>{_esc(k)}</span><b>{_esc(v)}</b></div>' for k, v in posture)

    scan = rb.scan or {}
    classes = m.get("classes_tested") or sorted({f.vuln_class for f in rb.findings})
    runs = scan.get("scanner_runs") or []
    scanner_txt = ", ".join(
        (f"{r['scanner']} ✓" if r.get("available") else f"{r['scanner']} (not installed)") for r in runs) or "none run"
    plan = scan.get("plan") or {}
    coverage = [
        ("Classes tested", ", ".join(classes) or "—"),
        ("Planner priority", ", ".join(plan.get("order", [])) or "—"),
        ("External OSS scanners", scanner_txt),
        ("Confirmed vs external leads", f"{m['confirmed']} oracle-confirmed · {m['external_leads']} unvalidated leads"),
        ("Intelligence backend", scan.get("intel_provider", "deterministic")),
    ]
    coverage_html = "".join(
        f'<div class="row"><span>{_esc(k)}</span><b>{_esc(v)}</b></div>' for k, v in coverage)

    corr = scan.get("correlation") or {}
    chains = corr.get("chains") or []
    chains_html = ""
    if chains:
        parts = []
        for c in chains:
            color = sev_color.get(c["severity"], "#5b6570")
            steps = "".join(f"<li>{_esc(s)}</li>" for s in c["steps"])
            built = (f'<div class="sub">Built from: {_esc(", ".join(c.get("contributing", [])))}</div>'
                     if c.get("contributing") else "")
            parts.append(
                f'<div class="finding" style="border-left-color:{color}"><div class="fbody">'
                f'<h3 style="margin-top:12px"><span class="sev" style="background:{color}">'
                f'{_esc(c["severity"])}</span> &nbsp;{_esc(c["title"])}</h3>'
                f'<div class="sub">{_esc(c["rationale"])}</div><ol class="checks">{steps}</ol>{built}'
                f'</div></div>')
        chains_html = ('<div class="panel"><h2>Attack chains (kill-chain)</h2>'
                       + "".join(parts) + "</div>")

    proofs = [p for p in (scan.get("exploitation") or []) if p.get("demonstrated")]
    exploit_html = ""
    if proofs:
        parts = []
        for p in proofs:
            steps = "".join(f"<li>{_esc(s)}</li>" for s in p.get("steps", []))
            ev = (f'<div class="sub">Evidence: {_esc(", ".join(str(s) for s in p.get("samples", [])[:8]))}</div>'
                  if p.get("samples") else "")
            parts.append(
                f'<div class="chain" style="border-left-color:#b4232c"><b>{_esc(p["title"])}</b>'
                f'<div class="sub">Technique: {_esc(p["technique"])}</div><ol class="checks">{steps}</ol>'
                f'<div><b>Demonstrated impact:</b> {_esc(p["impact"])}</div>{ev}</div>')
        exploit_html = ('<div class="panel"><h2>Exploitation — demonstrated impact</h2>'
                        + "".join(parts) + "</div>")

    roadmap = corr.get("roadmap") or []
    roadmap_html = ""
    if roadmap:
        rows = []
        for i, r in enumerate(roadmap, 1):
            color = sev_color.get(r["severity"], "#5b6570")
            classes = ", ".join(r.get("classes", []))
            rows.append(
                f'<div class="row"><span><span class="sev" style="background:{color}">{_esc(r["severity"])}'
                f'</span> &nbsp;{i}. {_esc(r["summary"])} <span class="badge">{_esc(r.get("effort","?"))} effort</span>'
                f'</span><b>{_esc(classes)}</b></div>')
        roadmap_html = ('<div class="panel"><h2>Remediation roadmap (prioritized)</h2>'
                        + "".join(rows) + "</div>")

    findings_html = []
    for f in rb.findings:
        dropped = f.state == State.DROPPED
        color = sev_color.get(f.severity, "#5b6570")
        if "external-scanner" in f.tags:
            badge = f'<span class="badge">🔎 {_esc(f.verification.validator)} lead (unvalidated)</span>'
        elif f.verification.validated:
            badge = '<span class="badge cf">✔ CONFIRMED</span>'
        else:
            badge = f'<span class="badge">{_esc(f.confidence)}</span>'
        if dropped:
            badge = '<span class="badge">dropped by validator</span>'
        parts = [f'<details class="finding{" dropped" if dropped else ""}" style="border-left-color:{color}"'
                 f'{"" if dropped else " open"}>']
        parts.append('<summary>'
                     f'<span class="sev" style="background:{color}">{_esc(f.severity)}</span>'
                     f'<span class="ftitle">{_esc(f.title)}</span>{badge}</summary>')
        parts.append('<div class="fbody">')

        meta = []
        if f.cwe:
            meta.append(" ".join(f'<span class="pill">{_esc(c)}</span>' for c in f.cwe))
        for cat in owasp_tags(f):
            meta.append(f'<span class="pill">{_esc(cat)}</span>')
        if f.cvss.vector:
            meta.append(f'<span class="pill">CVSS {_esc(f.cvss.version)} {_esc(f.cvss.base_score)}</span>')
        parts.append("<div>" + "".join(meta) + "</div>")

        if f.endpoint.get("url"):
            parts.append(f'<h3>Endpoint</h3><pre>{_esc(f.endpoint.get("method",""))} {_esc(f.endpoint["url"])}</pre>')
        if f.description:
            parts.append(f'<h3>Description</h3><div>{_esc(f.description)}</div>')
        if f.impact:
            parts.append(f'<h3>Impact</h3><div>{_esc(f.impact)}</div>')
        if f.root_cause:
            parts.append(f'<h3>Root cause</h3><div>{_esc(f.root_cause)}</div>')

        if f.verification.false_positive_checks:
            title = ("How we proved it (independent validation, "
                     f"{f.verification.reproductions} reproductions)") if f.verification.validated \
                    else "Validation checks"
            parts.append(f"<h3>{_esc(title)}</h3><ul class='checks'>")
            for chk in f.verification.false_positive_checks:
                parts.append(f"<li>{_esc(chk)}</li>")
            parts.append("</ul>")

        if f.reproduction.steps:
            parts.append("<h3>Reproduction</h3><ol class='checks'>")
            for s in f.reproduction.steps:
                parts.append(f"<li>{_esc(s)}</li>")
            parts.append("</ol>")

        if f.affected_code and f.affected_code.file:
            parts.append(f'<h3>Affected code</h3><pre>{_esc(f.affected_code.file)}:'
                         f'{_esc(f.affected_code.start_line)}  (via {_esc(f.affected_code.detected_by)})\n\n'
                         f'{_esc(f.affected_code.snippet)}</pre>')
        if f.remediation.summary or f.remediation.guidance:
            parts.append("<h3>Remediation</h3>")
            if f.remediation.summary:
                parts.append(f'<div><b>{_esc(f.remediation.summary)}</b></div>')
            if f.remediation.guidance:
                parts.append(f'<div>{_esc(f.remediation.guidance)}</div>')
        if f.remediation.proposed_diff:
            parts.append('<h3>Advisory patch <span class="badge">not auto-applied</span></h3>')
            parts.append(f'<pre class="diff">{_diff_html(f.remediation.proposed_diff)}</pre>')

        if f.compliance_control_refs:
            parts.append("<h3>Compliance evidence</h3><div>"
                         + "".join(f'<span class="pill">{_esc(c)}</span>' for c in f.compliance_control_refs)
                         + "</div>")
        if f.evidence:
            parts.append(f'<h3>Evidence bundle ({len(f.evidence)} artifact(s))</h3><div class="mono" '
                         f'style="font-size:12px;color:var(--muted)">'
                         + "<br>".join(_esc(e.type + " · " + e.storage_uri) for e in f.evidence[:12])
                         + "</div>")
        parts.append("</div></details>")
        findings_html.append("".join(parts))

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Rampart report — {_esc(sc.authorization.ticket or 'engagement')}</title>
<style>{_CSS}</style></head>
<body><div class="wrap">
<header class="top">
  <div>
    <h1><span class="brandmark">Rampart</span> assessment report</h1>
    <div class="sub">{_esc(sc.authorization.ticket or 'engagement')} · authorized by
      <b>{_esc(sc.authorization.authorized_by)}</b> · {now} · rampart {__version__}</div>
  </div>
  <button id="themebtn" class="themebtn">◐ theme</button>
</header>
<div class="sub">Find, <b>prove</b>, and help fix — evidence-first, self-hosted. Only <b>validated</b>
findings are shown as confirmed; dropped candidates are listed to make the false-positive
discipline visible.</div>
<div class="kpis">{kpi_html}</div>
<div class="panel"><h2>Executive summary</h2><div>{_esc(rb.executive_summary(m))}</div></div>
<div class="panel"><h2>Safety posture</h2><div class="grid2">{posture_html}</div></div>
<div class="panel"><h2>Coverage &amp; methodology</h2><div class="grid2">{coverage_html}</div></div>
{chains_html}
{exploit_html}
{roadmap_html}
<div class="panel"><h2>Findings</h2>
{''.join(findings_html) if findings_html else '<div class="sub">No findings.</div>'}
</div>
<div class="foot">Rampart augments — it does not replace — expert human pentesters. This report is
<b>evidence of control effectiveness</b>, not a compliance attestation. Every action above passed a
deterministic allowlist → scope → risk → policy → sandbox → audit pipeline and is recorded in an
append-only, hash-chained log.</div>
</div><script>{_JS}</script></body></html>"""
