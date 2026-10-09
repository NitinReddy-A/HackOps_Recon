"""Output surfaces must be safe against target-controlled text and agree on what "confirmed" means.

Covers: Markdown/compliance/SOC 2 escaping (F8), Fixed findings never counted as confirmed (F6),
severity sorting by rank (F19), odd severity values, SARIF rule metadata, the PR comment (F14) and
the sticky-comment poster only editing its own comment (F13).
"""

import json
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from conftest import write_engagement

from rampart.integrations import github
from rampart.reporting import ReportBuilder
from rampart.reporting.mdsafe import md, md_code, md_fence
from rampart.reporting.pr_comment import MARKER, render_pr_comment
from rampart.reporting.status import is_confirmed, norm_severity
from rampart.schemas.finding import Finding, State
from rampart.schemas.scope import EngagementScope

EVIL = "Evil/1.0 <script>alert('srv')</script>\"><img src=x onerror=alert(1)> `tick` | pipe @octocat <!-- "


def _scope(tmp_path):
    return EngagementScope.from_file(write_engagement(tmp_path, 18601))


def _finding(title, sev="high", state=State.VALIDATED, validated=True, **kw):
    f = Finding(
        engagement_id="e", title=title, vuln_class=kw.pop("vuln_class", "XSS"), severity=sev, state=state
    )
    f.verification.validated = validated
    f.cwe = kw.pop("cwe", ["CWE-79"])
    for k, v in kw.items():
        setattr(f, k, v)
    return f


def _hostile_findings():
    f = _finding(
        f"Server software/version disclosure in Server header: {EVIL}",
        sev="low",
        vuln_class="security-misconfiguration",
        cwe=["CWE-200"],
        endpoint={"method": "GET", "url": "http://127.0.0.1/p/<script>alert('path')</script>?q=`x`"},
        description=f"The Server header is {EVIL}",
        impact=EVIL,
        root_cause="[click](javascript:alert(1))",
    )
    f.verification.false_positive_checks = [EVIL]
    f.reproduction.steps = [f"GET / -> {EVIL}"]
    f.remediation.summary = EVIL
    f.remediation.guidance = EVIL
    f.remediation.proposed_diff = (
        "--- a\n+++ b\n+<script>alert('diff')</script>\n+````\n+<img src=x onerror=alert(2)>"
    )
    g = _finding(f"Reflected XSS in '\"><img src=x onerror=alert(9)>' on GET /x{EVIL}")
    g.remediation.summary = "Encode output"
    return [f, g]


def _scan_with_hostile_chain():
    return {
        "correlation": {
            "risk_score": 50,
            "risk_band": "Medium",
            "chains": [
                {
                    "title": f"Chain {EVIL}",
                    "severity": "high",
                    "rationale": EVIL,
                    "steps": [EVIL],
                    "contributing": [EVIL, "<b>x</b>"],
                }
            ],
            "roadmap": [
                {"summary": EVIL, "severity": "high", "classes": [EVIL], "count": 1, "guidance": EVIL}
            ],
        },
        "exploitation": [
            {
                "demonstrated": True,
                "title": EVIL,
                "technique": EVIL,
                "steps": [EVIL],
                "impact": EVIL,
                "samples": [EVIL],
            }
        ],
        "scanner_runs": [{"scanner": EVIL, "available": True, "findings": 1}],
        "plan": {"order": [EVIL]},
        "classes_tested": [EVIL],
    }


_CODE_SPAN = re.compile(r"(?<!\\)(`+)(.+?)(?<!`)\1(?!`)")


def _assert_no_live_html(text):
    # Outside fenced blocks and code spans, no raw tag or HTML comment may survive.
    kept, in_fence = [], ""
    for line in text.splitlines():
        if line.startswith("```"):
            fence = line[: len(line) - len(line.lstrip("`"))]
            in_fence = "" if in_fence and fence == in_fence else (in_fence or fence)
            continue
        if not in_fence:
            kept.append(line)
    stripped = _CODE_SPAN.sub("", "\n".join(kept))
    for bad in ("<script", "<img", "<!--", "<b>"):
        assert bad not in stripped, bad


def _render(markdown_text):
    """Render with python-markdown when available (it passes raw HTML through)."""
    try:
        import markdown
    except ImportError:  # pragma: no cover - optional dev dependency
        return None
    return markdown.markdown(markdown_text, extensions=["tables", "fenced_code"])


def _assert_rendered_safe(markdown_text):
    out = _render(markdown_text)
    if out is None:
        return
    assert "<script" not in out and "<img" not in out and "<b>" not in out
    assert 'href="javascript:' not in out  # no live link


# ----------------------------------------------------------------------------- F8
def test_markdown_report_escapes_target_controlled_strings(tmp_path):
    rb = ReportBuilder(_hostile_findings(), _scope(tmp_path), None, _scan_with_hostile_chain(), {})
    out = rb.to_markdown()
    _assert_no_live_html(out)
    assert "&lt;script&gt;" in out
    assert "\n`````diff\n" in out  # the diff fence outlasts the ```` run inside it
    _assert_rendered_safe(out)


def test_compliance_and_soc2_escape_titles(tmp_path):
    rb = ReportBuilder(_hostile_findings(), _scope(tmp_path), None, {}, {})
    for out in (rb.to_compliance(), rb.to_soc2()):
        _assert_no_live_html(out)
        assert "&lt;script&gt;" in out
        _assert_rendered_safe(out)


def test_md_helpers():
    assert md("a\nb\r\nc") == "a b c"
    assert md("<x>&`[y](z)") == "&lt;x&gt;&amp;\\`\\[y\\](z)"
    assert md_code("a``b") == "```a``b```"
    assert md_code("`x") == "`` `x ``"
    assert md_code("a|b", table=True) == "`a\\|b`"
    fence = md_fence("+````\n+x", "diff")
    assert fence[0] == "`````diff" and fence[-1] == "`````"


# ----------------------------------------------------------------------------- F6
def test_fixed_finding_is_not_confirmed_anywhere(tmp_path):
    open_f = _finding("SQL injection in 'id'", sev="critical", vuln_class="SQLI", cwe=["CWE-89"])
    fixed = _finding(
        "IDOR on /api/orders/{id}", sev="high", state=State.FIXED, vuln_class="IDOR/BOLA", cwe=["CWE-639"]
    )
    fixed.verification.last_retest = {"result": "fixed", "at": "2026-10-09T00:00:00Z"}
    rb = ReportBuilder([open_f, fixed], _scope(tmp_path), None, {}, {})
    assert is_confirmed(open_f) and not is_confirmed(fixed)

    m = rb.metrics()
    assert m["confirmed"] == 1 and m["fixed"] == 1
    assert m["by_severity"] == {"critical": 1}

    md_out = rb.to_markdown()
    findings_sec, fixed_sec = md_out.split("## Findings")[1].split("## Fixed (verified by retest)")
    assert "IDOR" not in findings_sec and "IDOR" in fixed_sec

    html = rb.to_html()
    assert "Fixed (verified by retest)" in html

    data = json.loads(rb.to_json())
    assert data["metrics"]["confirmed"] == 1 and data["metrics"]["fixed"] == 1

    sarif = json.loads(rb.to_sarif())
    assert [r["ruleId"] for r in sarif["runs"][0]["results"]] == ["CWE-89"]

    pr = render_pr_comment([open_f, fixed], fail_on="high")
    assert "**1 confirmed**" in pr and "1 verified fixed" in pr and "IDOR" not in pr

    soc2 = rb.to_soc2()
    ops = soc2.split("## Operating effectiveness")[1]
    assert ops.count("IDOR on /api/orders") == 1
    assert "IDOR" not in soc2.split("## Control exceptions")[1].split("## Operating effectiveness")[0]


def test_soc2_lists_a_duplicated_fixed_finding_once(tmp_path):
    fixed = _finding("IDOR on /api/orders/{id}", state=State.FIXED, vuln_class="IDOR/BOLA", cwe=["CWE-639"])
    rb = ReportBuilder([fixed, fixed], _scope(tmp_path), None, {}, {})
    ops = rb.to_soc2().split("## Operating effectiveness")[1]
    assert ops.count("IDOR on /api/orders") == 1


# ----------------------------------------------------------------------------- F19 / odd severities
def test_exceptions_sorted_by_severity_rank(tmp_path):
    fs = [
        _finding("L-finding", sev="low"),
        _finding("M-finding", sev="medium"),
        _finding("C-finding", sev="critical"),
        _finding("H-finding", sev="high"),
    ]
    rb = ReportBuilder(fs, _scope(tmp_path), None, {}, {})
    for out in (rb.to_soc2(), rb.to_compliance()):
        order = [out.index(t) for t in ("C-finding", "H-finding", "M-finding", "L-finding")]
        assert order == sorted(order), out


def test_renderers_tolerate_odd_severity_values(tmp_path):
    fs = [_finding("none-sev", sev=None), _finding("int-sev", sev=7), _finding("weird", sev="Bogus")]
    rb = ReportBuilder(fs, _scope(tmp_path), None, {}, {})
    for render in (rb.to_markdown, rb.to_html, rb.to_json, rb.to_sarif, rb.to_soc2, rb.to_compliance):
        render()
    assert "[INFO] none-sev" in rb.to_markdown()
    assert norm_severity(" HIGH ") == "high" and norm_severity(None) == "info"
    render_pr_comment(fs, fail_on="high")


# ----------------------------------------------------------------------------- static risk
def test_static_findings_get_their_own_risk_line(tmp_path):
    sast = _finding(
        "Hard-coded secret", sev="high", validated=False, state=State.EVIDENCE_FOUND, tags=["sast"]
    )
    rb = ReportBuilder([sast], _scope(tmp_path), None, {}, {})
    m = rb.metrics()
    assert m["static_unvalidated"] == 1 and m["static_risk_score"] > 0
    assert "Static-analysis exposure" in rb.to_markdown()
    assert "Static-analysis exposure" in rb.to_html()


# ----------------------------------------------------------------------------- SARIF
def test_sarif_rules_describe_the_rule_and_omit_empty_help_uri(tmp_path):
    a = _finding("SQL injection in 'q' on GET /x", vuln_class="SQLI", cwe=["CWE-89"])
    b = _finding("Some custom check", vuln_class="custom-check", cwe=[])
    rb = ReportBuilder([a, b], _scope(tmp_path), None, {}, {})
    rules = {r["id"]: r for r in json.loads(rb.to_sarif())["runs"][0]["tool"]["driver"]["rules"]}
    assert rules["CWE-89"]["shortDescription"]["text"] == "CWE-89: SQL Injection"
    assert rules["CWE-89"]["helpUri"].startswith("https://cwe.mitre.org/")
    assert "helpUri" not in rules["custom-check"]
    assert "Some custom check" not in json.dumps(rules)


# ----------------------------------------------------------------------------- F14
def _dict_finding(sev, title, url):
    return {
        "severity": sev,
        "title": title,
        "cwe": ["CWE-89"],
        "endpoint": {"method": "GET", "url": url},
        "verification": {"validated": True},
        "state": "Validated",
        "tags": [],
    }


def test_pr_comment_neutralises_injection():
    body = render_pr_comment(
        [
            _dict_finding("high", "SQL injection in '<!--' on GET /search", "http://t/search"),
            _dict_finding("medium", "Reflected XSS in 'q' on GET /a`b|c\nd", "http://t/a`b|c"),
            _dict_finding("low", "Server header (cc @org/security-team, see #12)", "http://t/"),
        ],
        fail_on="high",
    )
    rows = [line for line in body.splitlines() if line.startswith("| ") and "Severity" not in line]
    assert len(rows) == 3
    for row in rows:
        # exactly 5 unescaped pipes -> 4 cells, the table stays intact
        assert len(re.findall(r"(?<!\\)\|", row)) == 5, row
    assert "<!--" not in body.replace(MARKER, "")
    assert "@org" not in body and "@‍org" in body and "#12" not in body
    assert len(re.findall(r"(?<!\\)`", body)) % 2 == 0  # every code span is closed


# ----------------------------------------------------------------------------- F13
class _FakeGitHub:
    def __init__(self, comments, user_status=403, patch_status=200):
        self.log = []
        outer = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _j(self, code, obj):
                b = json.dumps(obj).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(b)))
                self.end_headers()
                self.wfile.write(b)

            def do_GET(self):
                outer.log.append(("GET", self.path))
                if self.path == "/user":
                    if user_status != 200:
                        return self._j(user_status, {"message": "Resource not accessible by integration"})
                    return self._j(200, {"login": "me-bot", "type": "User"})
                page = int(self.path.rsplit("page=", 1)[-1]) if "page=" in self.path else 1
                return self._j(200, comments if page == 1 else [])

            def _body(self):
                return json.loads(self.rfile.read(int(self.headers["Content-Length"])))

            def do_PATCH(self):
                self._body()
                outer.log.append(("PATCH", self.path))
                if patch_status != 200:
                    return self._j(patch_status, {"message": "nope"})
                return self._j(200, {"html_url": "http://x/c/1", "id": 1})

            def do_POST(self):
                self._body()
                outer.log.append(("POST", self.path))
                return self._j(201, {"html_url": "http://x/c/2", "id": 2})

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}"

    def methods(self):
        return [(m, p) for m, p in self.log if m != "GET"]


def _post(fake):
    try:
        return github.post_or_update_comment(MARKER + "\nnew", repo="o/r", pr=5, token="t", api_url=fake.url)
    finally:
        fake.httpd.shutdown()


def test_sticky_comment_never_edits_a_foreign_comment():
    fake = _FakeGitHub(
        [{"id": 777, "body": f"{MARKER} hidden", "user": {"login": "attacker", "type": "User"}}]
    )
    res = _post(fake)
    assert res["action"] == "created"
    assert fake.methods() == [("POST", "/repos/o/r/issues/5/comments")]


def test_sticky_comment_ignores_marker_not_at_start():
    fake = _FakeGitHub(
        [{"id": 9, "body": f"lol {MARKER}", "user": {"login": "github-actions[bot]", "type": "Bot"}}]
    )
    assert _post(fake)["action"] == "created"


def test_sticky_comment_updates_own_bot_comment():
    fake = _FakeGitHub(
        [{"id": 42, "body": f"{MARKER}\nold", "user": {"login": "github-actions[bot]", "type": "Bot"}}]
    )
    res = _post(fake)
    assert res["action"] == "updated" and fake.methods() == [("PATCH", "/repos/o/r/issues/comments/42")]


def test_sticky_comment_matches_token_login_when_user_endpoint_works():
    comments = [
        {"id": 1, "body": f"{MARKER}\nold", "user": {"login": "github-actions[bot]", "type": "Bot"}},
        {"id": 2, "body": f"{MARKER}\nold", "user": {"login": "me-bot", "type": "User"}},
    ]
    fake = _FakeGitHub(comments, user_status=200)
    assert _post(fake)["id"] == 2


def test_sticky_comment_falls_back_to_post_when_patch_forbidden():
    fake = _FakeGitHub(
        [{"id": 42, "body": f"{MARKER}\nold", "user": {"login": "github-actions[bot]", "type": "Bot"}}],
        patch_status=403,
    )
    res = _post(fake)
    assert res["posted"] and res["action"] == "created"
    assert fake.methods() == [
        ("PATCH", "/repos/o/r/issues/comments/42"),
        ("POST", "/repos/o/r/issues/5/comments"),
    ]
