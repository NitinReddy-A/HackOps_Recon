"""External scanner adapter framework — parsing + graceful degradation (tools not required)."""

import json

from rampart.scanners.adapters import ADAPTERS, build_adapters, doctor
from rampart.scanners.adapters.sarif import sarif_to_findings
from rampart.scanners.adapters.tools import NmapAdapter, NucleiAdapter

_SEMGREP_SARIF = {
    "version": "2.1.0",
    "runs": [
        {
            "tool": {
                "driver": {
                    "name": "semgrep",
                    "rules": [
                        {
                            "id": "py.sqli",
                            "name": "SQL injection",
                            "shortDescription": {"text": "SQLi"},
                            "helpUri": "https://semgrep.dev/r/py.sqli",
                            "properties": {"cwe": ["CWE-89: SQL Injection"]},
                        }
                    ],
                }
            },
            "results": [
                {
                    "ruleId": "py.sqli",
                    "level": "error",
                    "message": {"text": "Detected string-formatted SQL query"},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": "app/db.py"},
                                "region": {"startLine": 42},
                            }
                        }
                    ],
                }
            ],
        }
    ],
}


def test_sarif_normaliser_maps_fields_and_marks_unvalidated():
    adapter = ADAPTERS["semgrep"]()
    findings = sarif_to_findings(adapter, _SEMGREP_SARIF, "demo", "http://127.0.0.1:8080")
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == "high"  # SARIF error -> high
    assert "CWE-89" in f.cwe
    assert "external-scanner" in f.tags and "semgrep" in f.tags
    assert f.verification.validated is False  # external leads are never auto-confirmed
    assert f.confidence != "confirmed"
    assert "db.py:42" in f.endpoint["url"]


def test_nuclei_jsonl_parse():
    adapter = NucleiAdapter()
    jsonl = "\n".join(
        json.dumps(x)
        for x in [
            {
                "template-id": "tech-detect",
                "info": {"name": "Tech", "severity": "info", "tags": ["tech"]},
                "matched-at": "http://127.0.0.1:8080",
            },
            {
                "template-id": "cve-2021-1234",
                "info": {"name": "Some CVE", "severity": "high", "classification": {"cwe-id": ["cwe-79"]}},
                "matched-at": "http://127.0.0.1:8080/x",
            },
        ]
    )
    findings = adapter._parse(jsonl, "demo", "http://127.0.0.1:8080")
    assert len(findings) == 2
    high = [f for f in findings if f.severity == "high"][0]
    assert "CWE-79" in high.cwe
    assert all(not f.verification.validated for f in findings)


def test_nmap_xml_parse():
    xml = (
        "<nmaprun><host><ports>"
        '<port protocol="tcp" portid="8080"><state state="open"/>'
        '<service name="http" product="Werkzeug" version="2.0"/></port>'
        '<port protocol="tcp" portid="22"><state state="closed"/></port>'
        "</ports></host></nmaprun>"
    )
    findings = NmapAdapter()._parse(xml, "demo", "http://127.0.0.1:8080")
    assert len(findings) == 1 and "8080" in findings[0].title


def test_doctor_lists_all_adapters():
    info = doctor()
    names = {r["name"] for r in info["adapters"]}
    assert {"nuclei", "nmap", "semgrep", "trivy", "testssl"} <= names
    assert isinstance(info["docker"], bool)


def test_build_adapters_factory():
    assert build_adapters("") == []
    picked = build_adapters("nuclei,semgrep")
    assert [a.name for a in picked] == ["nuclei", "semgrep"]
    assert len(build_adapters("all")) == len(ADAPTERS)


def test_unavailable_adapter_skips_cleanly():
    # With the tool absent, is_available() is False and run() is never reached by the supervisor.
    a = NucleiAdapter()
    if not a.is_available():
        assert a.install_hint and a.help_uri


# --------------------------------------------------------------------- C-9 nuclei scope argv
class _Limits:
    max_requests_per_host_per_min = 240


class _Scope:
    limits = _Limits()
    paths_exclude = ["/admin/**", "/logout"]


def test_nuclei_argv_is_scope_constrained_passive():
    argv = NucleiAdapter(scope=_Scope(), active=False).build_argv("http://127.0.0.1:18850/")
    assert "-ni" in argv  # no interactsh / OAST
    assert "-dr" in argv  # no redirects off-host
    # rate = 240/60 = 4
    assert argv[argv.index("-rl") + 1] == "4"
    assert "intrusive,dos,fuzz" in argv  # intrusive/dos/fuzz excluded when passive
    assert NucleiAdapter(scope=_Scope()).excluded_paths() == ["/admin/**", "/logout"]


def test_nuclei_argv_active_keeps_intrusive_but_not_dos():
    argv = NucleiAdapter(scope=_Scope(), active=True).build_argv("http://127.0.0.1:18850/")
    tags = argv[argv.index("-etags") + 1]
    assert tags == "dos"  # only dos excluded under --active


def test_nuclei_rate_limit_floor_is_one():
    class _Tiny:
        class limits:
            max_requests_per_host_per_min = 30

    argv = NucleiAdapter(scope=_Tiny()).build_argv("http://t/")
    assert argv[argv.index("-rl") + 1] == "1"  # 30//60 == 0 -> floored to 1


# --------------------------------------------------------------------- C-16 semgrep honesty
def test_semgrep_skips_without_config(monkeypatch):
    from rampart.scanners.adapters.tools import SemgrepAdapter

    monkeypatch.delenv("RAMPART_SEMGREP_CONFIG", raising=False)
    a = SemgrepAdapter(repo="x")
    assert a.skip_reason()
    assert a._cmd("x") == []
    assert a.run(None, "http://t", "demo") == []


def test_semgrep_runs_with_local_config(monkeypatch, tmp_path):
    from rampart.scanners.adapters.tools import SemgrepAdapter

    rules = tmp_path / "rules.yml"
    rules.write_text("rules: []\n")
    monkeypatch.setenv("RAMPART_SEMGREP_CONFIG", str(rules))
    a = SemgrepAdapter(repo="x")
    assert a.skip_reason() == ""
    assert a.uses_network() is False
    assert str(rules) in a._cmd("x")


def test_semgrep_registry_config_is_flagged_network(monkeypatch):
    from rampart.scanners.adapters.tools import SemgrepAdapter

    monkeypatch.setenv("RAMPART_SEMGREP_CONFIG", "p/ci")
    assert SemgrepAdapter(repo="x").uses_network() is True


# --------------------------------------------------------------------- C-17 gitleaks tempfile
def test_gitleaks_writes_tempfile_not_dev_stdout(tmp_path, monkeypatch):
    from rampart.scanners.adapters import tools
    from rampart.scanners.adapters.tools import GitleaksAdapter

    seen = {}

    def fake_exec(self, cmd):
        # the report path must be a real writable file, never /dev/stdout
        rp = cmd[cmd.index("--report-path") + 1]
        seen["report_path"] = rp
        assert rp != "/dev/stdout"
        with open(rp, "w", encoding="utf-8") as fh:
            json.dump(_SEMGREP_SARIF, fh)

        class _R:
            returncode = 1  # gitleaks returns non-zero when leaks are found

        return _R()

    monkeypatch.setattr(tools.ScannerAdapter, "_exec", fake_exec)
    monkeypatch.setattr(GitleaksAdapter, "resolved_binary", lambda self: "gitleaks")
    findings = GitleaksAdapter(repo=str(tmp_path)).run(None, "http://t", "demo")
    assert seen["report_path"] != "/dev/stdout"
    assert len(findings) == 1  # report parsed despite non-zero exit
