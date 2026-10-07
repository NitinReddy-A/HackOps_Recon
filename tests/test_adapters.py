"""External scanner adapter framework — parsing + graceful degradation (tools not required)."""
import json

from rampart.scanners.adapters import ADAPTERS, build_adapters, doctor
from rampart.scanners.adapters.sarif import sarif_to_findings
from rampart.scanners.adapters.tools import NmapAdapter, NucleiAdapter

_SEMGREP_SARIF = {
    "version": "2.1.0",
    "runs": [{
        "tool": {"driver": {"name": "semgrep", "rules": [
            {"id": "py.sqli", "name": "SQL injection",
             "shortDescription": {"text": "SQLi"}, "helpUri": "https://semgrep.dev/r/py.sqli",
             "properties": {"cwe": ["CWE-89: SQL Injection"]}}]}},
        "results": [{
            "ruleId": "py.sqli", "level": "error",
            "message": {"text": "Detected string-formatted SQL query"},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": "app/db.py"}, "region": {"startLine": 42}}}],
        }],
    }],
}


def test_sarif_normaliser_maps_fields_and_marks_unvalidated():
    adapter = ADAPTERS["semgrep"]()
    findings = sarif_to_findings(adapter, _SEMGREP_SARIF, "demo", "http://127.0.0.1:8080")
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == "high"                       # SARIF error -> high
    assert "CWE-89" in f.cwe
    assert "external-scanner" in f.tags and "semgrep" in f.tags
    assert f.verification.validated is False          # external leads are never auto-confirmed
    assert f.confidence != "confirmed"
    assert "db.py:42" in f.endpoint["url"]


def test_nuclei_jsonl_parse():
    adapter = NucleiAdapter()
    jsonl = "\n".join(json.dumps(x) for x in [
        {"template-id": "tech-detect", "info": {"name": "Tech", "severity": "info", "tags": ["tech"]},
         "matched-at": "http://127.0.0.1:8080"},
        {"template-id": "cve-2021-1234", "info": {"name": "Some CVE", "severity": "high",
         "classification": {"cwe-id": ["cwe-79"]}}, "matched-at": "http://127.0.0.1:8080/x"},
    ])
    findings = adapter._parse(jsonl, "demo", "http://127.0.0.1:8080")
    assert len(findings) == 2
    high = [f for f in findings if f.severity == "high"][0]
    assert "CWE-79" in high.cwe
    assert all(not f.verification.validated for f in findings)


def test_nmap_xml_parse():
    xml = ('<nmaprun><host><ports>'
           '<port protocol="tcp" portid="8080"><state state="open"/>'
           '<service name="http" product="Werkzeug" version="2.0"/></port>'
           '<port protocol="tcp" portid="22"><state state="closed"/></port>'
           '</ports></host></nmaprun>')
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
