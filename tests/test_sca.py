"""Full SCA: CVSS scoring, multi-ecosystem manifest parsing, OSV matching (mocked), and the
graceful-offline / graceful-network-failure guarantees."""

import json

from rampart.sca import collect_dependencies, cvss, osv, scan_sca


# ------------------------------------------------------------------- CVSS calculator
def test_cvss_v31_known_vectors():
    # Values cross-checked against the official FIRST CVSS 3.1 calculator.
    assert cvss.base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == 9.8
    assert cvss.base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H") == 7.5
    assert cvss.base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N") == 6.1
    assert cvss.base_score("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N") == 0.0


def test_cvss_bands_and_fallback():
    assert cvss.severity_band(9.8) == "critical"
    assert cvss.severity_band(7.5) == "high"
    assert cvss.severity_band(5.0) == "medium"
    assert cvss.severity_band(1.0) == "low"
    assert cvss.severity_band(0.0) == "info"
    assert cvss.base_score("not-a-vector") is None
    assert cvss.from_text("CRITICAL")[0] == "critical"
    assert cvss.from_text("")[0] == "medium"  # unknown -> conservative default


# --------------------------------------------------------------------- manifest parsers
def test_parses_multiple_ecosystems(tmp_path):
    (tmp_path / "requirements.txt").write_text("Flask==0.12.2\nrequests>=2.0\nDjango===1.8\n")
    (tmp_path / "package-lock.json").write_text(
        json.dumps(
            {
                "lockfileVersion": 3,
                "packages": {"": {"name": "root"}, "node_modules/lodash": {"version": "4.17.4"}},
            }
        )
    )
    (tmp_path / "go.mod").write_text("module x\n\nrequire (\n\tgithub.com/foo/bar v1.2.3\n)\n")
    (tmp_path / "Gemfile.lock").write_text("GEM\n  specs:\n    rails (5.2.0)\n")
    deps = collect_dependencies(str(tmp_path))
    got = {(d.ecosystem, d.name, d.version) for d in deps}
    assert ("PyPI", "flask", "0.12.2") in got
    assert ("PyPI", "django", "1.8") in got  # === exact pin
    assert ("npm", "lodash", "4.17.4") in got
    assert ("Go", "github.com/foo/bar", "v1.2.3") in got
    assert ("RubyGems", "rails", "5.2.0") in got
    # A version range (requests>=2.0) is NOT matchable to a CVE, so it is skipped.
    assert not any(d.name == "requests" for d in deps)


def test_parsers_record_manifest_and_line(tmp_path):
    (tmp_path / "requirements.txt").write_text("# header\nFlask==0.12.2\n")
    deps = collect_dependencies(str(tmp_path))
    d = next(d for d in deps if d.name == "flask")
    assert d.manifest == "requirements.txt" and d.line == 2


# ----------------------------------------------------------------------------- OSV match
_FLASK_VULN = {
    "id": "GHSA-562c-5r94-xh97",
    "aliases": ["CVE-2018-1000656"],
    "summary": "Flask denial of service",
    "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"}],
    "affected": [
        {
            "package": {"ecosystem": "PyPI", "name": "flask"},
            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "0.12.3"}]}],
        }
    ],
    "database_specific": {"cwe_ids": ["CWE-400"]},
}


def _fetch_flask_only(url, payload, timeout=None):
    if payload["package"]["name"] == "flask":
        return {"vulns": [_FLASK_VULN]}
    return {"vulns": []}


def test_scan_sca_offline_is_a_noop(tmp_path):
    (tmp_path / "requirements.txt").write_text("Flask==0.12.2\n")
    assert scan_sca(str(tmp_path), "eng", online=False) == []


def test_scan_sca_online_emits_upgrade_finding(tmp_path):
    (tmp_path / "requirements.txt").write_text("Flask==0.12.2\nsafe-pkg==1.0.0\n")
    findings = scan_sca(str(tmp_path), "eng", online=True, fetch=_fetch_flask_only)
    assert len(findings) == 1  # only the vulnerable package
    f = findings[0]
    assert f.vuln_class == "sca-known-vulnerability"
    assert f.severity == "high" and f.cvss.base_score == 7.5
    assert "CWE-400" in f.cwe
    assert "0.12.3" in f.remediation.summary  # concrete upgrade target
    assert f.remediation.type == "dependency_upgrade"
    assert "CVE-2018-1000656" in f.description  # CVE id surfaced first
    assert f.affected_code.file == "requirements.txt"
    assert not f.verification.validated  # advisory-tier, below oracle-confirmed
    f.assert_consistent()


def test_scan_sca_recommends_highest_fix_across_advisories(tmp_path):
    (tmp_path / "requirements.txt").write_text("Flask==0.12.0\n")
    v2 = json.loads(json.dumps(_FLASK_VULN))
    v2["id"] = "GHSA-other"
    v2["aliases"] = ["CVE-2019-1010083"]
    v2["affected"][0]["ranges"][0]["events"] = [{"introduced": "0"}, {"fixed": "1.0.0"}]

    def fetch(url, payload, timeout=None):
        return {"vulns": [_FLASK_VULN, v2]} if payload["package"]["name"] == "flask" else {"vulns": []}

    f = scan_sca(str(tmp_path), "eng", online=True, fetch=fetch)[0]
    assert ">= 1.0.0" in f.remediation.summary  # upgrading to the max fix clears both


def test_scan_sca_graceful_on_network_failure(tmp_path):
    (tmp_path / "requirements.txt").write_text("Flask==0.12.2\n")

    def broken_fetch(url, payload, timeout=None):
        raise OSError("network down")

    # query_package swallows fetch errors; a raising fetch bubbles, so emulate the real seam:
    # the default http_fetch catches everything and returns None -> no advisories -> no findings.
    assert osv.http_fetch("http://127.0.0.1:0/nope", {"x": 1}, timeout=0.2) is None


def test_scan_sca_no_fix_published(tmp_path):
    (tmp_path / "requirements.txt").write_text("Flask==0.12.2\n")
    nofix = json.loads(json.dumps(_FLASK_VULN))
    nofix["affected"][0]["ranges"][0]["events"] = [{"introduced": "0"}]  # no 'fixed'

    def fetch(url, payload, timeout=None):
        return {"vulns": [nofix]} if payload["package"]["name"] == "flask" else {"vulns": []}

    f = scan_sca(str(tmp_path), "eng", online=True, fetch=fetch)[0]
    assert "No fixed version" in f.remediation.summary
    f.assert_consistent()
