"""SCA correctness regressions: per-installed-version fix selection (no downgrades), full CVE list
for KEV/EPSS, PyPI name normalisation, dist->import aliasing + unknown-import handling, framework
entrypoints in the call graph, manifest coverage (requirements-*, -r, pyproject, package.json,
yarn/pnpm locks, go.mod replace), OSV querybatch, PEP 440 / SemVer ordering, SARIF locations.
All network access goes through injected fetch seams."""

import json

from rampart.sca import collect_dependencies, osv, scan_sca
from rampart.sca import scanner as sca_scanner
from rampart.sca.enrich import _cves_of, reachable
from rampart.sca.parsers import Dep, collect_unpinned
from rampart.sca.reachability import analyze_repo, reachability


def _vuln(
    vid, eco, name, events, aliases=(), score="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", rtype=None
):
    return {
        "id": vid,
        "aliases": list(aliases),
        "summary": f"{name} issue",
        "severity": [{"type": "CVSS_V3", "score": score}],
        "affected": [
            {
                "package": {"ecosystem": eco, "name": name},
                "ranges": [{"type": rtype or ("SEMVER" if eco == "npm" else "ECOSYSTEM"), "events": events}],
            }
        ],
    }


def _fetch_for(table):
    """Per-package /v1/query seam: {(eco, name): [vulns]}."""

    def fetch(url, payload, timeout=None):
        pkg = payload["package"]
        return {"vulns": table.get((pkg["ecosystem"], pkg["name"]), [])}

    return fetch


# ------------------------------------------------------------------------------- D1 / D25
def test_fix_version_matches_installed_range_never_downgrades():
    json5 = _vuln(
        "GHSA-9c47",
        "npm",
        "json5",
        [{"introduced": "0"}, {"fixed": "1.0.2"}, {"introduced": "2.0.0"}, {"fixed": "2.2.2"}],
    )
    assert osv.fixed_version_for(json5, "npm", "json5", "2.2.1") == "2.2.2"
    assert osv.fixed_version_for(json5, "npm", "json5", "1.0.0") == "1.0.2"
    assert osv.fixed_version_for(json5, "npm", "json5", "3.0.0") == ""  # nothing above installed
    git_only = _vuln("G", "npm", "x", [{"introduced": "0"}, {"fixed": "abc123"}], rtype="GIT")
    assert osv.fixed_version_for(git_only, "npm", "x", "1.0.0") == ""


def test_scan_recommends_upgrade_above_installed(tmp_path):
    (tmp_path / "package-lock.json").write_text(
        json.dumps({"lockfileVersion": 3, "packages": {"": {}, "node_modules/semver": {"version": "7.5.1"}}})
    )
    semver = _vuln(
        "GHSA-c2qf",
        "npm",
        "semver",
        [
            {"introduced": "0"},
            {"fixed": "5.7.2"},
            {"introduced": "6.0.0"},
            {"fixed": "6.3.1"},
            {"introduced": "7.0.0"},
            {"fixed": "7.5.2"},
        ],
        aliases=["CVE-2022-25883"],
    )
    f = scan_sca(
        str(tmp_path), "e", online=True, fetch=_fetch_for({("npm", "semver"): [semver]}), enrich=False
    )[0]
    assert "to >= 7.5.2" in f.remediation.summary


def test_title_counts_unique_vulns_and_cvss_version_from_vector(tmp_path):
    (tmp_path / "requirements.txt").write_text("Flask==0.12.2\n")
    a = _vuln(
        "PYSEC-2019-1", "PyPI", "flask", [{"introduced": "0"}, {"fixed": "1.0"}], aliases=["CVE-2019-1010083"]
    )
    b = _vuln(
        "GHSA-5wv5",
        "PyPI",
        "flask",
        [{"introduced": "0"}, {"fixed": "1.0"}],
        aliases=["CVE-2019-1010083", "PYSEC-2019-1"],
        score="CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
    )
    f = scan_sca(
        str(tmp_path), "e", online=True, fetch=_fetch_for({("PyPI", "flask"): [a, b]}), enrich=False
    )[0]
    assert "(1 advisory/ies" in f.title  # two OSV records for ONE vulnerability
    assert f.cvss.version == "3.1" and f.cvss.vector.startswith("CVSS:3.1/")


def test_go_install_hint_has_v_prefix(tmp_path):
    (tmp_path / "go.mod").write_text("module x\n\nrequire golang.org/x/text v0.3.7\n")
    v = _vuln("GO-2022-1", "Go", "golang.org/x/text", [{"introduced": "0"}, {"fixed": "0.3.8"}])
    f = scan_sca(
        str(tmp_path), "e", online=True, fetch=_fetch_for({("Go", "golang.org/x/text"): [v]}), enrich=False
    )[0]
    assert "go get golang.org/x/text@v0.3.8" in f.remediation.guidance


def test_version_ordering_pep440_and_semver():
    k = osv._version_key
    assert sorted(["2.0.5", "2.0.0rc1", "2.0.0", "2.0.0.dev1", "2.0.0a1", "2.0.0.post1"], key=k) == [
        "2.0.0.dev1",
        "2.0.0a1",
        "2.0.0rc1",
        "2.0.0",
        "2.0.0.post1",
        "2.0.5",
    ]
    assert sorted(["2.0.5", "2.0.0", "2.0.0-rc.1", "1.10.0"], key=lambda v: k(v, "npm")) == [
        "1.10.0",
        "2.0.0-rc.1",
        "2.0.0",
        "2.0.5",
    ]


# ------------------------------------------------------------------------------------- D2
def test_kev_sees_cves_beyond_the_displayed_reference_list(tmp_path):
    (tmp_path / "requirements.txt").write_text("struts==2.3.5\n")
    vulns = [
        _vuln(
            f"GHSA-{i}",
            "PyPI",
            "struts",
            [{"introduced": "0"}, {"fixed": "6.0"}],
            aliases=[f"CVE-2016-{1000 + i}"],
        )
        for i in range(12)
    ]
    vulns.append(
        _vuln(
            "GHSA-kev", "PyPI", "struts", [{"introduced": "0"}, {"fixed": "6.0"}], aliases=["CVE-2017-5638"]
        )
    )
    findings = scan_sca(
        str(tmp_path),
        "e",
        online=True,
        fetch=_fetch_for({("PyPI", "struts"): vulns}),
        fetch_epss_fn=lambda url, timeout=None: {"data": []},
        fetch_kev_fn=lambda url, timeout=None: {"vulnerabilities": [{"cveID": "CVE-2017-5638"}]},
    )
    f = findings[0]
    assert "CVE-2017-5638" in _cves_of(f)
    assert f.exploit_intel["kev"] is True and f.exploit_intel["priority"] == "P0"


# ------------------------------------------------------------------------------- D3 / D4
def _flask_app(tmp_path):
    app = tmp_path / "app"
    app.mkdir()
    (app / "server.py").write_text(
        "from flask import Flask, request\n"
        "import jwt\n"
        "import requests\n"
        "import mystery_mod\n"
        "app = Flask(__name__)\n"
        "\n"
        "@app.route('/fetch')\n"
        "def fetch():\n"
        "    return requests.get(request.args['u']).text\n"
        "\n"
        "@app.route('/tok')\n"
        "def tok():\n"
        "    return jwt.decode(request.args['t'], 'k', algorithms=['HS256'])\n"
        "\n"
        "def view(req):\n"
        "    return mystery_mod.run(req)\n"
        "\n"
        "urlpatterns = [path('v/', view)]\n"
        "\n"
        "class Config:\n"
        "    SESSION = requests.Session()\n"
    )
    return str(tmp_path)


def test_decorated_handlers_and_referenced_views_are_entrypoints(tmp_path):
    g = analyze_repo(_flask_app(tmp_path))
    assert reachability(g, ["requests"])["tier"] == "reachable"
    assert reachability(g, ["jwt"])["tier"] == "reachable"
    assert reachability(g, ["mystery_mod"])["tier"] == "reachable"  # view passed to path(...)
    assert "requests.Session" in reachability(g, ["requests"])["reachable_symbols"]  # class body


def test_pyjwt_resolves_to_jwt_and_unknown_import_names_are_not_unreachable(tmp_path):
    repo = _flask_app(tmp_path)
    pyjwt = Dep("PyPI", "pyjwt", "1.5.0", "requirements.txt", 1)
    r, detail = reachable(pyjwt, repo)
    assert r is True and detail["tier"] == "reachable"
    # A dist whose import name we cannot map, while the repo imports an unattributed module
    # (mystery_mod): we must NOT claim "unreachable" and drop its severity.
    odd = Dep("PyPI", "py-mystery-dist", "1.0", "requirements.txt", 2)
    r2, detail2 = reachable(odd, repo, all_deps=[pyjwt, odd])
    assert r2 is None and detail2["tier"] == "unknown-import-name"
    # ...but when every third-party import is attributed, an unimported dep IS unreachable.
    others = [
        pyjwt,
        Dep("PyPI", "flask", "1", "r", 1),
        Dep("PyPI", "requests", "1", "r", 1),
        Dep("PyPI", "mystery-mod", "1", "r", 1),
        Dep("PyPI", "urllib3", "1", "r", 1),
    ]
    r3, detail3 = reachable(others[-1], repo, all_deps=others)
    assert r3 is False and detail3["tier"] == "unreachable"


# ---------------------------------------------------------------------------------- D13
def test_pypi_names_are_pep503_normalised(tmp_path):
    (tmp_path / "requirements.txt").write_text("Flask_Cors==3.0.8\n")
    deps = collect_dependencies(str(tmp_path))
    assert [(d.name, d.version) for d in deps] == [("flask-cors", "3.0.8")]
    v = _vuln("GHSA-x", "PyPI", "Flask-CORS", [{"introduced": "0"}, {"fixed": "3.0.9"}])
    assert osv.fixed_version_for(v, "PyPI", "flask-cors", "3.0.8") == "3.0.9"


# ----------------------------------------------------------------------------- D14 / D24
def test_manifest_coverage_and_pinning_rules(tmp_path):
    py = tmp_path / "py"
    py.mkdir()
    (py / "requirements.txt").write_text(
        "Flask==0.12.2\nurllib3>=1.24,<2\nidna==2.*\n-r base-requirements.txt\npkg @ https://x/pkg.tgz\n"
    )
    (py / "base-requirements.txt").write_text("Pillow==6.0.0\n")
    (py / "requirements-dev.txt").write_text("PyJWT==1.5.0\n")
    reqdir = tmp_path / "requirements"
    reqdir.mkdir()
    (reqdir / "prod.txt").write_text("Django==3.2.0\n")
    pp = tmp_path / "pyproj"
    pp.mkdir()
    (pp / "pyproject.toml").write_text(
        '[project]\nname = "x"\ndependencies = ["Jinja2==2.10", "requests>=2.0"]\n'
    )
    node = tmp_path / "node"
    node.mkdir()
    (node / "package.json").write_text('{"dependencies": {"left-pad": "1.3.0", "express": "^4.0.0"}}')
    (node / "package-lock.json").write_text(
        json.dumps(
            {
                "lockfileVersion": 3,
                "packages": {
                    "": {},
                    "node_modules/lodash": {"version": "4.17.4"},
                    "packages/local": {"version": "1.0.0"},
                    "node_modules/linked": {"link": True, "resolved": "packages/local"},
                },
            }
        )
    )
    yarn = tmp_path / "yarn"
    yarn.mkdir()
    (yarn / "yarn.lock").write_text(
        '"@babel/core@^7.0.0", "@babel/core@^7.1.0":\n  version "7.1.2"\n\nminimist@^1.2.0:\n  version "1.2.0"\n'
    )
    pnpm = tmp_path / "pnpm"
    pnpm.mkdir()
    (pnpm / "pnpm-lock.yaml").write_text(
        "lockfileVersion: '6.0'\npackages:\n  /ms@2.0.0:\n    resolution: {integrity: x}\n"
        "  /@types/node@18.0.0(peer@1.0.0):\n    resolution: {integrity: y}\n"
    )
    go = tmp_path / "go"
    go.mkdir()
    (go / "go.mod").write_text(
        "module x\n\nrequire (\n\tgolang.org/x/text v0.3.7\n\tgithub.com/local/thing v1.0.0\n)\n\n"
        "replace golang.org/x/text => golang.org/x/text v0.14.0\nreplace github.com/local/thing => ../thing\n"
    )
    (go / "go.sum").write_text("golang.org/x/text v0.3.0 h1:abc=\ngolang.org/x/text v0.3.7 h1:abc=\n")

    got = {(d.ecosystem, d.name, d.version) for d in collect_dependencies(str(tmp_path))}
    for expected in (
        ("PyPI", "flask", "0.12.2"),
        ("PyPI", "pillow", "6.0.0"),
        ("PyPI", "pyjwt", "1.5.0"),
        ("PyPI", "django", "3.2.0"),
        ("PyPI", "jinja2", "2.10"),
        ("npm", "lodash", "4.17.4"),
        ("npm", "left-pad", "1.3.0"),
        ("npm", "@babel/core", "7.1.2"),
        ("npm", "minimist", "1.2.0"),
        ("npm", "ms", "2.0.0"),
        ("npm", "@types/node", "18.0.0"),
        ("Go", "golang.org/x/text", "v0.14.0"),
    ):
        assert expected in got, expected
    names = {n for _e, n, _v in got}
    assert "packages/local" not in names and "linked" not in names and "github.com/local/thing" not in names
    assert not any(n in ("idna", "urllib3", "requests", "express") for n in names)
    assert not any(v in ("v0.3.0", "v0.3.7", "2.") for _e, _n, v in got)

    unpinned = {(u.manifest, u.name) for u in collect_unpinned(str(tmp_path))}
    assert ("py/requirements.txt", "urllib3") in unpinned and ("py/requirements.txt", "idna") in unpinned
    assert ("pyproj/pyproject.toml", "requests") in unpinned
    assert not any(n == "express" for _m, n in unpinned)  # ranged, but a lockfile pins it


# ------------------------------------------------------------------------------------ D15
def test_querybatch_is_used_and_no_silent_package_cap(tmp_path):
    lock = {"lockfileVersion": 3, "packages": {"": {}}}
    for i in range(1200):
        lock["packages"][f"node_modules/p{i}"] = {"version": "1.0.0"}
    (tmp_path / "package-lock.json").write_text(json.dumps(lock))
    calls = {"batch": 0, "detail": 0, "query": 0}
    vuln = _vuln("GHSA-last", "npm", "p1199", [{"introduced": "0"}, {"fixed": "1.0.1"}])

    def fetch(url, payload, timeout=None):
        if url == osv.OSV_QUERYBATCH_URL:
            calls["batch"] += 1
            assert len(payload["queries"]) <= osv.QUERYBATCH_MAX
            return {
                "results": [
                    {"vulns": [{"id": "GHSA-last"}]} if q["package"]["name"] == "p1199" else {}
                    for q in payload["queries"]
                ]
            }
        if url.startswith(osv.OSV_VULN_URL):
            calls["detail"] += 1
            return vuln
        calls["query"] += 1
        return {"vulns": []}

    findings = scan_sca(str(tmp_path), "e", online=True, fetch=fetch, enrich=False)
    assert [f.title.split(":")[1].split()[0] for f in findings] == ["p1199"]  # beyond the old 400 cap
    assert calls == {"batch": 2, "detail": 1, "query": 0}
    assert sca_scanner.last_scan_notes == []
    scan_sca(str(tmp_path), "e", online=True, fetch=fetch, enrich=False, max_packages=10)
    assert any("cap" in n for n in sca_scanner.last_scan_notes)


# ------------------------------------------------------------------------------------ D22
def test_sarif_has_no_zero_line_region_or_pseudo_uri(tmp_path):
    (tmp_path / "package-lock.json").write_text(
        '{"lockfileVersion":3,"packages":{"":{},"node_modules/x":{"version":"1.0.0"}}}'
    )
    v = _vuln("GHSA-x", "npm", "x", [{"introduced": "0"}, {"fixed": "1.0.1"}])
    f = scan_sca(str(tmp_path), "e", online=True, fetch=_fetch_for({("npm", "x"): [v]}), enrich=False)[0]
    f.affected_code.start_line = f.affected_code.end_line = 0
    res = f.to_sarif_result()
    uris = [
        loc["physicalLocation"]["artifactLocation"]["uri"]
        for loc in res["locations"]
        if "physicalLocation" in loc
    ]
    assert uris == ["package-lock.json"]
    assert all("region" not in loc.get("physicalLocation", {}) for loc in res["locations"])
    assert res["locations"][0]["logicalLocations"][0]["fullyQualifiedName"] == "npm:x"
    assert res["properties"]["package"] == {"ecosystem": "npm", "name": "x"}
