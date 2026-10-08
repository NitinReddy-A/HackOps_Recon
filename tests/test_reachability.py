"""Call-graph reachability: tiers (function-reachable / reachable / dead / test-only / unused /
unreachable) and the exploit-intel priority effect."""
import os

import pytest

from rampart.sca.reachability import analyze_repo, reachability, tier_to_bool


def _mkrepo(tmp_path):
    app = tmp_path / "app"
    app.mkdir()
    (tmp_path / "tests").mkdir()
    (app / "main.py").write_text(
        "from flask import render_template\n"
        "import requests\n"
        "\n"
        "def render_page(x):\n"
        "    return render_template(x)\n"
        "\n"
        "def dead_func():\n"
        "    import unused_pkg\n"
        "    return unused_pkg.do()\n"
        "\n"
        "def main():\n"
        "    return render_page('home')\n"
        "\n"
        "if __name__ == '__main__':\n"
        "    main()\n")
    (tmp_path / "tests" / "test_x.py").write_text("import onlytestlib\nonlytestlib.foo()\n")
    return str(tmp_path)


def test_reachability_tiers(tmp_path):
    g = analyze_repo(_mkrepo(tmp_path))
    assert g is not None
    # flask is called on the live path main -> render_page -> render_template
    r_flask = reachability(g, ["flask"], ["flask.render_template"])
    assert r_flask["tier"] == "function-reachable"
    assert r_flask["vulnerable_symbol_reachable"] is True
    assert tier_to_bool("function-reachable") is True
    # requests: imported but never actually called
    assert reachability(g, ["requests"])["tier"] == "imported-unused"
    # unused_pkg: used only inside a function never reached from an entrypoint (dead code)
    assert reachability(g, ["unused_pkg"])["tier"] == "imported-not-on-live-path"
    # onlytestlib: used only in tests
    assert reachability(g, ["onlytestlib"])["tier"] == "test-only"
    # not present at all
    assert reachability(g, ["totallyabsent"])["tier"] == "unreachable"


def test_no_source_is_unknown(tmp_path):
    (tmp_path / "requirements.txt").write_text("flask==1.0\n")      # no .py source
    assert analyze_repo(str(tmp_path)) is None


def test_function_reachable_keeps_priority_high(tmp_path):
    """A vuln whose symbol is reachable must not be de-prioritised, even with a low base score."""
    from rampart.sca import scan_sca
    repo = _mkrepo(tmp_path)
    (tmp_path / "requirements.txt").write_text("Flask==0.12.2\n")

    def osv(url, payload, timeout=None):
        if payload["package"]["name"] == "flask":
            return {"vulns": [{"id": "G", "aliases": ["CVE-2099-1"], "summary": "x",
                "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N"}],
                "affected": [{"package": {"ecosystem": "PyPI", "name": "flask"},
                              "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "0.12.3"}]}],
                              "ecosystem_specific": {"imports": [{"path": "flask", "symbols": ["render_template"]}]}}]}]}
        return {"vulns": []}

    f = scan_sca(repo, "e", online=True, fetch=osv)[0]
    assert f.exploit_intel["reachability_tier"] == "function-reachable"
    assert f.exploit_intel["vulnerable_symbol_reachable"] is True
    assert "vuln-symbol-reachable" in f.tags
