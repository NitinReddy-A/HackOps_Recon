"""OOB collaborator + blind SSRF/XXE — out-of-band callback is deterministic proof."""

from conftest import make_engagement, write_engagement

from rampart.engagement import Engagement, EngagementConfig
from rampart.oob import OOBCollaborator


def _active_eng(tmp_path, port):
    scope = write_engagement(tmp_path, port)
    cfg = EngagementConfig(
        scope_file=scope,
        target=f"http://127.0.0.1:{port}",
        work_dir=str(tmp_path / ".rampart"),
        openapi=str(tmp_path / "openapi.json"),
        appmodel_seed=str(tmp_path / "seed.json"),
        application="demo-shop-api",
        active=True,
    )
    return Engagement(cfg)


def test_collaborator_records_hits():
    c = OOBCollaborator()
    c.start()
    try:
        import urllib.request

        tok, url = c.new_token()
        assert not c.received(tok)
        urllib.request.urlopen(url, timeout=2).read()
        assert c.wait_for(tok, timeout=2)
        other, _ = c.new_token()
        assert not c.wait_for(other, timeout=0.3)  # a token never hit stays clean
    finally:
        c.stop()


def test_blind_ssrf_confirmed_on_vuln_target(tmp_path, vuln_server):
    eng = make_engagement(tmp_path, vuln_server.port)
    findings = eng.run_oob()
    blind = [f for f in findings if "blind" in f.tags]
    assert blind, "blind SSRF should be confirmed out-of-band on the vulnerable target"
    f = blind[0]
    assert f.verification.validated and f.confidence == "confirmed"
    assert f.verification.method == "out-of-band-collaborator"
    assert "/api/webhook" in f.endpoint["url"]
    f.assert_consistent()


def test_blind_ssrf_clean_on_fixed_target(tmp_path, fixed_server):
    eng = make_engagement(tmp_path, fixed_server.port)
    findings = eng.run_oob()
    assert not findings, "fixed target blocks internal fetch -> no OOB callback -> nothing confirmed"


def test_blind_xxe_confirmed_in_active_mode(tmp_path, vuln_server):
    findings = _active_eng(tmp_path, vuln_server.port).run_oob()
    xxe = [f for f in findings if f.vuln_class == "XXE"]
    assert xxe, "blind XXE should be confirmed out-of-band on /api/import in --active mode"
    f = xxe[0]
    assert f.verification.validated and f.verification.method == "out-of-band-collaborator"
    assert "/api/import" in f.endpoint["url"]
    f.assert_consistent()


def test_blind_xxe_clean_on_fixed(tmp_path, fixed_server):
    findings = _active_eng(tmp_path, fixed_server.port).run_oob()
    assert not [f for f in findings if f.vuln_class == "XXE"]


# --------------------------------------------------------------------- C-15 collaborator host
class _NoCallRunner:
    def get(self, *a, **k):
        raise AssertionError("nothing may be injected when the collaborator is unreachable")

    post = get


class _OneParamModel:
    class _Ep:
        method = "GET"
        path = "/fetch"
        parameters = [{"in": "query", "name": "url"}]

    endpoints = [_Ep()]


def test_loopback_collaborator_skips_remote_target_with_reason():
    from rampart.oob import blind_ssrf_scan, blind_xxe_scan, oob_skip_reason

    c = OOBCollaborator()  # default: loopback bind + advertise (safe)
    assert c.is_loopback
    out = blind_ssrf_scan(_NoCallRunner(), c, _OneParamModel(), "https://app.example.com")
    assert out == [] and "not loopback" in out.skip_reason
    out = blind_xxe_scan(_NoCallRunner(), c, _OneParamModel(), "https://app.example.com")
    assert out == [] and out.skip_reason
    assert oob_skip_reason("http://127.0.0.1:8080", c) == ""
    assert oob_skip_reason("http://localhost:8080", c) == ""


def test_external_collaborator_url_is_advertised():
    from rampart.oob import oob_skip_reason

    c = OOBCollaborator(host="0.0.0.0", port=0, public_url="http://oob.example.net:8000/")
    assert c.base_url == "http://oob.example.net:8000"
    assert not c.is_loopback
    assert oob_skip_reason("https://app.example.com", c) == ""
    c.port = 1234
    tok, url = c.new_token()
    assert url == f"http://oob.example.net:8000/{tok}"
