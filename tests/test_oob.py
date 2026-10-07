"""OOB collaborator + blind SSRF — out-of-band callback is deterministic proof."""
from conftest import make_engagement
from rampart.oob import OOBCollaborator


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
        assert not c.wait_for(other, timeout=0.3)   # a token never hit stays clean
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
