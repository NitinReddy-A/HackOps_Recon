"""The sensitive-file check must not fire on a soft-404 / catch-all page that echoes a content
signature for every path. A non-existent sibling path is used as a negative control: if it also
returns the signature, the "match" is not a real exposed file and must be dropped.
"""

from types import SimpleNamespace

from rampart.scanners import sensitive_files_check


class _FakeRunner:
    """Returns a canned (status, body) per requested path via a responder callable."""

    engagement_id = "TEST-0001"

    def __init__(self, responder):
        self._responder = responder
        self.paths = []

    def get(self, path, session=None, payload_class="", rationale="", summary=""):
        self.paths.append(path)
        status, body = self._responder(path)
        return SimpleNamespace(executed=True, status=status, body=body, evidence=[])


def test_real_exposure_is_confirmed_when_control_is_clean():
    def responder(path):
        if path == "/.env":
            return 200, "DB_PASSWORD=s3cr3t\nAPI_KEY=abc"
        return 404, "not found"  # the soft-404 control path 404s -> clean

    runner = _FakeRunner(responder)
    findings = sensitive_files_check(runner, "http://127.0.0.1:9", "demo")
    assert [f.vuln_class for f in findings] == ["sensitive-file-exposure"]
    assert findings[0].endpoint.get("url", "").endswith("/.env")
    # a control request to a non-existent sibling was made
    assert any("rampart-absent-" in p for p in runner.paths)


def test_soft_404_catch_all_is_dropped():
    # A catch-all that returns 200 with a password-ish marketing page for EVERY path would
    # otherwise false-positive /.env, /config.json, etc. The negative control catches it.
    def responder(_path):
        return 200, "<html>Page not found. Forgot your PASSWORD? Reset it here.</html>"

    runner = _FakeRunner(responder)
    findings = sensitive_files_check(runner, "http://127.0.0.1:9", "demo")
    assert findings == [], f"soft-404 catch-all must be dropped, got {[f.title for f in findings]}"
