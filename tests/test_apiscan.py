"""Unit tests for the self-contained API-depth scanner (rampart.apiscan).

These drive the scanner with a MOCK runner (no live server): a tiny FakeRunner returns a fake
ProbeOutcome (.executed/.status/.body) chosen from the (method, path, headers/body) of each
call, so we can simulate a verb-tampering bypass, a properly-secured endpoint, and GraphQL
field-suggestion / batching behaviour deterministically.

The fake endpoints mirror rampart.schemas.appmodel.Endpoint (.method/.path/.parameters/
.auth_required), so the scanner works unchanged against the real application model.
"""

from dataclasses import dataclass, field

from rampart.apiscan import api_scan, graphql_depth_scan, method_tampering_scan
from rampart.schemas.finding import State


# --------------------------------------------------------------------------- fakes
@dataclass
class FakeOutcome:
    executed: bool
    status: int
    body: str = ""


@dataclass
class FakeEndpoint:
    """Mirrors rampart.schemas.appmodel.Endpoint's relevant fields."""

    method: str
    path: str
    parameters: list = field(default_factory=list)
    auth_required: bool = False


class FakeAppModel:
    def __init__(self, endpoints):
        self.endpoints = endpoints


_ADMIN_BODY = (
    '{"section":"admin-dashboard","users":[{"username":"root","is_admin":true,"email":"root@corp"}]}'
)


class FakeRunner:
    """Simulates a server purely from (method, path, headers/body) — no sockets/urllib."""

    engagement_id = "eng-apiscan-test"

    def __init__(self, admin_bypass=True):
        self.admin_bypass = admin_bypass
        self.calls = []

    def get(self, path, session=None, headers=None, **kw):
        headers = headers or {}
        override = headers.get("X-HTTP-Method-Override")
        self.calls.append(("GET", path, override, session))
        if path == "/api/admin":
            # canonical GET is denied unauth; a mis-configured server serves admin data when the
            # method is tampered via the override header (verb-based authz bypass).
            if override and self.admin_bypass:
                return FakeOutcome(True, 200, _ADMIN_BODY)
            return FakeOutcome(True, 403, "Forbidden")
        if path == "/api/secure":
            return FakeOutcome(True, 403, "Forbidden")  # always protected, no bypass
        return FakeOutcome(True, 404, "Not Found")

    def post(self, path, json_body=None, session=None, headers=None, **kw):
        self.calls.append(("POST", path, json_body, session))
        if "graphql" in path.lower():
            return self._graphql(path, json_body)
        return FakeOutcome(True, 403, "Forbidden")

    def _graphql(self, path, body):
        secure = "secure" in path.lower()
        if isinstance(body, list):  # array batching
            if secure:
                return FakeOutcome(True, 400, '{"errors":[{"message":"Batching is not allowed."}]}')
            return FakeOutcome(True, 200, '{"data":[{"__typename":"Query"},{"__typename":"Query"}]}')
        q = str((body or {}).get("query", ""))
        if "uesr" in q:  # misspelled field
            if secure:
                return FakeOutcome(True, 200, '{"errors":[{"message":"Cannot query field \\"uesr\\"."}]}')
            return FakeOutcome(
                True,
                200,
                '{"errors":[{"message":"Cannot query field \\"uesr\\" on type '
                '\\"Query\\". Did you mean \\"user\\"?"}]}',
            )
        if q.count(":") >= 2:  # multi-alias amplification
            if secure:
                return FakeOutcome(True, 400, '{"errors":[{"message":"Too many aliases."}]}')
            return FakeOutcome(True, 200, '{"data":{"a0":"Query","a1":"Query"}}')
        return FakeOutcome(True, 200, '{"data":{"__typename":"Query"}}')


def _admin_model():
    return FakeAppModel(
        [
            FakeEndpoint("GET", "/api/admin", auth_required=True),
            FakeEndpoint("GET", "/api/secure", auth_required=True),
        ]
    )


def _gql_model(path="/graphql"):
    return FakeAppModel([FakeEndpoint("POST", path, auth_required=False)])


# --------------------------------------------------------------- (a) confirmed verb bypass
def test_method_tampering_confirms_verb_bypass():
    runner = FakeRunner(admin_bypass=True)
    findings = method_tampering_scan(runner, _admin_model(), "http://t", "demo")
    mt = [f for f in findings if f.vuln_class == "HTTP_METHOD_TAMPERING"]
    assert len(mt) == 1, "exactly the /api/admin bypass should be confirmed"
    f = mt[0]
    assert f.confidence == "confirmed"
    assert f.verification.validated is True
    assert f.state == State.VALIDATED
    assert f.severity == "high"
    assert f.verification.method == "method-override-replay"
    assert f.verification.independent_reproduction is True
    assert f.verification.reproductions >= 2
    assert "CWE-650" in f.cwe and "CWE-285" in f.cwe
    assert f.owasp.get("api_2023") == ["API5:2023-BFLA"]
    assert "/api/admin" in f.endpoint["url"]
    # the negative control (canonical 403) is recorded among the false-positive checks
    assert any("403" in c for c in f.verification.false_positive_checks)
    # NON-DESTRUCTIVE by default: nothing but safe GET transport was issued
    assert all(c[0] == "GET" for c in runner.calls), "default run must issue no POST/write"
    f.assert_consistent()


# --------------------------------------------------------------- (b) secured -> no finding
def test_method_tampering_secure_endpoint_no_finding():
    runner = FakeRunner(admin_bypass=False)  # override never flips the decision
    findings = method_tampering_scan(runner, _admin_model(), "http://t", "demo")
    assert [f for f in findings if f.vuln_class == "HTTP_METHOD_TAMPERING"] == []


# --------------------------------------------------------------- (c) GraphQL field suggestion
def test_graphql_field_suggestion_is_firm():
    runner = FakeRunner()
    findings = graphql_depth_scan(runner, _gql_model(), "http://t", "demo")
    fs = [f for f in findings if f.vuln_class == "GRAPHQL_FIELD_SUGGESTION"]
    assert len(fs) == 1
    f = fs[0]
    assert f.confidence == "firm"
    assert f.verification.validated is False
    assert f.state == State.EVIDENCE_FOUND
    assert "CWE-200" in f.cwe
    f.assert_consistent()


# --------------------------------------------------------------- (d) GraphQL batching
def test_graphql_batching_is_firm():
    runner = FakeRunner()
    findings = graphql_depth_scan(runner, _gql_model(), "http://t", "demo")
    b = [f for f in findings if f.vuln_class == "GRAPHQL_BATCHING"]
    assert len(b) == 1
    f = b[0]
    assert f.confidence == "firm"
    assert f.verification.validated is False
    assert f.state == State.EVIDENCE_FOUND
    assert "CWE-770" in f.cwe
    f.assert_consistent()


# --------------------------------------------------------------- GraphQL secure -> nothing
def test_graphql_secure_endpoint_no_findings():
    runner = FakeRunner()
    findings = graphql_depth_scan(runner, _gql_model("/graphql/secure"), "http://t", "demo")
    assert findings == [], "a locked-down GraphQL endpoint yields no firm indicators"


# --------------------------------------------------------------- active gating is off by default
def test_active_mode_issues_gated_post_probes():
    # With no bypass, the safe GET family finds nothing, so the scanner proceeds to the gated
    # real-verb (POST-tunnelled) family — proving active=True is what unlocks the write transport.
    runner = FakeRunner(admin_bypass=False)
    findings = method_tampering_scan(runner, _admin_model(), "http://t", "demo", active=True)
    assert findings == []
    assert any(c[0] == "POST" and c[1] == "/api/admin" for c in runner.calls)


# --------------------------------------------------------------- api_scan combines both
def test_api_scan_combines_both_scanners():
    runner = FakeRunner(admin_bypass=True)
    model = FakeAppModel(
        [
            FakeEndpoint("GET", "/api/admin", auth_required=True),
            FakeEndpoint("GET", "/api/secure", auth_required=True),
            FakeEndpoint("POST", "/graphql", auth_required=False),
        ]
    )
    findings = api_scan(runner, model, "http://t", "demo")
    classes = sorted({f.vuln_class for f in findings})
    assert classes == ["GRAPHQL_BATCHING", "GRAPHQL_FIELD_SUGGESTION", "HTTP_METHOD_TAMPERING"]
    # default remains non-destructive: the only POSTs are the (safe) GraphQL queries
    assert all("graphql" in c[1].lower() for c in runner.calls if c[0] == "POST")
    for f in findings:
        f.assert_consistent()


# --------------------------------------------------------------- confirmed tier is honest
def test_only_method_tampering_is_confirmed_graphql_is_firm():
    runner = FakeRunner(admin_bypass=True)
    model = FakeAppModel(
        [
            FakeEndpoint("GET", "/api/admin", auth_required=True),
            FakeEndpoint("POST", "/graphql", auth_required=False),
        ]
    )
    findings = api_scan(runner, model, "http://t", "demo")
    confirmed = {f.vuln_class for f in findings if f.confidence == "confirmed"}
    firm = {f.vuln_class for f in findings if f.confidence == "firm"}
    assert confirmed == {"HTTP_METHOD_TAMPERING"}
    assert firm == {"GRAPHQL_FIELD_SUGGESTION", "GRAPHQL_BATCHING"}
    assert all(f.verification.validated for f in findings if f.confidence == "confirmed")
    assert all(not f.verification.validated for f in findings if f.confidence == "firm")
