"""Business-logic scanner: economic tampering (confirmed) + workflow step-skip (firm indicator).

All against a MOCK runner (no live server). The FakeRunner returns a fake ProbeOutcome keyed on
path + query params, mirroring the real ProbeRunner.get/.post surface and the real
ApplicationModel/Endpoint shape (``.path``/``.method``/``.parameters`` = list of {name,in,type}).
"""
import json

from rampart.bizlogic import (
    bizlogic_scan,
    economic_tampering_scan,
    workflow_skip_scan,
)
from rampart.runner import ProbeOutcome
from rampart.schemas.appmodel import ApplicationModel, Endpoint
from rampart.schemas.finding import State

TARGET = "http://demo.local"


# --------------------------------------------------------------------------- fakes
class _FakeResponse:
    def __init__(self, status, body, headers=None):
        self.status = status
        self.body = body
        self.headers = headers or {}


class FakeRunner:
    """Mimics rampart.runner.ProbeRunner.get/.post, dispatching to a handler(path, query, session)."""

    def __init__(self, handler, engagement_id="eng_test"):
        self._handler = handler
        self.engagement_id = engagement_id
        self.calls = []

    def get(self, path, session=None, payload_class="boundary-probe", rationale="",
            hypothesis_id=None, capture=True, summary="", query=None, headers=None):
        q = dict(query or {})
        self.calls.append(("GET", path, q))
        status, body = self._handler(path, q, session)
        return ProbeOutcome(executed=True, response=_FakeResponse(status, body))

    def post(self, path, json_body, session=None, payload_class="canary", rationale="",
             hypothesis_id=None, capture=True, summary="", headers=None, content_type=None):
        self.calls.append(("POST", path, json_body))
        status, body = self._handler(path, {}, session)
        return ProbeOutcome(executed=True, response=_FakeResponse(status, body))


def _appmodel(*endpoints):
    return ApplicationModel(engagement_id="eng_test", endpoints=list(endpoints))


def _checkout_ep():
    return Endpoint(
        id="ep_checkout", method="GET", path="/api/checkout",
        parameters=[{"name": "item", "in": "query", "type": "string"},
                    {"name": "qty", "in": "query", "type": "integer"}])


def _confirm_ep():
    return Endpoint(id="ep_confirm", method="GET", path="/api/checkout/confirm", parameters=[])


# --------------------------------------------------------------------------- handlers
def _vuln_checkout(path, query, session):
    """Vulnerable: trusts client qty; total = 9.99 * qty (so -1 -> -9.99, 0 -> 0, 2 -> 19.98)."""
    if path == "/api/checkout":
        try:
            q = float(query.get("qty"))
        except (TypeError, ValueError):
            q = 1.0
        total = round(9.99 * q, 2)
        return 200, json.dumps({"item": query.get("item", "x"), "qty": query.get("qty"), "total": total})
    return 404, json.dumps({"error": "not found"})


def _safe_checkout(path, query, session):
    """Safe: rejects non-positive quantities with 400; otherwise a correct positive total."""
    if path == "/api/checkout":
        try:
            q = float(query.get("qty"))
        except (TypeError, ValueError):
            q = 1.0
        if q <= 0:
            return 400, json.dumps({"error": "quantity must be positive"})
        return 200, json.dumps({"total": round(9.99 * q, 2)})
    return 404, json.dumps({"error": "not found"})


def _workflow_vuln(path, query, session):
    """Vulnerable: /api/checkout/confirm fulfils with no session; everything else 404s."""
    if path == "/api/checkout/confirm" and not session:
        return 200, json.dumps({"status": "confirmed", "order": 123})
    return 404, json.dumps({"error": "not found"})


def _combined_vuln(path, query, session):
    if path == "/api/checkout/confirm":
        return (200, json.dumps({"status": "confirmed", "order": 123})) if not session \
            else (403, json.dumps({"error": "forbidden"}))
    return _vuln_checkout(path, query, session)


# --------------------------------------------------------------------------- economic
def test_economic_vulnerable_confirms_once():
    runner = FakeRunner(_vuln_checkout)
    findings = economic_tampering_scan(runner, _appmodel(_checkout_ep()), TARGET)
    econ = [f for f in findings if f.vuln_class == "BUSINESS_LOGIC_ECONOMIC"]
    assert len(econ) == 1, f"expected exactly one confirmed economic finding, got {len(econ)}"
    f = econ[0]
    assert f.confidence == "confirmed"
    assert f.verification.validated is True
    assert f.state == State.VALIDATED
    assert f.verification.reproductions >= 2
    assert f.severity == "high"
    assert "CWE-840" in f.cwe and "CWE-20" in f.cwe
    assert f.dedupe_key == "bizlogic:econ:/api/checkout:qty"
    assert "qty" in str(f.endpoint.get("parameters"))
    f.assert_consistent()


def test_economic_safe_server_yields_nothing():
    runner = FakeRunner(_safe_checkout)
    findings = economic_tampering_scan(runner, _appmodel(_checkout_ep()), TARGET)
    assert findings == [], "a server that rejects abusive quantities must yield no finding"


def test_economic_requires_two_reproductions():
    runner = FakeRunner(_vuln_checkout)
    f = economic_tampering_scan(runner, _appmodel(_checkout_ep()), TARGET)[0]
    # probe + control calls recorded; the broken total reproduced from clean requests.
    assert f.verification.reproductions >= 2
    assert any("control" in c.lower() for c in f.verification.false_positive_checks)


# --------------------------------------------------------------------------- workflow
def test_workflow_direct_fulfilment_is_flagged():
    runner = FakeRunner(_workflow_vuln)
    findings = workflow_skip_scan(runner, _appmodel(_confirm_ep()), TARGET)
    wf = [f for f in findings if f.vuln_class == "BUSINESS_LOGIC_WORKFLOW"]
    assert len(wf) == 1, "the unauthenticated late-stage fulfilment must be flagged"
    f = wf[0]
    # Conservative oracle: this implementation emits a FIRM indicator (never confirmed).
    assert f.confidence == "firm"
    assert f.verification.validated is False
    assert f.state == State.EVIDENCE_FOUND
    assert "CWE-841" in f.cwe
    assert f.verification.reproductions >= 2
    assert "needs-human-review" in f.tags
    f.assert_consistent()


def test_workflow_blanket_200_is_not_flagged():
    # A server that returns the fulfilment signal for EVERYTHING (incl. the non-existent control)
    # must be dropped as a false positive.
    def blanket(path, query, session):
        return 200, json.dumps({"status": "confirmed"})
    runner = FakeRunner(blanket)
    findings = workflow_skip_scan(runner, _appmodel(_confirm_ep()), TARGET)
    assert findings == [], "blanket-200 servers must not produce a workflow finding"


# --------------------------------------------------------------------------- combined
def test_bizlogic_scan_combines_both_and_is_consistent():
    runner = FakeRunner(_combined_vuln)
    model = _appmodel(_checkout_ep(), _confirm_ep())
    findings = bizlogic_scan(runner, model, TARGET)
    classes = {f.vuln_class for f in findings}
    assert "BUSINESS_LOGIC_ECONOMIC" in classes
    assert "BUSINESS_LOGIC_WORKFLOW" in classes
    for f in findings:
        f.assert_consistent()
