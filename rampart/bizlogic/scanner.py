"""Deterministic business-logic scanner (economic tampering + workflow step-skip).

Business-logic flaws are the class a competitor's LLM agents "reason" about. We cannot reason
like an LLM here, but the classic, high-value logic bugs are *decidable with an oracle*: a
server that accepts an abusive economic value (negative/zero quantity or price) and returns a
logically-broken total has a confirmable defect — no judgement required. This module applies
the same probe / negative-control / 2+-reproduction discipline as the web oracles
(``rampart/validation/web_oracles.py``) so an economic-tampering finding can honestly carry
``confidence=confirmed``.

Two detectors:

* :func:`economic_tampering_scan` — **confirmed** (fail-closed). The server must ACCEPT the
  abusive value (200) AND return a non-positive computed total, while a valid-quantity negative
  control returns 200 with a positive total. A reject (400/422) or a clamp (total stays
  positive) drops the candidate.
* :func:`workflow_skip_scan` — **firm indicator only** (``validated=False``). A direct hit on a
  late-stage endpoint is a strong signal but cannot be *proven* without a stateful multi-step
  oracle (the endpoint may be legitimately public/idempotent), so — honouring the trust
  primitive — it is never promoted to ``confirmed``. A blanket-200 negative control guards the
  most common false positive.

All requests go through the provided :class:`~rampart.runner.ProbeRunner`; nothing opens a raw
socket, and every probe is an unauthenticated Tier-1 GET (no state is written).
"""

from __future__ import annotations

import re

from ..schemas.finding import CVSS, Finding, Remediation, Reproduction, State, Verification
from ..util import now_iso

# ---------------------------------------------------------------------------- economic
# Quantity-style parameters: a negative/zero quantity is abusive.
_QUANTITY_PARAMS = {"qty", "quantity", "count", "qnty", "num", "units"}
# Price/money-style parameters: a zero/negative amount is abusive.
_PRICE_PARAMS = {"amount", "price", "cost", "total"}
_ECONOMIC_PARAMS = _QUANTITY_PARAMS | _PRICE_PARAMS

# A valid, unambiguously-positive quantity used as the negative control.
_CONTROL_VALUE = "2"
# The economic result keys we parse out of a JSON-ish response body (first match wins). Only an
# UNQUOTED number is matched, so a reflected input like "qty":"-1" is ignored — we want the
# server's *computed* figure.
_RESULT_KEY = re.compile(
    r'(?i)"(total|grand_total|subtotal|order_total|amount_due|amount|price|cost|sum|charge)"'
    r"\s*:\s*(-?\d+(?:\.\d+)?)"
)

_ECON_CVSS = CVSS(
    version="4.0",
    base_score=7.5,
    severity="high",
    vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N",
    v31_fallback={"base_score": 7.5, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N"},
)


def _query_params(ep) -> list:
    """Query-string parameter dicts on an endpoint (tolerant of a missing ``in``)."""
    out = []
    for p in getattr(ep, "parameters", None) or []:
        if not isinstance(p, dict):
            continue
        if (p.get("in") or "query") == "query" and p.get("name"):
            out.append(p)
    return out


def _parse_economic_number(body: str):
    """Return the server's first computed economic figure in ``body`` as a float, or ``None``."""
    if not body:
        return None
    m = _RESULT_KEY.search(body)
    if not m:
        return None
    try:
        return float(m.group(2))
    except (TypeError, ValueError):
        return None


def _build_query(ep, target_param: str, value) -> dict:
    """Query dict that varies ``target_param`` and fills every other query param with a benign 1."""
    q = {}
    for p in _query_params(ep):
        name = p["name"]
        q[name] = str(value) if name == target_param else "1"
    return q


def _abusive_values(param: str) -> list:
    """Abusive economic values to try, ordered by the most telling for the parameter kind."""
    low = param.lower()
    if low in _QUANTITY_PARAMS:
        return [-1, 0]  # negative then zero quantity
    return [0, -1]  # price/amount: zero (free) then negative


def economic_tampering_scan(
    runner, appmodel, target_url, application="target", engagement_id="", reproductions: int = 2
) -> list[Finding]:
    """Confirm economic/parameter-tampering flaws on endpoints carrying money/quantity params.

    Oracle (fail-closed): the server ACCEPTS an abusive value (status 200) AND the response
    carries a non-positive computed total, while a valid-quantity negative control returns 200
    with a POSITIVE total, and the broken result reproduces ``reproductions`` times. Anything
    less decisive (reject, clamp, missing total, flaky control) is dropped.
    """
    findings: list[Finding] = []
    eng = engagement_id or getattr(runner, "engagement_id", "")
    for ep in getattr(appmodel, "endpoints", []) or []:
        if (getattr(ep, "method", None) or "GET").upper() != "GET":
            continue
        path = getattr(ep, "path", "")
        econ_params = [p["name"] for p in _query_params(ep) if p["name"].lower() in _ECONOMIC_PARAMS]
        if not path or not econ_params:
            continue

        # One negative control per endpoint: a valid quantity must give a correct positive total.
        control = runner.get(
            path,
            session=None,
            query=_build_query(ep, econ_params[0], _CONTROL_VALUE),
            payload_class="boundary-probe",
            rationale="negative control: a valid positive quantity must yield a positive total",
            summary=f"econ control {path}",
        )
        control_total = _parse_economic_number(control.body) if control.executed else None
        control_ok = bool(
            control.executed and control.status == 200 and control_total is not None and control_total > 0
        )
        if not control_ok:
            # Without a correct baseline we cannot judge the probe — fail closed.
            continue

        for param in econ_params:
            confirmed_val = None
            for val in _abusive_values(param):
                probe = runner.get(
                    path,
                    session=None,
                    query=_build_query(ep, param, val),
                    payload_class="boundary-probe",
                    rationale=f"economic tampering: set '{param}'={val} (abusive)",
                    summary=f"econ probe {path} {param}={val}",
                )
                if not probe.executed or probe.status != 200:
                    continue  # rejected -> safe server for this value
                total = _parse_economic_number(probe.body)
                if total is None or total > 0:
                    continue  # clamped / no broken total -> safe
                # Decisive so far: re-derive from clean requests.
                repro_ok = 0
                for _ in range(reproductions):
                    r = runner.get(
                        path,
                        session=None,
                        query=_build_query(ep, param, val),
                        payload_class="boundary-probe",
                        rationale="reproduction of accepted abusive economic value",
                        summary=f"econ repro {path} {param}={val}",
                    )
                    rt = _parse_economic_number(r.body) if r.executed else None
                    if r.executed and r.status == 200 and rt is not None and rt <= 0:
                        repro_ok += 1
                if repro_ok >= reproductions:
                    confirmed_val = (val, total, repro_ok)
                    break
            if confirmed_val is None:
                continue
            val, total, repro_ok = confirmed_val
            findings.append(
                _economic_finding(
                    eng, application, target_url, path, param, val, total, control_total, repro_ok
                )
            )
    return findings


def _economic_finding(
    engagement_id, application, target_url, path, param, abusive_value, broken_total, control_total, repro_ok
) -> Finding:
    f = Finding(
        engagement_id=engagement_id,
        title=f"Business-logic economic tampering via '{param}' on GET {path}",
        vuln_class="BUSINESS_LOGIC_ECONOMIC",
        severity="high",
        confidence="confirmed",
        state=State.VALIDATED,
        cwe=["CWE-840", "CWE-20"],
        owasp={
            "api_2023": ["API6:2023-Unrestricted Access to Sensitive Business Flows"],
            "web_2021": ["A04:2021-Insecure Design"],
        },
        cvss=_ECON_CVSS,
        asset={"type": "web", "application": application, "environment": "authorized", "target": target_url},
        endpoint={
            "method": "GET",
            "url": f"{target_url}{path}",
            "auth_required": False,
            "parameters": [{"name": param, "in": "query", "abused_value": abusive_value}],
        },
        description=(
            f"The '{param}' parameter on GET {path} accepts the abusive value "
            f"{abusive_value}: the server returns 200 and a non-positive computed total "
            f"({broken_total}), whereas a valid quantity yields a positive total "
            f"({control_total}). The client-supplied economic value is trusted without "
            "server-side bounds checking."
        ),
        impact=(
            "An attacker can place free or negative-cost orders (e.g. a negative quantity "
            "credits the account), causing direct revenue loss and corrupting financial "
            "records / inventory."
        ),
        root_cause="Server trusts client-supplied economic values without server-side validation/bounds.",
        reproduction=Reproduction(
            prerequisites=["None (unauthenticated GET)"],
            steps=[
                f"GET {path} with '{param}'={abusive_value} -> 200 with total {broken_total}",
                f"GET {path} with '{param}'={_CONTROL_VALUE} (control) -> 200 with positive total {control_total}",
                f"Repeat the abusive request; the non-positive total reproduces ({repro_ok}x)",
            ],
            deterministic=True,
        ),
        remediation=Remediation(
            summary="Validate and bound economic inputs server-side; recompute price on the server.",
            type="code_patch",
            guidance=(
                "Reject non-positive quantities/amounts (400) before processing, clamp to "
                "sane bounds, and recompute the authoritative price/total on the server from "
                "trusted catalogue data rather than from client-supplied figures (CWE-840/CWE-20)."
            ),
            effort="medium",
        ),
        references=[
            "https://cwe.mitre.org/data/definitions/840.html",
            "https://cwe.mitre.org/data/definitions/20.html",
            "https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/",
        ],
        compliance_control_refs=["SOC2:CC6.1"],
        dedupe_key=f"bizlogic:econ:{path}:{param}",
        tags=["business-logic", "economic", "parameter-tampering"],
        verification=Verification(
            method="economic-boundary-replay",
            validated=True,
            validated_at=now_iso(),
            validator="bizlogic-oracle",
            independent_reproduction=True,
            reproductions=repro_ok,
            false_positive_checks=[
                f"negative control '{param}'={_CONTROL_VALUE} returned 200 with a positive total "
                f"({control_total}) — the endpoint works correctly for valid input",
                f"abusive '{param}'={abusive_value} was ACCEPTED (200), not rejected or clamped",
                f"non-positive total ({broken_total}) reproduced {repro_ok}x from clean requests",
            ],
            confidence_score=0.9,
        ),
    )
    f.assert_consistent()
    return f


# ---------------------------------------------------------------------------- workflow
# Path keywords that denote a late/fulfilment workflow stage.
_LATE_STAGE_KEYWORDS = (
    "confirm",
    "complete",
    "finalize",
    "finalise",
    "checkout",
    "download",
    "invoice",
    "receipt",
    "approve",
)
# Body tokens that indicate a protected action was actually fulfilled.
_FULFILMENT_SIGNALS = (
    "confirmed",
    "completed",
    "complete",
    "finalized",
    "finalised",
    "receipt",
    "invoice",
    "fulfilled",
    "approved",
    "paid",
    "success",
)
# A deterministic, certainly-non-existent sibling path — used as a blanket-200 negative control.
_WF_CONTROL_SEGMENT = "rampart-nonexistent-precondition-probe"


def _looks_fulfilled(outcome) -> bool:
    body = (outcome.body or "").lower()
    return outcome.executed and outcome.status == 200 and any(s in body for s in _FULFILMENT_SIGNALS)


def workflow_skip_scan(
    runner, appmodel, target_url, application="target", engagement_id="", reproductions: int = 2
) -> list[Finding]:
    """Flag late-stage endpoints that fulfil a protected action with no prior workflow state.

    Conservative by design: this is emitted as a **firm indicator** (``validated=False``), never
    ``confirmed`` — a stateless probe cannot prove the prerequisite was genuinely skippable. A
    blanket-200 negative control (a certainly-non-existent sibling must NOT look fulfilled) guards
    the commonest false positive; without it, or without a reproducible fulfilment signal, the
    candidate is dropped.
    """
    findings: list[Finding] = []
    eng = engagement_id or getattr(runner, "engagement_id", "")
    seen_paths = set()
    for ep in getattr(appmodel, "endpoints", []) or []:
        if (getattr(ep, "method", None) or "GET").upper() != "GET":
            continue
        path = getattr(ep, "path", "")
        if not path or path in seen_paths:
            continue
        if not any(k in path.lower() for k in _LATE_STAGE_KEYWORDS):
            continue
        seen_paths.add(path)

        probe = runner.get(
            path,
            session=None,
            payload_class="boundary-probe",
            rationale="workflow step-skip: call a late-stage endpoint with no prior state/session",
            summary=f"workflow probe {path}",
        )
        if not _looks_fulfilled(probe):
            continue
        # Negative control: a certainly-non-existent sibling must not also look fulfilled,
        # otherwise the server blanket-200s everything and the signal is meaningless.
        control_path = path.rstrip("/") + "/" + _WF_CONTROL_SEGMENT
        control = runner.get(
            control_path,
            session=None,
            payload_class="benign-read",
            rationale="negative control: a non-existent sibling must not look fulfilled",
            summary=f"workflow control {path}",
        )
        if _looks_fulfilled(control):
            continue
        repro_ok = 0
        for _ in range(reproductions):
            r = runner.get(
                path,
                session=None,
                payload_class="boundary-probe",
                rationale="reproduction of unauthenticated fulfilment",
                summary=f"workflow repro {path}",
            )
            if _looks_fulfilled(r):
                repro_ok += 1
        if repro_ok < reproductions:
            continue
        findings.append(_workflow_finding(eng, application, target_url, path, probe, control, repro_ok))
    return findings


def _workflow_finding(engagement_id, application, target_url, path, probe, control, repro_ok) -> Finding:
    f = Finding(
        engagement_id=engagement_id,
        title=f"Possible workflow step-skip: late-stage GET {path} fulfilled with no precondition",
        vuln_class="BUSINESS_LOGIC_WORKFLOW",
        severity="medium",
        confidence="firm",
        state=State.EVIDENCE_FOUND,
        cwe=["CWE-841"],
        owasp={"web_2021": ["A04:2021-Insecure Design"]},
        asset={"type": "web", "application": application, "environment": "authorized", "target": target_url},
        endpoint={"method": "GET", "url": f"{target_url}{path}", "auth_required": False, "parameters": []},
        description=(
            f"GET {path} is a late-stage/fulfilment endpoint yet returns 200 with a "
            f"fulfilment signal when called directly with no prior workflow state or "
            f"session (status {probe.status}). A correctly-sequenced workflow would "
            "require the preceding step (redirect/401/403/409). A non-existent sibling "
            f"control returned status {control.status} (not fulfilled), so the server is "
            "not simply returning 200 for everything."
        ),
        impact=(
            "If the preceding step (payment, authorization, eligibility) is genuinely "
            "bypassable, an attacker could obtain the fulfilled outcome (completed order, "
            "invoice, download) without satisfying it. Requires stateful/manual confirmation."
        ),
        root_cause="Improper enforcement of behavioral workflow: a later stage does not verify that "
        "its prerequisite stage was completed.",
        reproduction=Reproduction(
            prerequisites=["None (unauthenticated GET, no prior workflow steps)"],
            steps=[
                f"GET {path} directly with no session -> {probe.status} with a fulfilment signal",
                f"GET {path}/{_WF_CONTROL_SEGMENT} (non-existent control) -> {control.status} (not fulfilled)",
                f"Repeat the direct call; fulfilment reproduces ({repro_ok}x)",
                "MANUAL: confirm statefully that the prerequisite step is actually skippable",
            ],
            deterministic=False,
        ),
        remediation=Remediation(
            summary="Enforce workflow preconditions server-side before fulfilling a late-stage action.",
            type="code_patch",
            guidance=(
                "Gate each late-stage action on verified server-side state proving the prior "
                "step(s) completed (e.g. a signed/stored workflow token or a state machine), "
                "and reject out-of-order requests with 409/403 (CWE-841)."
            ),
            effort="medium",
        ),
        references=[
            "https://cwe.mitre.org/data/definitions/841.html",
            "https://owasp.org/Top10/A04_2021-Insecure_Design/",
        ],
        compliance_control_refs=["SOC2:CC6.1"],
        dedupe_key=f"bizlogic:workflow:{path}",
        tags=["business-logic", "workflow", "step-skip", "needs-human-review"],
        verification=Verification(
            method="workflow-precondition-probe",
            validated=False,
            validated_at=now_iso(),
            validator="bizlogic-workflow-detector",
            independent_reproduction=True,
            reproductions=repro_ok,
            false_positive_checks=[
                "INDICATOR ONLY — a stateless probe cannot prove the prerequisite was genuinely "
                "required; the endpoint may be legitimately public, idempotent, or a template. "
                "Confirm statefully (complete the real flow, then try to skip a step).",
                f"blanket-200 guard: non-existent sibling control returned {control.status} (not fulfilled)",
                f"fulfilment signal reproduced {repro_ok}x from clean requests",
            ],
            confidence_score=0.5,
        ),
    )
    f.assert_consistent()
    return f


# ---------------------------------------------------------------------------- entry point
def bizlogic_scan(runner, appmodel, target_url, application="target", engagement_id="") -> list[Finding]:
    """Run both business-logic detectors and return their combined findings."""
    return economic_tampering_scan(
        runner, appmodel, target_url, application, engagement_id
    ) + workflow_skip_scan(runner, appmodel, target_url, application, engagement_id)
