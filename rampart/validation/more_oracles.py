"""Independent oracles for SSRF, command injection, and path traversal.

Same discipline as the other oracles: a probe signal is confirmed only against a benign
control and with 2+ reproductions. All probes are unauthenticated Tier-1 GETs with an inert
marker in the query string — nothing is actually fetched, executed, or read on the tester side.
"""
from __future__ import annotations

from .oracle import OracleVerdict
from .web_oracles import _collect

_CMD_MARKER = "RAMPARTCMDMARK42"
_SSRF_INTERNAL_URL = "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
_SSRF_SIGNATURE = "RAMPART-SSRF"
_TRAVERSAL_PAYLOAD = "../../../../../../etc/passwd"
_TRAVERSAL_SIGNATURE = "RAMPART-TRAVERSAL"


def _marker_oracle(runner, hyp, *, vuln_class, probe_value, control_value, signature,
                   reproductions):
    path, param = hyp["endpoint_path"], hyp["selector_param"]
    hid = hyp.get("id")
    probe = runner.get(path, session=None, query={param: probe_value}, payload_class="boundary-probe",
                       rationale=f"{vuln_class} probe", hypothesis_id=hid, summary=f"{vuln_class} probe")
    control = runner.get(path, session=None, query={param: control_value}, payload_class="boundary-probe",
                         rationale=f"{vuln_class} benign control", hypothesis_id=hid,
                         summary=f"{vuln_class} control")
    if not probe.executed or not control.executed:
        return OracleVerdict(False, vuln_class, reasons=["probe blocked by policy"],
                             evidence=_collect(probe, control))

    probe_hit = signature in (probe.body or "")
    control_hit = signature in (control.body or "")
    reasons, fp = [], []
    reasons.append(("PASS" if probe_hit else "FAIL")
                   + f": attack value produced the {vuln_class} signature in the response")
    reasons.append(("PASS" if not control_hit else "FAIL")
                   + ": benign control did NOT produce the signature")
    fp.append(f"probe signature present={probe_hit}; control signature present={control_hit}")
    decisive = probe_hit and not control_hit

    repro_ok = 0
    if decisive:
        for i in range(reproductions):
            r = runner.get(path, session=None, query={param: probe_value}, payload_class="boundary-probe",
                           rationale=f"reproduction #{i+1}", hypothesis_id=hid, summary=f"{vuln_class} repro {i+1}")
            if r.executed and signature in (r.body or ""):
                repro_ok += 1
        fp.append(f"reproduced {repro_ok}/{reproductions} times from clean requests")

    return OracleVerdict(
        validated=decisive and repro_ok >= reproductions, vuln_class=vuln_class,
        reasons=reasons, false_positive_checks=fp, reproductions=repro_ok,
        evidence=_collect(probe, control),
        controls={"probe_hit": probe_hit, "control_hit": control_hit})


def run_ssrf_oracle(runner, hyp, reproductions: int = 2) -> OracleVerdict:
    return _marker_oracle(runner, hyp, vuln_class="SSRF",
                          probe_value=_SSRF_INTERNAL_URL, control_value="https://example.com/",
                          signature=_SSRF_SIGNATURE, reproductions=reproductions)


def run_cmdi_oracle(runner, hyp, reproductions: int = 2) -> OracleVerdict:
    return _marker_oracle(runner, hyp, vuln_class="CMDI",
                          probe_value=f"127.0.0.1; echo {_CMD_MARKER}", control_value="127.0.0.1",
                          signature=_CMD_MARKER, reproductions=reproductions)


def run_traversal_oracle(runner, hyp, reproductions: int = 2) -> OracleVerdict:
    return _marker_oracle(runner, hyp, vuln_class="PATH_TRAVERSAL",
                          probe_value=_TRAVERSAL_PAYLOAD, control_value="readme.txt",
                          signature=_TRAVERSAL_SIGNATURE, reproductions=reproductions)


_BFLA_SIGNATURE = "RAMPART-BFLA"
import re as _re
_SENSITIVE_KEY = _re.compile(
    r'(?i)"(ssn|social_security|password|passwd|pwd|password_hash|secret|api[_-]?key|api[_-]?token|'
    r'access[_-]?token|private[_-]?key|credit[_-]?card|card[_-]?number|cvv|pan)"\s*:')


_HHI_CANARY = "rampart-hhi-canary.example"


def run_hostheader_oracle(runner, hyp, reproductions: int = 2) -> OracleVerdict:
    """Host-header injection: a crafted Host header is reflected into links/body (password-reset
    poisoning, cache poisoning). Deterministic: the attacker host appears for the crafted Host and
    not for the legitimate one. All over GET — no state change."""
    path = hyp["endpoint_path"]
    hid = hyp.get("id")
    probe = runner.get(path, session=None, headers={"Host": _HHI_CANARY}, payload_class="boundary-probe",
                       rationale="host-header injection probe", hypothesis_id=hid, summary="hhi probe")
    control = runner.get(path, session=None, payload_class="benign-read",
                         rationale="control: legitimate Host", hypothesis_id=hid, summary="hhi control")
    if not probe.executed or not control.executed:
        return OracleVerdict(False, "HOST_HEADER_INJECTION", reasons=["probe blocked by policy"],
                             evidence=_collect(probe, control))
    reflected = _HHI_CANARY in (probe.body or "")
    control_clean = _HHI_CANARY not in (control.body or "")
    reasons, fp = [], []
    reasons.append(("PASS" if reflected else "FAIL") + ": crafted Host header is reflected into the response")
    reasons.append(("PASS" if control_clean else "FAIL") + ": legitimate Host does not contain the canary")
    decisive = reflected and control_clean
    repro_ok = 0
    if decisive:
        for i in range(reproductions):
            r = runner.get(path, session=None, headers={"Host": _HHI_CANARY}, payload_class="boundary-probe",
                           rationale=f"reproduction #{i+1}", hypothesis_id=hid, summary=f"hhi repro {i+1}")
            if r.executed and _HHI_CANARY in (r.body or ""):
                repro_ok += 1
        fp.append(f"reproduced {repro_ok}/{reproductions} times")
    return OracleVerdict(validated=decisive and repro_ok >= reproductions, vuln_class="HOST_HEADER_INJECTION",
                         reasons=reasons, false_positive_checks=fp, reproductions=repro_ok,
                         evidence=_collect(probe, control))


def run_ssti_oracle(runner, hyp, reproductions: int = 2) -> OracleVerdict:
    # Arithmetic differential: {{1337*1338}} evaluates to 1788906 only if the template engine runs it.
    return _marker_oracle(runner, hyp, vuln_class="SSTI",
                          probe_value="{{1337*1338}}", control_value="1337*1338",
                          signature="1788906", reproductions=reproductions)


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
    probe = runner.get(path, session=None, headers={"Authorization": f"Bearer {forged}"},
                       payload_class="boundary-probe",
                       rationale="JWT probe: forged alg=none token with attacker-chosen identity",
                       hypothesis_id=hid, summary="jwt forged")
    unauth = runner.get(path, session=None, payload_class="benign-read",
                        rationale="negative control: no token", hypothesis_id=hid, summary="jwt unauth")
    if not probe.executed or not unauth.executed:
        return OracleVerdict(False, "JWT", reasons=["probe blocked by policy"],
                             evidence=_collect(probe, unauth))
    accepted = probe.status == 200 and _JWT_CANARY in (probe.body or "")
    auth_enforced = unauth.status in (401, 403)
    reasons, fp = [], []
    reasons.append(("PASS" if accepted else "FAIL")
                   + f": server accepted a forged alg=none token as '{_JWT_CANARY}' (status {probe.status})")
    reasons.append(("PASS" if auth_enforced else "FAIL")
                   + f": unauthenticated request is rejected (status {unauth.status})")
    decisive = accepted and auth_enforced
    repro_ok = 0
    if decisive:
        for i in range(reproductions):
            r = runner.get(path, session=None, headers={"Authorization": f"Bearer {forged}"},
                           payload_class="boundary-probe", rationale=f"reproduction #{i+1}",
                           hypothesis_id=hid, summary=f"jwt repro {i+1}")
            if r.executed and r.status == 200 and _JWT_CANARY in (r.body or ""):
                repro_ok += 1
        fp.append(f"reproduced {repro_ok}/{reproductions} times from clean requests")
    return OracleVerdict(validated=decisive and repro_ok >= reproductions, vuln_class="JWT",
                         reasons=reasons, false_positive_checks=fp, reproductions=repro_ok,
                         evidence=_collect(probe, unauth),
                         controls={"probe_status": probe.status, "unauth_status": unauth.status})


def run_bfla_oracle(runner, sessions, hyp, reproductions: int = 2) -> OracleVerdict:
    """Broken function-level authorization: a low-privilege principal reaches a privileged
    function (200 + privileged data) while the function still enforces authentication."""
    path = hyp["endpoint_path"]
    actor = hyp["actor_principal"]
    hid = hyp.get("id")
    if sessions is not None:
        sessions.fresh_session(actor)
    authed = runner.get(path, session=actor, payload_class="boundary-probe",
                        rationale="BFLA: low-privilege principal calls a privileged function",
                        hypothesis_id=hid, summary="bfla authed")
    unauth = runner.get(path, session=None, payload_class="benign-read",
                        rationale="negative control: unauthenticated access", hypothesis_id=hid,
                        summary="bfla unauth")
    if not authed.executed or not unauth.executed:
        return OracleVerdict(False, "BFLA", reasons=["probe blocked by policy"],
                             evidence=_collect(authed, unauth))
    priv = authed.status == 200 and _BFLA_SIGNATURE in (authed.body or "")
    auth_enforced = unauth.status in (401, 403)
    reasons, fp = [], []
    reasons.append(("PASS" if priv else "FAIL")
                   + f": low-priv principal '{actor}' received privileged data (status {authed.status})")
    reasons.append(("PASS" if auth_enforced else "FAIL")
                   + f": the function still enforces authentication (unauth -> {unauth.status})")
    decisive = priv and auth_enforced
    repro_ok = 0
    if decisive:
        for i in range(reproductions):
            if sessions is not None:
                sessions.fresh_session(actor)
            r = runner.get(path, session=actor, payload_class="boundary-probe",
                           rationale=f"reproduction #{i+1}", hypothesis_id=hid, summary=f"bfla repro {i+1}")
            if r.executed and r.status == 200 and _BFLA_SIGNATURE in (r.body or ""):
                repro_ok += 1
        fp.append(f"reproduced {repro_ok}/{reproductions} times from clean sessions")
    return OracleVerdict(validated=decisive and repro_ok >= reproductions, vuln_class="BFLA",
                         reasons=reasons, false_positive_checks=fp, reproductions=repro_ok,
                         evidence=_collect(authed, unauth),
                         controls={"authed_status": authed.status, "unauth_status": unauth.status})


def run_exposure_oracle(runner, sessions, hyp, reproductions: int = 2) -> OracleVerdict:
    """Excessive data exposure: an authenticated response includes sensitive fields (PII/secrets)."""
    path = hyp["endpoint_path"]
    actor = hyp["actor_principal"]
    hid = hyp.get("id")
    if sessions is not None:
        sessions.fresh_session(actor)
    resp = runner.get(path, session=actor, payload_class="boundary-probe",
                      rationale="excessive data exposure: inspect returned fields",
                      hypothesis_id=hid, summary="exposure probe")
    if not resp.executed:
        return OracleVerdict(False, "EXCESSIVE_DATA", reasons=["probe blocked by policy"],
                             evidence=_collect(resp))
    matches = sorted({m.group(1).lower() for m in _SENSITIVE_KEY.finditer(resp.body or "")})
    hit = resp.status == 200 and bool(matches)
    reasons, fp = [], []
    reasons.append(("PASS" if hit else "FAIL")
                   + f": response exposes sensitive field(s): {', '.join(matches) or 'none'}")
    repro_ok = 0
    if hit:
        for i in range(reproductions):
            r = runner.get(path, session=actor, payload_class="boundary-probe",
                           rationale=f"reproduction #{i+1}", hypothesis_id=hid, summary=f"exposure repro {i+1}")
            if r.executed and _SENSITIVE_KEY.search(r.body or ""):
                repro_ok += 1
        fp.append(f"reproduced {repro_ok}/{reproductions} times; fields: {', '.join(matches)}")
    return OracleVerdict(validated=hit and repro_ok >= reproductions, vuln_class="EXCESSIVE_DATA",
                         reasons=reasons, false_positive_checks=fp, reproductions=repro_ok,
                         evidence=_collect(resp), controls={"fields": matches, "status": resp.status})
