"""Independent deterministic oracles for the web/API injection classes (blueprint section 31).

Each mirrors the BOLA oracle's discipline: a positive signal is never enough on its own —
the oracle re-derives proof with a benign baseline, the probe, and negative controls, and
requires the effect to reproduce 2+ times from a clean request. This is the deterministic
false-positive gate that lets a reflected-XSS / SQLi / open-redirect finding carry
``confidence=confirmed`` honestly. All probes are unauthenticated Tier-1 GETs with the
payload in the query string; nothing is written or destroyed.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

from .oracle import OracleVerdict

# A distinctive, inert token so we can recognise our own input reflected back.
_CANARY = "RAMPARTxk7q1"
# SQL driver/error signatures a backend leaks when a quote breaks a statement.
_SQL_ERROR = re.compile(
    r"(?i)(SQLSTATE|SQL syntax|syntax error at or near|unterminated quoted|unclosed quotation|"
    r"ORA-\d{4,}|ODBC|psql:|mysql_fetch|PG::|SQLite3::|near \"[^\"]*\": syntax error)"
)
# A host we claim to redirect to but NEVER fetch — the oracle only inspects the Location header.
_REDIRECT_CANARY_HOST = "rampart-oracle-canary.example"

# Tokens that legitimately change between two identical requests (clocks, ids, nonces). They are
# masked before boolean-based response comparison so a time-varying page cannot fake a difference.
_DYNAMIC_TOKENS = [
    re.compile(
        r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(?::\d{2}(?:[.,]\d+)?)?(?:Z|[+-]\d{2}:?\d{2})?"
    ),  # ISO-8601 datetime
    re.compile(
        r"(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun), \d{1,2} (?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) "
        r"\d{4} \d{2}:\d{2}:\d{2} GMT"
    ),  # HTTP-date
    re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"),  # UUID
    re.compile(r"\b[0-9a-fA-F]{16,}\b"),  # hex nonce / token / hash
    re.compile(r"(?<![\d.])\d{10}(?:\d{3})?(?:\.\d+)?(?![\d])"),  # epoch seconds / millis
]


def _normalize_dynamic(body: str) -> str:
    out = body or ""
    for rx in _DYNAMIC_TOKENS:
        out = rx.sub("<dyn>", out)
    return out


def _headers_ci(response) -> dict:
    return {str(k).lower(): v for k, v in (getattr(response, "headers", {}) or {}).items()}


def _ctype(response) -> str:
    return _headers_ci(response).get("content-type", "")


def _collect(*outcomes) -> list:
    evs = []
    for o in outcomes:
        evs.extend(getattr(o, "evidence", []) or [])
    return evs


# --------------------------------------------------------------------- Reflected XSS
def run_xss_oracle(runner, hyp: dict, reproductions: int = 2) -> OracleVerdict:
    path, param = hyp["endpoint_path"], hyp["selector_param"]
    hid = hyp.get("id")
    benign = f"{_CANARY}benign"
    markup = f'"><rx>{_CANARY}</rx>'  # contains HTML metacharacters

    base = runner.get(
        path,
        session=None,
        query={param: benign},
        payload_class="boundary-probe",
        rationale="baseline: benign value to locate the reflection point",
        hypothesis_id=hid,
        summary="xss baseline",
    )
    probe = runner.get(
        path,
        session=None,
        query={param: markup},
        payload_class="boundary-probe",
        rationale="probe: inject inert HTML markup in the parameter",
        hypothesis_id=hid,
        summary="xss probe",
    )
    if not probe.executed or not base.executed:
        return OracleVerdict(
            False, "XSS", reasons=["probe blocked by policy"], evidence=_collect(base, probe)
        )

    html_context = "text/html" in _ctype(probe.response).lower()
    benign_reflected = benign in base.body
    unescaped = markup in probe.body  # raw `<`/`>` survived -> executable
    escaped = ("&lt;rx&gt;" in probe.body) or ("&lt;" in probe.body and _CANARY in probe.body)

    reasons, fp = [], []
    reasons.append(
        ("PASS" if html_context else "FAIL")
        + f": response is an HTML context ({_ctype(probe.response) or 'n/a'})"
    )
    reasons.append(
        ("PASS" if benign_reflected else "FAIL") + ": the parameter value is reflected into the page"
    )
    reasons.append(
        ("PASS" if unescaped else "FAIL") + ": injected markup is reflected WITHOUT output encoding"
    )
    fp.append(f"encoded reflection seen instead: {escaped} (encoding would neutralise the payload)")
    all_ok = html_context and benign_reflected and unescaped

    repro_ok = 0
    if all_ok:
        for i in range(reproductions):
            r = runner.get(
                path,
                session=None,
                query={param: markup},
                payload_class="boundary-probe",
                rationale=f"reproduction #{i + 1} of unescaped reflection",
                hypothesis_id=hid,
                summary=f"xss repro {i + 1}",
            )
            if r.executed and markup in r.body and "text/html" in _ctype(r.response).lower():
                repro_ok += 1
        fp.append(f"reproduced {repro_ok}/{reproductions} times from clean requests")

    return OracleVerdict(
        validated=all_ok and repro_ok >= reproductions,
        vuln_class="XSS",
        reasons=reasons,
        false_positive_checks=fp,
        reproductions=repro_ok,
        evidence=_collect(base, probe),
        controls={"content_type": _ctype(probe.response), "unescaped": unescaped, "escaped": escaped},
    )


# --------------------------------------------------------------------- SQL injection
def run_sqli_oracle(runner, hyp: dict, reproductions: int = 2) -> OracleVerdict:
    path, param = hyp["endpoint_path"], hyp["selector_param"]
    hid = hyp.get("id")
    base_val = str(hyp.get("base_value", "1"))

    base = runner.get(
        path,
        session=None,
        query={param: base_val},
        payload_class="boundary-probe",
        rationale="baseline: benign lookup",
        hypothesis_id=hid,
        summary="sqli baseline",
    )
    # error-based: a lone quote should break a concatenated statement
    err = runner.get(
        path,
        session=None,
        query={param: base_val + "'"},
        payload_class="boundary-probe",
        rationale="probe: single quote to break the statement (error-based)",
        hypothesis_id=hid,
        summary="sqli error-probe",
    )
    # a benign non-numeric control must NOT error (isolates the quote as the cause)
    ctrl = runner.get(
        path,
        session=None,
        query={param: _CANARY},
        payload_class="boundary-probe",
        rationale="negative control: benign token (no quote) must not error",
        hypothesis_id=hid,
        summary="sqli control",
    )
    # boolean-based: true vs false conditions
    t = runner.get(
        path,
        session=None,
        query={param: base_val + "' AND '1'='1"},
        payload_class="boundary-probe",
        rationale="probe: always-true boolean condition",
        hypothesis_id=hid,
        summary="sqli true",
    )
    fcond = runner.get(
        path,
        session=None,
        query={param: base_val + "' AND '1'='2"},
        payload_class="boundary-probe",
        rationale="probe: always-false boolean condition",
        hypothesis_id=hid,
        summary="sqli false",
    )
    # second fetch of each condition: a real boolean sink is stable per condition
    t2 = runner.get(
        path,
        session=None,
        query={param: base_val + "' AND '1'='1"},
        payload_class="boundary-probe",
        rationale="probe: always-true boolean condition (stability re-fetch)",
        hypothesis_id=hid,
        summary="sqli true 2",
    )
    fcond2 = runner.get(
        path,
        session=None,
        query={param: base_val + "' AND '1'='2"},
        payload_class="boundary-probe",
        rationale="probe: always-false boolean condition (stability re-fetch)",
        hypothesis_id=hid,
        summary="sqli false 2",
    )
    if not all(o.executed for o in (base, err, ctrl, t, fcond, t2, fcond2)):
        return OracleVerdict(
            False,
            "SQLI",
            reasons=["probe blocked by policy"],
            evidence=_collect(base, err, ctrl, t, fcond, t2, fcond2),
        )

    err_sig = bool(_SQL_ERROR.search(err.body))
    base_sig = bool(_SQL_ERROR.search(base.body))
    ctrl_sig = bool(_SQL_ERROR.search(ctrl.body))
    error_based = err_sig and not base_sig and not ctrl_sig

    nb, nt, nt2 = _normalize_dynamic(base.body), _normalize_dynamic(t.body), _normalize_dynamic(t2.body)
    nf, nf2 = _normalize_dynamic(fcond.body), _normalize_dynamic(fcond2.body)
    true_like_base = (t.status == t2.status == base.status) and (nt == nt2 == nb)
    false_stable = (fcond.status == fcond2.status) and (nf == nf2)
    false_differs = (nf != nt) or (fcond.status != t.status)
    boolean_based = true_like_base and false_stable and false_differs

    reasons, fp = [], []
    reasons.append(
        ("PASS" if error_based else "FAIL")
        + f": single-quote yields a DB error ({err.status}) absent from baseline/benign control"
    )
    reasons.append(
        ("PASS" if boolean_based else "FAIL")
        + ": AND 1=1 matches the baseline (twice) while AND 1=2 is stable and differs "
        "(boolean-based inference; clocks/ids/nonces masked)"
    )
    fp.append(f"benign control '{_CANARY}' errored: {ctrl_sig} (should be False)")
    fp.append(f"baseline errored: {base_sig} (should be False)")
    decisive = error_based or boolean_based

    repro_ok = 0
    if decisive:
        for i in range(reproductions):
            if error_based:
                r = runner.get(
                    path,
                    session=None,
                    query={param: base_val + "'"},
                    payload_class="boundary-probe",
                    rationale=f"reproduction #{i + 1} error-based",
                    hypothesis_id=hid,
                    summary=f"sqli repro {i + 1}",
                )
                ok = r.executed and bool(_SQL_ERROR.search(r.body))
            else:
                # re-fetch BOTH conditions and compare them to each other (never to a stale response)
                rt = runner.get(
                    path,
                    session=None,
                    query={param: base_val + "' AND '1'='1"},
                    payload_class="boundary-probe",
                    rationale=f"reproduction #{i + 1} boolean-based (true)",
                    hypothesis_id=hid,
                    summary=f"sqli repro {i + 1} true",
                )
                rf = runner.get(
                    path,
                    session=None,
                    query={param: base_val + "' AND '1'='2"},
                    payload_class="boundary-probe",
                    rationale=f"reproduction #{i + 1} boolean-based (false)",
                    hypothesis_id=hid,
                    summary=f"sqli repro {i + 1} false",
                )
                ok = (
                    rt.executed
                    and rf.executed
                    and (_normalize_dynamic(rt.body) != _normalize_dynamic(rf.body) or rt.status != rf.status)
                )
            repro_ok += 1 if ok else 0
        fp.append(f"reproduced {repro_ok}/{reproductions} times from clean requests")

    return OracleVerdict(
        validated=decisive and repro_ok >= reproductions,
        vuln_class="SQLI",
        reasons=reasons,
        false_positive_checks=fp,
        reproductions=repro_ok,
        evidence=_collect(base, err, ctrl, t, fcond, t2, fcond2),
        controls={
            "error_based": error_based,
            "boolean_based": boolean_based,
            "err_status": err.status,
            "base_status": base.status,
        },
    )


# --------------------------------------------------------------------- Open redirect
def run_redirect_oracle(runner, hyp: dict, reproductions: int = 2) -> OracleVerdict:
    path, param = hyp["endpoint_path"], hyp["selector_param"]
    hid = hyp.get("id")
    evil = f"https://{_REDIRECT_CANARY_HOST}/pwned"

    probe = runner.get(
        path,
        session=None,
        query={param: evil},
        payload_class="boundary-probe",
        rationale="probe: attacker-controlled absolute URL in the redirect parameter",
        hypothesis_id=hid,
        summary="redirect probe",
    )
    safe = runner.get(
        path,
        session=None,
        query={param: "/account"},
        payload_class="boundary-probe",
        rationale="negative control: a local relative path",
        hypothesis_id=hid,
        summary="redirect control",
    )
    if not probe.executed or not safe.executed:
        return OracleVerdict(
            False, "OPEN_REDIRECT", reasons=["probe blocked by policy"], evidence=_collect(probe, safe)
        )

    def _loc_host(outcome):
        loc = _headers_ci(outcome.response).get("location", "")
        return urlparse(loc).hostname or "", loc

    probe_host, probe_loc = _loc_host(probe)
    safe_host, safe_loc = _loc_host(safe)
    is_redirect = probe.status in (301, 302, 303, 307, 308)
    external = is_redirect and probe_host == _REDIRECT_CANARY_HOST
    control_safe = (safe.status >= 400) or (not safe_host) or (safe_host != _REDIRECT_CANARY_HOST)

    reasons, fp = [], []
    reasons.append(
        ("PASS" if external else "FAIL")
        + f": parameter drives an off-site redirect to {probe_host or 'n/a'} (status {probe.status})"
    )
    reasons.append(
        ("PASS" if control_safe else "FAIL")
        + f": a local relative value stays on-site or is rejected (status {safe.status})"
    )
    fp.append(f"probe Location: {probe_loc or 'none'}")
    fp.append(f"control Location: {safe_loc or 'none'}")
    all_ok = external and control_safe

    repro_ok = 0
    if all_ok:
        for i in range(reproductions):
            r = runner.get(
                path,
                session=None,
                query={param: evil},
                payload_class="boundary-probe",
                rationale=f"reproduction #{i + 1} external redirect",
                hypothesis_id=hid,
                summary=f"redirect repro {i + 1}",
            )
            h, _ = _loc_host(r)
            if r.executed and r.status in (301, 302, 303, 307, 308) and h == _REDIRECT_CANARY_HOST:
                repro_ok += 1
        fp.append(f"reproduced {repro_ok}/{reproductions} times from clean requests")

    return OracleVerdict(
        validated=all_ok and repro_ok >= reproductions,
        vuln_class="OPEN_REDIRECT",
        reasons=reasons,
        false_positive_checks=fp,
        reproductions=repro_ok,
        evidence=_collect(probe, safe),
        controls={"probe_status": probe.status, "probe_host": probe_host, "control_status": safe.status},
    )
