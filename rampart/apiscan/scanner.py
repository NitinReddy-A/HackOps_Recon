"""HTTP method/verb-tampering & access-control-bypass scanner + safe GraphQL depth checks.

Design mirrors the deterministic oracles (``rampart/validation/*``) and the self-contained
``list[Finding]`` scanners (``rampart/scanners/misconfig.py``, ``rampart/iac/scanner.py``):

* A positive signal is never enough on its own. Method tampering is only ``confirmed`` when a
  NEGATIVE CONTROL proves the canonical request really is denied (401/403) AND the override
  probe flips it to a 2xx with real content AND that effect reproduces >=2 times from clean,
  unauthenticated requests. Anything short of that is DROPPED (fail-closed) — never emitted as
  a tentative "confirmed".
* GraphQL depth checks are honestly tiered as ``firm`` indicators (human-review), not
  ``confirmed`` — introspection itself is covered by an independent oracle elsewhere.

Non-destructive by default: the only transport used is a GET carrying an
``X-HTTP-Method-Override`` header (which asks the server to treat the request as another verb
WITHOUT us issuing a destructive one). Real state-changing verbs (PUT/PATCH/DELETE) are
tunnelled over a gated Tier-2 POST and run ONLY when ``active=True``.
"""
from __future__ import annotations

import re

from ..schemas.finding import CVSS, Finding, Remediation, Reproduction, State, Verification
from ..util import now_iso

# ---------------------------------------------------------------------------- method tampering
_OVERRIDE_HEADER = "X-HTTP-Method-Override"
# Documented synonyms a server might honour; the standard header above is what we probe with.
_OVERRIDE_HEADER_SYNONYMS = ("X-HTTP-Method", "X-Method-Override")
# Safe override verbs — even if the server honours them they cannot mutate state; transport=GET.
_SAFE_OVERRIDES = ("GET", "HEAD", "OPTIONS")
# Real state-changing verbs — tunnelled over a gated POST; ACTIVE (active=True) only.
_ACTIVE_OVERRIDES = ("PUT", "PATCH", "DELETE")
_STATE_CHANGING = {"POST", "PUT", "PATCH", "DELETE"}
_ADMIN_RE = re.compile(r"(?i)(/admin|/internal|/manage|/actuator|/config|/_)")
_DENIAL = re.compile(
    r"(?i)\b(forbidden|unauthori[sz]ed|access denied|not authori[sz]ed|login required|"
    r"permission denied|authentication required)\b")
_PLACEHOLDER = re.compile(r"\{[^}/]+\}")
_REPRO = 2


def _concrete(path: str) -> str:
    """Replace ``{id}``-style path templates with a sample value so probes hit a resource."""
    return _PLACEHOLDER.sub("1", path or "/") or "/"


def _is_2xx(status) -> bool:
    return isinstance(status, int) and 200 <= status < 300


def _is_denied(status) -> bool:
    return status in (401, 403)


def _looks_real(body, control_body) -> bool:
    """A successful probe body is 'real' when it is non-empty, is not itself a denial page,
    and differs from the canonical denial body (so a generic 2xx error cannot pass)."""
    b = (body or "").strip()
    if not b or _DENIAL.search(b):
        return False
    return b != (control_body or "").strip()


def _is_protected(e) -> bool:
    """An endpoint worth testing: access-controlled (auth_required / security / observed roles)
    or state-changing by verb or an admin-ish path."""
    method = (getattr(e, "method", "GET") or "GET").upper()
    if getattr(e, "auth_required", False):
        return True
    if getattr(e, "security", None):          # OpenAPI-derived models may carry a security block
        return True
    if getattr(e, "observed_roles", None):
        return True
    if method in _STATE_CHANGING:
        return True
    return bool(_ADMIN_RE.search(getattr(e, "path", "") or ""))


def _canonical_control(runner, transport, path):
    """The negative control: the canonical request, unauthenticated, that MUST be denied."""
    rationale = (f"negative control: canonical {transport} to a protected path, "
                 "unauthenticated — must be denied (401/403)")
    if transport == "POST":
        return runner.post(path, {}, session=None, payload_class="boundary-probe",
                           rationale=rationale, summary="method-tamper control")
    return runner.get(path, session=None, payload_class="benign-read",
                      rationale=rationale, summary="method-tamper control")


def _tamper_probe(runner, transport, path, override_method, repro=0):
    tag = f" reproduction #{repro}" if repro else ""
    rationale = (f"verb-tampering probe: {transport} with {_OVERRIDE_HEADER}: {override_method}, "
                 f"unauthenticated{tag}")
    headers = {_OVERRIDE_HEADER: override_method}
    summary = f"method-tamper probe {override_method}{tag}"
    if transport == "POST":
        return runner.post(path, {}, session=None, headers=headers, payload_class="boundary-probe",
                           rationale=rationale, summary=summary)
    return runner.get(path, session=None, headers=headers, payload_class="boundary-probe",
                      rationale=rationale, summary=summary)


def _method_tamper_finding(eng, application, target_url, canon, path, transport, alt,
                           control, probe, repro_ok) -> Finding:
    url = f"{target_url}{path}"
    f = Finding(
        engagement_id=eng,
        title=f"HTTP method/verb tampering authorization bypass on {canon} {path}",
        vuln_class="HTTP_METHOD_TAMPERING",
        severity="high",
        confidence="confirmed",
        state=State.VALIDATED,
        cwe=["CWE-650", "CWE-285"],
        owasp={"api_2023": ["API5:2023-BFLA"]},
        asvs={"requirement": "V4.1.1", "level": 1},
        cvss=CVSS(version="4.0", base_score=8.2,
                  vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N",
                  severity="high",
                  v31_fallback={"base_score": 8.1,
                                "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N"}),
        asset={"type": "api_endpoint", "application": application,
               "environment": "authorized", "target": target_url},
        endpoint={"method": canon, "url": url, "override_method": alt,
                  "override_header": _OVERRIDE_HEADER, "transport": transport,
                  "auth_required": True},
        description=(f"{canon} {path} enforces authentication for the canonical request, but an "
                     f"unauthenticated {transport} carrying '{_OVERRIDE_HEADER}: {alt}' is served a "
                     f"{probe.status} response with real/privileged content. The HTTP method/verb is "
                     "trusted for the access-control decision, so tampering with it via the override "
                     "header bypasses authorization."),
        impact=("An anonymous attacker reaches a protected function/resource by changing the HTTP "
                "method through an override header — broken function-level authorization (BFLA)."),
        root_cause=("Authorization is keyed on the HTTP method (or on an override header the server "
                    "re-dispatches on) rather than on the authenticated principal; a security filter "
                    "guards only the canonical verb and is bypassed when the verb is overridden."),
        reproduction=Reproduction(
            prerequisites=["None (unauthenticated)"],
            steps=[f"{transport} {path} with no session -> {control.status} (denied; auth enforced)",
                   f"{transport} {path} with '{_OVERRIDE_HEADER}: {alt}' and no session -> "
                   f"{probe.status} (allowed)",
                   "Observe real/privileged content returned without authentication"],
            deterministic=True),
        remediation=Remediation(
            summary="Authorize on the authenticated principal, not the HTTP method; ignore "
                    "method-override headers unless strictly required.",
            type="code_patch",
            guidance=("Apply deny-by-default, centralized function-level authorization keyed on the "
                      "authenticated identity/role for EVERY method (including HEAD/OPTIONS and any "
                      "X-HTTP-Method-Override/X-HTTP-Method/X-Method-Override header). Disable "
                      "method-override handling where it is not needed, and ensure the auth filter "
                      "runs after method normalization so an override cannot route around it "
                      "(CWE-650, CWE-285, OWASP API5:2023)."),
            effort="medium"),
        references=["https://cwe.mitre.org/data/definitions/650.html",
                    "https://cwe.mitre.org/data/definitions/285.html",
                    "https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/"],
        compliance_control_refs=["SOC2:CC6.3", "ISO27001:A.8.2", "PCI-DSS:7.1"],
        dedupe_key=f"{application}:method-tamper:{canon}:{path}",
        tags=["method-tampering", "verb-tampering", "access-control", "bfla", "api"],
        verification=Verification(
            method="method-override-replay",
            validated=True,
            validated_at=now_iso(),
            validator="apiscan-method-tamper",
            independent_reproduction=True,
            reproductions=repro_ok,
            false_positive_checks=[
                f"negative control: canonical {canon} unauthenticated returned {control.status} "
                "(auth IS enforced — the defect is isolated to the method/override, not a missing "
                "auth check)",
                f"override probe unauthenticated returned {probe.status} with real content distinct "
                "from the denial body",
                f"reproduced {repro_ok}/{_REPRO} times from clean, unauthenticated requests"],
            confidence_score=0.9))
    f.assert_consistent()
    return f


def method_tampering_scan(runner, appmodel, target_url, application, engagement_id="",
                          active=False) -> list[Finding]:
    """Detect method/verb-tampering authorization bypass (CWE-650/CWE-285, OWASP API5:2023).

    For each access-controlled or state-changing endpoint, prove that an ``X-HTTP-Method-Override``
    header flips a genuinely-denied canonical request into a 2xx with real content, re-derived
    against a negative control and reproduced twice. Returns ``confirmed`` findings only.

    Non-destructive by default (``active=False``): GET transport + safe override verbs only.
    ``active=True`` additionally tunnels real PUT/PATCH/DELETE over a gated Tier-2 POST.
    """
    eng = engagement_id or getattr(runner, "engagement_id", "")
    findings: list[Finding] = []
    seen: set = set()
    for e in (getattr(appmodel, "endpoints", []) or []):
        if not _is_protected(e):
            continue
        canon = (getattr(e, "method", "GET") or "GET").upper()
        path = _concrete(getattr(e, "path", "/") or "/")
        key = (canon, path)
        if key in seen:
            continue
        seen.add(key)

        families = [("GET", _SAFE_OVERRIDES)]
        if active:
            families.append(("POST", _ACTIVE_OVERRIDES))

        finding = None
        for transport, overrides in families:
            control = _canonical_control(runner, transport, path)
            # Fail-closed: without a clean negative control (canonical really denied) we cannot
            # isolate the override as the cause, so we never emit for this family.
            if not getattr(control, "executed", False) or not _is_denied(control.status):
                continue
            for alt in overrides:
                probe = _tamper_probe(runner, transport, path, alt)
                if not getattr(probe, "executed", False) or not _is_2xx(probe.status):
                    continue
                if not _looks_real(probe.body, control.body):
                    continue
                # Reproduce from clean, unauthenticated state.
                repro_ok = 0
                for i in range(_REPRO):
                    r = _tamper_probe(runner, transport, path, alt, repro=i + 1)
                    if (getattr(r, "executed", False) and _is_2xx(r.status)
                            and _looks_real(r.body, control.body)):
                        repro_ok += 1
                if repro_ok < _REPRO:
                    continue  # not decisively reproducible -> DROP (fail-closed)
                finding = _method_tamper_finding(eng, application, target_url, canon, path,
                                                 transport, alt, control, probe, repro_ok)
                break
            if finding is not None:
                break
        if finding is not None:
            findings.append(finding)
    return findings


# ---------------------------------------------------------------------------- GraphQL depth
# A deliberately misspelled field name (near-miss of a common root field) to elicit the
# server's "Did you mean …?" field suggestion when suggestions are enabled.
_GQL_TYPO_QUERY = "query { uesr }"
_GQL_BATCH = [{"query": "{ __typename }"}, {"query": "{ __typename }"}]
_GQL_ALIAS_QUERY = "query { a0: __typename a1: __typename }"
# Tolerate JSON/backslash-escaped quotes around the suggested field, e.g. Did you mean \"user\"?
_DID_YOU_MEAN = re.compile(r"(?i)did you mean\s+[\"'\\]*([A-Za-z_][A-Za-z0-9_]*)")
_GQL_REJECTED = re.compile(r"(?i)(not allowed|not permitted|disabled|not supported|too many|"
                           r"forbidden|rejected|limit exceeded)")


def _gql_endpoints(appmodel) -> list:
    paths, seen = [], set()
    for e in (getattr(appmodel, "endpoints", []) or []):
        p = getattr(e, "path", "") or ""
        if "graphql" in p.lower() and p not in seen:
            seen.add(p)
            paths.append(p)
    return paths


def _firm_graphql_finding(eng, application, target_url, path, *, vuln_class, severity, cwe,
                          owasp, title, description, impact, root_cause, remediation, references,
                          checks, method_name, score, tags) -> Finding:
    f = Finding(
        engagement_id=eng, title=title, vuln_class=vuln_class, severity=severity,
        confidence="firm", state=State.EVIDENCE_FOUND, cwe=cwe, owasp=owasp,
        asset={"type": "api_endpoint", "application": application,
               "environment": "authorized", "target": target_url},
        endpoint={"method": "POST", "url": f"{target_url}{path}", "auth_required": False},
        description=description, impact=impact, root_cause=root_cause,
        reproduction=Reproduction(prerequisites=["None (unauthenticated POST)"],
                                  steps=checks, deterministic=True),
        remediation=remediation, references=references,
        compliance_control_refs=["SOC2:CC7.1", "ISO27001:A.8.9"],
        dedupe_key=f"{application}:{vuln_class}:{path}", tags=tags,
        verification=Verification(method=method_name, validated=False, validated_at=now_iso(),
                                  validator="apiscan-graphql", independent_reproduction=False,
                                  reproductions=0, false_positive_checks=checks,
                                  confidence_score=score))
    f.assert_consistent()  # firm (not confirmed) — always consistent
    return f


def graphql_depth_scan(runner, appmodel, target_url, application,
                       engagement_id="") -> list[Finding]:
    """Safe GraphQL depth signals, tiered as ``firm`` indicators (never ``confirmed``).

    * GRAPHQL_FIELD_SUGGESTION (CWE-200): a misspelled field triggers a 'Did you mean "<field>"?'
      error, leaking schema even with introspection disabled.
    * GRAPHQL_BATCHING (CWE-770): an array-batch of two queries (or a multi-alias query) is
      accepted (200), a query-amplification / resource-exhaustion indicator.

    Introspection itself is covered by an independent oracle elsewhere and is not re-checked here.
    """
    eng = engagement_id or getattr(runner, "engagement_id", "")
    findings: list[Finding] = []
    for path in _gql_endpoints(appmodel):
        # --- field-suggestion leakage -------------------------------------------------
        sug = runner.post(path, {"query": _GQL_TYPO_QUERY}, session=None, payload_class="benign-read",
                          rationale="graphql field-suggestion probe: misspelled field name",
                          summary="graphql field-suggestion probe")
        if getattr(sug, "executed", False):
            m = _DID_YOU_MEAN.search(sug.body or "")
            if m:
                suggested = m.group(1).strip()
                findings.append(_firm_graphql_finding(
                    eng, application, target_url, path,
                    vuln_class="GRAPHQL_FIELD_SUGGESTION", severity="low", cwe=["CWE-200"],
                    owasp={"api_2023": ["API8:2023-Security Misconfiguration"]},
                    title=f"GraphQL field-suggestion leakage on POST {path}",
                    description=("The GraphQL endpoint returns field suggestions "
                                 f"('Did you mean \"{suggested}\"?') for a misspelled field, "
                                 "leaking schema field names even if introspection is disabled."),
                    impact="An attacker can enumerate schema field names (and infer the data model) "
                           "without introspection, aiding targeted queries/mutations.",
                    root_cause="GraphQL field-suggestion ('did you mean') hints are enabled on an "
                               "endpoint exposed to untrusted clients.",
                    remediation=Remediation(
                        summary="Disable field suggestions / verbose errors for untrusted clients.",
                        type="config",
                        guidance="Turn off 'did you mean' field suggestions in production (e.g. "
                                 "disable in the GraphQL server config or mask errors at the edge), "
                                 "alongside disabling introspection (CWE-200).",
                        effort="low"),
                    references=["https://cwe.mitre.org/data/definitions/200.html",
                                "https://owasp.org/www-project-web-security-testing-guide/latest/"
                                "4-Web_Application_Security_Testing/12-API_Testing/01-Testing_GraphQL"],
                    checks=[f"POST {path} with a misspelled field returned a "
                            f"'Did you mean \"{suggested}\"?' suggestion",
                            "FIRM indicator — schema leakage via error hints (not a confirmed "
                            "exploit); confirm the endpoint is production and the field is real"],
                    method_name="graphql-field-suggestion", score=0.6,
                    tags=["graphql", "field-suggestion", "information-disclosure",
                          "needs-human-review"]))

        # --- batching / alias amplification indicator ---------------------------------
        batch = runner.post(path, _GQL_BATCH, session=None, payload_class="benign-read",
                            rationale="graphql batching probe: array of 2 trivial queries",
                            summary="graphql batching probe")
        accepted = (getattr(batch, "executed", False) and batch.status == 200
                    and not _GQL_REJECTED.search(batch.body or ""))
        mech = "array batching (2 queries in one request)"
        if not accepted:
            alias = runner.post(path, {"query": _GQL_ALIAS_QUERY}, session=None,
                               payload_class="benign-read",
                               rationale="graphql alias-amplification probe: multiple aliases",
                               summary="graphql alias probe")
            if (getattr(alias, "executed", False) and alias.status == 200
                    and not _GQL_REJECTED.search(alias.body or "")):
                accepted = True
                mech = "alias amplification (multiple aliases in one query)"
        if accepted:
            findings.append(_firm_graphql_finding(
                eng, application, target_url, path,
                vuln_class="GRAPHQL_BATCHING", severity="medium", cwe=["CWE-770"],
                owasp={"api_2023": ["API4:2023-Unrestricted Resource Consumption"]},
                title=f"GraphQL query batching / alias amplification accepted on POST {path}",
                description=(f"The GraphQL endpoint accepts {mech}, letting a single request fan out "
                             "into many resolver executions — a resource-amplification / "
                             "denial-of-service vector."),
                impact="A single unauthenticated request can be amplified into many operations, "
                       "enabling denial-of-service and brute-force/rate-limit evasion.",
                root_cause="Query batching and/or alias fan-out are accepted without depth, "
                           "complexity, or batch-size limits.",
                remediation=Remediation(
                    summary="Enforce query cost/depth/complexity limits and cap or disable batching.",
                    type="config",
                    guidance="Add query depth and complexity/cost limits, cap the number of aliases, "
                             "and disable or bound array batching for untrusted clients; apply "
                             "per-client rate limiting (CWE-770, OWASP API4:2023).",
                    effort="medium"),
                references=["https://cwe.mitre.org/data/definitions/770.html",
                            "https://owasp.org/API-Security/editions/2023/en/"
                            "0xa4-unrestricted-resource-consumption/"],
                checks=[f"POST {path} accepted {mech} with HTTP 200",
                        "FIRM indicator — amplification is accepted (not a demonstrated DoS); "
                        "confirm absence of depth/complexity/rate limits"],
                method_name="graphql-batching", score=0.55,
                tags=["graphql", "batching", "resource-amplification", "dos",
                      "needs-human-review"]))
    return findings


# ---------------------------------------------------------------------------- convenience
def api_scan(runner, appmodel, target_url, application, engagement_id="",
             active=False) -> list[Finding]:
    """Run both API-depth scans and return the combined findings.

    = ``method_tampering_scan(...)`` (confirmed) + ``graphql_depth_scan(...)`` (firm indicators).
    Non-destructive by default; ``active=True`` enables the gated real-verb method-tamper probes.
    """
    return (method_tampering_scan(runner, appmodel, target_url, application,
                                  engagement_id=engagement_id, active=active)
            + graphql_depth_scan(runner, appmodel, target_url, application,
                                 engagement_id=engagement_id))
