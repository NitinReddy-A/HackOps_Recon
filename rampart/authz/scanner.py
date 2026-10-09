"""Deeper authentication / access-control checks beyond the alg=none JWT oracle.

Two of the most common real-world JWT failures, each confirmed with a probe + negative control +
reproductions (fail-closed — only a decisive, reproduced bypass is reported confirmed):

  * **Weak HMAC signing secret** — the token IS signature-verified, but with a guessable secret
    (``secret``, ``changeme``, the framework default …). We forge an attacker identity signed with
    a candidate from a small wordlist; if the server accepts it, the secret is broken (CWE-326/347).
  * **Expiry not enforced** — a token whose ``exp`` is in the past is still accepted (CWE-613), proven
    by replaying a forged already-expired token once a signing path is known to be accepted.

All requests go through the ProbeRunner (policy-gated, audited). This is non-destructive: GETs only.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets as _secrets
import time

from ..schemas.finding import CVSS, Finding, Remediation, Reproduction, State, Verification
from ..util import now_iso

CANARY = "rampart-authz-canary"

# Small, high-signal wordlist of secrets seen in the wild / framework defaults.
WEAK_SECRETS = [
    "secret",
    "secretkey",
    "secret_key",
    "changeme",
    "password",
    "123456",
    "admin",
    "jwt",
    "jwtsecret",
    "jwt_secret",
    "key",
    "test",
    "dev",
    "supersecret",
    "your-256-bit-secret",
    "your_jwt_secret",
    "mysecret",
    "s3cr3t",
    "token",
    "qwerty",
    "default",
]


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def forge_hs256(payload: dict, secret: str) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    signing_input = f"{_b64url(json.dumps(header).encode())}.{_b64url(json.dumps(payload).encode())}"
    sig = hmac.new(secret.encode("utf-8"), signing_input.encode("ascii"), hashlib.sha256).digest()
    return f"{signing_input}.{_b64url(sig)}"


def _auth_required(ep) -> bool:
    return getattr(ep, "auth_required", False) is True


def _candidate_paths(appmodel, probe_paths=None) -> list[str]:
    if probe_paths:
        return list(probe_paths)
    paths = []
    for ep in getattr(appmodel, "endpoints", []) or []:
        method = (getattr(ep, "method", "GET") or "GET").upper()
        if method == "GET" and _auth_required(ep):
            p = getattr(ep, "path", "")
            if p and p not in paths:
                paths.append(p)
    return paths


def _weak_secret_finding(path, target_url, application, engagement_id, secret, expiry_bypass) -> Finding:
    extra = " The server also accepted an EXPIRED token (exp not enforced)." if expiry_bypass else ""
    cwes = ["CWE-326", "CWE-347"] + (["CWE-613"] if expiry_bypass else [])
    return Finding(
        engagement_id=engagement_id,
        title=f"Weak JWT signing secret on GET {path}",
        vuln_class="WEAK_JWT_SECRET",
        severity="critical",
        confidence="confirmed",
        state=State.VALIDATED,
        cwe=cwes,
        owasp={
            "api_2023": ["API2:2023-Broken Authentication"],
            "web_2021": ["A07:2021-Identification and Authentication Failures"],
        },
        cvss=CVSS(
            version="3.1",
            base_score=9.8,
            severity="critical",
            vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        ),
        asset={"type": "web", "application": application, "environment": "authorized", "target": target_url},
        endpoint={"method": "GET", "url": f"{target_url}{path}", "auth_required": True},
        description=(
            f"The JWT on {path} is HMAC-signed with a guessable secret; an attacker who "
            f"knows/guesses it can forge a token for any identity (e.g. an admin).{extra}"
        ),
        impact="Full authentication bypass / account & privilege takeover by forging arbitrary tokens.",
        root_cause="JWTs are signed with a weak, guessable HMAC secret (and signature/exp are the only gate).",
        reproduction=Reproduction(
            prerequisites=["Network access to the API"],
            steps=[
                f"Forge an HS256 token for '{CANARY}' signed with a weak secret",
                f"GET {path} with Authorization: Bearer <forged>",
                "Observe the forged identity is accepted",
            ],
            deterministic=True,
        ),
        remediation=Remediation(
            summary="Rotate to a long, random (>=256-bit) signing key from a secrets manager; enforce exp.",
            type="config_change",
            guidance="Use a high-entropy signing key, store it in a secrets manager, validate alg against "
            "an allowlist, and reject expired/not-yet-valid tokens.",
            effort="medium",
        ),
        references=[
            "https://cwe.mitre.org/data/definitions/326.html",
            "https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/",
        ],
        compliance_control_refs=["SOC2:CC6.1", "ISO27001:A.8.5", "PCI-DSS:8.3"],
        dedupe_key=f"{application}:GET:{path}:weak-jwt-secret",
        tags=["auth", "jwt", "weak-secret"] + (["jwt-expiry"] if expiry_bypass else []),
        verification=Verification(
            method="jwt-weak-secret-forge",
            validated=True,
            validated_at=now_iso(),
            validator="authz-scan",
            independent_reproduction=True,
            reproductions=2,
            false_positive_checks=[
                f"forged token signed with weak secret '{secret}' was accepted as '{CANARY}'",
                "a request with NO token returned 401 (negative control)",
                "a token signed with a random 256-bit secret was REJECTED (so the server "
                "does verify the signature — this is a weak key, not a missing check)",
            ],
            confidence_score=0.96,
        ),
    )


def jwt_secret_scan(
    runner, appmodel, target_url, application, engagement_id="", probe_paths=None, wordlist=None
) -> list[Finding]:
    """Detect weak JWT HMAC secrets (and expiry-not-enforced) on auth-protected GET endpoints."""
    wordlist = wordlist or WEAK_SECRETS
    findings = []
    for path in _candidate_paths(appmodel, probe_paths):
        future = int(time.time()) + 3600
        # Control 1: no token must be rejected (proves the endpoint is actually protected).
        ctrl = runner.get(
            path,
            session=None,
            payload_class="benign-read",
            rationale="authz control: request with no token",
            summary="authz control",
        )
        if not ctrl.executed or ctrl.status != 401:
            continue
        # Control 2: a token signed with a long RANDOM secret must ALSO be rejected. If it is
        # accepted, the server isn't verifying the signature at all (that is the alg=none / no-sig
        # class, reported elsewhere) — NOT a weak-secret bug, so we drop to avoid misattribution.
        rand_tok = forge_hs256({"sub": CANARY, "role": "admin", "exp": future}, _secrets.token_hex(32))
        rc = runner.get(
            path,
            session=None,
            headers={"Authorization": f"Bearer {rand_tok}"},
            payload_class="boundary-probe",
            rationale="authz control: token signed with a random secret must be rejected",
            summary="authz random-secret control",
        )
        if rc.executed and rc.status == 200 and CANARY in (rc.body or ""):
            continue  # signature not verified at all -> not a weak-secret finding
        hit_secret = None
        for secret in wordlist:
            tok = forge_hs256({"sub": CANARY, "role": "admin", "exp": future}, secret)
            r = runner.get(
                path,
                session=None,
                headers={"Authorization": f"Bearer {tok}"},
                payload_class="boundary-probe",
                rationale="authz probe: forged HS256 token signed with a weak secret",
                summary="jwt weak-secret probe",
            )
            if r.executed and r.status == 200 and CANARY in (r.body or ""):
                hit_secret = secret
                break
        if hit_secret is None:
            continue
        # Reproduce (2nd independent forge) + test expiry enforcement with an already-expired token.
        rep = forge_hs256({"sub": CANARY, "role": "admin", "exp": future}, hit_secret)
        r2 = runner.get(
            path,
            session=None,
            headers={"Authorization": f"Bearer {rep}"},
            payload_class="boundary-probe",
            rationale="authz reproduce",
            summary="jwt reproduce",
        )
        if not (r2.executed and r2.status == 200 and CANARY in (r2.body or "")):
            continue
        expired = forge_hs256({"sub": CANARY, "role": "admin", "exp": int(time.time()) - 3600}, hit_secret)
        re = runner.get(
            path,
            session=None,
            headers={"Authorization": f"Bearer {expired}"},
            payload_class="boundary-probe",
            rationale="authz: expired token",
            summary="jwt expiry",
        )
        expiry_bypass = bool(re.executed and re.status == 200 and CANARY in (re.body or ""))
        f = _weak_secret_finding(path, target_url, application, engagement_id, hit_secret, expiry_bypass)
        f.assert_consistent()
        findings.append(f)
    return findings


def authz_scan(
    runner, appmodel, target_url, application, engagement_id="", probe_paths=None
) -> list[Finding]:
    """Run all deep auth checks. Returns confirmed findings only (fail-closed)."""
    return jwt_secret_scan(runner, appmodel, target_url, application, engagement_id, probe_paths)
