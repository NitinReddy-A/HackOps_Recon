"""Self-contained API-depth scanner: HTTP method/verb tampering + safe GraphQL depth checks.

Two complementary API-security probes that close an API-depth gap:

* :func:`method_tampering_scan` — detects method-based access-control bypass
  (CWE-650 "Trusting HTTP Permission Methods on the Server Side" / CWE-285 Improper
  Authorization / OWASP API5:2023 BFLA-via-verb). It emits a runtime-``confirmed`` Finding
  only when an unauthenticated request carrying an ``X-HTTP-Method-Override`` header flips a
  genuinely-denied canonical request into a 2xx with real content, re-derived against a
  negative control and reproduced 2+ times. NON-DESTRUCTIVE by default: the override header
  lets us probe the authz decision WITHOUT issuing a destructive verb; real PUT/DELETE/PATCH
  (tunnelled over a gated POST) run only when ``active=True``.

* :func:`graphql_depth_scan` — SAFE, honest ``firm`` indicators (never ``confirmed``):
  field-suggestion leakage ("Did you mean …?") and query batching / alias amplification.

All HTTP goes through the policy-gated, audited :class:`~rampart.runner.ProbeRunner`.
"""
from .scanner import api_scan, graphql_depth_scan, method_tampering_scan

__all__ = ["api_scan", "graphql_depth_scan", "method_tampering_scan"]
