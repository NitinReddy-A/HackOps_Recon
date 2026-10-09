"""Typed, dependency-free schemas — the load-bearing contracts (blueprint section 30).

These are frozen early because everything else depends on them:

* :mod:`rampart.schemas.scope`     - the ``rampart.scope.yaml`` authorization contract (R1 gate)
* :mod:`rampart.schemas.toolcall`  - the typed tool-call request + policy decision (invariant 1)
* :mod:`rampart.schemas.appmodel`  - the application model that makes BOLA/IDOR decidable
* :mod:`rampart.schemas.finding`   - the SARIF-exportable finding + evidence bundle
* :mod:`rampart.schemas.audit`     - the append-only, hash-chained audit event
"""
