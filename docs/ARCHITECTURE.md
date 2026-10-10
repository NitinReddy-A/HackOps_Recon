# Architecture

This is a map of how Rampart is put together and why. If you're about to contribute, read this
after the [two rules in CONTRIBUTING.md](../CONTRIBUTING.md#the-two-rules-please-read-before-you-write-code).

## The idea in one sentence

An LLM (or a deterministic rule engine) **proposes** what to test; deterministic code **disposes** —
it gates every action through one safety choke-point, executes only vetted requests, and confirms a
finding only when an independent oracle can re-prove it. Safety and trust are properties of the
*architecture*, not of a prompt.

## The flow of a scan

```
 rampart.scope.yaml                 (1) authorization gate — fail closed if missing/expired/out-of-scope
        │
        ▼
 build the application model         (2) endpoints, roles, seeded principals, object ownership
        │                                (from OpenAPI, a seed file, and/or the crawler)
        ▼
 supervisor proposes hypotheses      (3) "what to test next" — LLM/deterministic, auditable plan
        │
        ▼
 orchestrator fans out (parallel)    (4) each hypothesis → a worker, on a bounded thread pool
        │
        ▼
 worker runs a probe  ───────────▶  POLICY PIPELINE  ───────────▶  executor  ──▶  target
        │                           allowlist → scope → resolved-IP → risk → policy → budget → audit
        ▼                           (fail closed at every step; everything is logged before & after)
 independent oracle validates        (5) re-derive the proof from a clean state, 2+ reproductions,
        │                                negative control — the ONLY thing allowed to say "confirmed"
        ▼                            ┌── (5b) finding-driven escalation (optional, `--deep`): a CONFIRMED
 finding (CWE/OWASP/CVSS + evidence) │       finding deterministically spawns bounded follow-up
        │  ◀──────────────────────────┘       hypotheses (the sibling injection classes on a proven-hot
        ▼                                     parameter; sibling endpoints of a proven-vulnerable object
 correlate · score · compliance (6)           type) — each re-enters at step 4, still gated and
                                              oracle-proven. Hard depth/total/per-finding caps + dedup.
```

The one thing to internalize: **step 4's arrow to the target always goes through the policy
pipeline.** No scanner, agent, or model output reaches the network any other way. (The browser,
gRPC, and infra engines open their own connections — they're the documented exceptions, pointed
only at an already in-scope host.)

## The layers (and which package is which)

### Contracts & safety (the load-bearing core)

| Package | What it does |
| --- | --- |
| `rampart/schemas/` | The `rampart.scope.yaml` scope contract, the `Finding` shape, and the typed `ToolCallRequest`. The vocabulary everything else speaks. |
| `rampart/policy/` | **The single choke-point.** `pipeline.py` runs allowlist → scope → resolved-IP → risk tier → policy engine → budget/rate-limit → execute → audit. Fail-closed. Start here. |
| `rampart/audit/` | Append-only, hash-chained, tamper-evident log of every decision and action. |
| `rampart/executor/` | The only place a request actually goes out: the HTTP client, the seeded-session manager, and secrets resolution. |
| `rampart/evidence/` | Content-addressed, secret-scrubbed evidence store. |

### Discover & confirm

| Package | What it does |
| --- | --- |
| `rampart/appmodel/` | Builds the application model (endpoints, roles, principals, object ownership). |
| `rampart/recon/` | Scope-gated crawler — discovers endpoints/params and fingerprints tech with no spec. |
| `rampart/workers/` | The supervisor (phase state machine) and the per-class workers that gather initial signal. |
| `rampart/validation/` | The **oracles** — independent re-derivation of proof, and the registry that maps a class to its oracle. Only oracles confirm. |
| `rampart/orchestration/` | The DAG task graph + bounded concurrent scheduler that runs the above in parallel, and `escalation.py` — the deterministic, capped, deduped finding-driven deep-scan policy (`--deep`). |

### The checks

| Package | What it does |
| --- | --- |
| `rampart/scanners/` | Built-in safe checks (security headers, misconfig, sensitive files) + external OSS adapters (Nuclei/Nmap/Semgrep/Trivy/testssl → SARIF). |
| `rampart/sast/` | Native Python-AST source scanner + secret scanner. |
| `rampart/sca/` | Full SCA: manifest parsers → OSV.dev → CVSS, plus EPSS/KEV and call-graph reachability. |
| `rampart/iac/` | Static IaC scan (Terraform / CloudFormation / Kubernetes / Dockerfile). |
| `rampart/infra/` | Live, scope-gated exposed-services scan. |
| `rampart/authz/` | Deep auth checks (weak JWT secret, expiry-not-enforced). |
| `rampart/bizlogic/` | Deterministic business-logic checks (economic/parameter tampering). |
| `rampart/apiscan/` | HTTP verb-tampering + GraphQL depth. |
| `rampart/grpc_scan/` | gRPC reflection exposure + per-RPC method checks. |
| `rampart/oob/` | Out-of-band collaborator for blind SSRF/XXE. |
| `rampart/browser/` | Headless-browser engine for DOM & stored XSS. |
| `rampart/llm/` | OWASP LLM Top 10 assessment of an authorized LLM endpoint. |

### Reason, exploit, report

| Package | What it does |
| --- | --- |
| `rampart/intelligence/` | The pluggable reasoning layer: deterministic (default), Claude Code, or any OpenAI-compatible key. See [LLM_AND_API_KEYS.md](LLM_AND_API_KEYS.md). |
| `rampart/agents/` | The multi-agent reasoning harness (planner → explorer → critic) for business-logic flaws, tiered `agent-assessed`. |
| `rampart/exploitation/` | Bounded, non-destructive proof-of-impact for confirmed findings. |
| `rampart/correlation/` | Links findings into attack chains and computes a risk score. |
| `rampart/remediation/` | Advisory patch suggestions (never auto-applied). |
| `rampart/compliance/` | Maps findings to eight frameworks (SOC 2, ISO 27001, PCI DSS, NIST/FedRAMP, HIPAA, GDPR, OWASP ASVS, CIS). |
| `rampart/reporting/` | Findings → JSON / SARIF / Markdown / HTML / SOC 2 / compliance. |
| `rampart/store/` | Run persistence — file-based by default, SQL (SQLite/Postgres) for multi-tenant. |

### Surfaces

| Package | What it does |
| --- | --- |
| `rampart/engagement.py` | The façade that wires everything together for one run. **Every surface below routes through this**, so they all produce identical results. |
| `rampart/cli.py` | The `rampart` command and all its modes. |
| `rampart/sdk.py` | The public Python API — `Rampart(...).scan()` and `ScanResult` ([docs/SDK.md](SDK.md)). |
| `rampart/mcp/` | An MCP server exposing scope-guarded tools to Claude Code and other agents ([docs/MCP.md](MCP.md)). |
| `rampart/server/` | A zero-dependency local web dashboard (`rampart serve`). |
| `rampart/integrations/` | Outbound integrations — e.g. posting a findings summary as a GitHub PR comment. |

## Confidence tiers

Not every finding is equal, and Rampart never pretends otherwise:

1. **`confirmed`** — an independent oracle re-proved it (2+ reproductions, negative control).
2. **`agent-assessed`** — the reasoning layer flagged it; a human should confirm. Never auto-promoted.
3. **external-scanner-lead** — an adapter (Nuclei, etc.) reported it; unvalidated.
4. **static** (SAST/SCA/IaC) — present in source/config; not proven at runtime.

A runtime-`confirmed` finding whose CWE also appears in source gets tagged *source-correlated* —
the strongest signal, "proven at runtime **and** located in code."

## Dependencies

The core has **zero required runtime dependencies** — it's stdlib only, so it runs anywhere and is
easy to audit. Everything heavier is an opt-in extra: `[browser]` (Playwright), `[grpc]` (grpcio),
`[yaml]` (PyYAML, with a strict built-in fallback). Development adds `pytest`, `ruff`, and
`pre-commit` under `[dev]`.
