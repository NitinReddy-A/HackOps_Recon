# Rampart

![License](https://img.shields.io/badge/license-Apache--2.0-blue)
![Python](https://img.shields.io/badge/python-3.10%2B-3776AB?logo=python&logoColor=white)
![Runtime deps](https://img.shields.io/badge/runtime%20deps-none-success)
![Tests](https://img.shields.io/badge/tests-100%2B%20passing-brightgreen)
![Benchmark](https://img.shields.io/badge/benchmark-100%25%20precision%20%2F%20recall-brightgreen)
![Coverage](https://img.shields.io/badge/box-black%20%C2%B7%20grey%20%C2%B7%20white-blue)
![Status](https://img.shields.io/badge/status-v0.8-orange)

**Find, _prove_, and help _fix_ web, API, and LLM vulnerabilities in applications you are authorized to test — self-hosted, evidence-first, open source.**

Rampart is an open-source, self-hostable application-security agent. It orchestrates deterministic testing under an LLM planner to reproduce the shape of the commercial *Probe → Exploit → Verify* loop (Parameter, XBOW, Horizon3) — but it runs **inside your own infrastructure**, ships **proof-of-exploit instead of CVSS lists**, and is honest about what it can and cannot do.

> It is a **defensive tool for assets you own or are authorized to test**. It augments — it does not replace — expert human pentesters.

---

## Why Rampart is different

The autonomous-AppSec field is almost entirely closed-source SaaS. Rampart occupies the intersection no incumbent does:

1. **Open + self-hostable** — your code and targets never leave your infra (vs XBOW/NodeZero/Pentera SaaS).
2. **Validation + evidence** — no finding is "confirmed" until an *independent* component re-derives the proof from a clean state. This kills DAST/SAST false-positive noise.
3. **Runtime ↔ source correlation + fix loop** — localizes a bug to a code line and proposes a minimal, *advisory* patch (never auto-merged).
4. **Developer-first** — one CLI command, SARIF for CI, evidence you can hand to an auditor.

Two architectural invariants carry the whole thing:

- **The LLM proposes; deterministic code disposes.** No model output reaches the network or filesystem except as a typed request that has passed a single choke-point: `allowlist → scope → resolved-IP → risk → policy → sandbox → audit`, fail-closed at every stage. A prompt-injected model can, at worst, emit requests the policy engine rejects.
- **Evidence over alerts.** Nothing is `confidence=confirmed` unless a *separate* validator re-derives the proof with a deterministic oracle, 2+ reproductions from clean state, and negative controls.

---

## 60-second demo (no API keys, no Docker, no external targets)

Everything runs against an **intentionally-vulnerable demo app we ship and you own**, on localhost. Nothing touches the internet.

```bash
python scripts/demo.py            # starts the target, runs the assessment, writes the report
```

or drive it yourself:

```bash
# 1. start the intentionally-vulnerable target (a tiny stdlib HTTP API with a real IDOR)
python examples/demo_target/vulnerable_app.py --port 8080 &

# 2. run the flagship assessment: scope-gate → map → hypothesize → validate → remediate → report
python -m rampart test \
  --scope-file examples/demo_target/SECURITY.md \
  --target     http://127.0.0.1:8080 \
  --openapi    examples/demo_target/openapi.json \
  --appmodel-seed examples/demo_target/appmodel_seed.json \
  --repo       examples/demo_target \
  --application demo-shop-api \
  --work-dir   .rampart-demo \
  --report     html,md,json,sarif,compliance

# 3. open .rampart-demo/reports/report.html
```

You'll get output like:

```
  7 confirmed · 4 dropped by FP gate · validation rate 64%
   [HIGH]   Overly permissive CORS policy (wildcard origin with credentials)  ✔ CONFIRMED
   [HIGH]   IDOR/BOLA on GET /api/orders/{id} exposes other users' Orders     ✔ CONFIRMED
   [HIGH]   SQL injection in 'id' on GET /api/products                        ✔ CONFIRMED
   [MEDIUM] Reflected XSS in 'q' on GET /api/search                           ✔ CONFIRMED
   [MEDIUM] Open redirect via 'next' on GET /api/go                           ✔ CONFIRMED
   [MEDIUM] Missing security headers on /                                     ✔ CONFIRMED
   [LOW]    Server software/version disclosure                               ✔ CONFIRMED
   · dropped: SQL injection in 'q' / XSS in 'id' / XSS in 'next' / ...  (oracle killed the non-sinks)
   audit chain: intact · 91 events · cost $0.0 · 0 tokens
```

Note the **dropped** rows: the same broad enumeration proposed SQLi on `q` and XSS on `id`, and the
independent oracle *killed them* because they aren't real sinks. Breadth **with** zero false positives.

**The credibility test:** re-run against the patched build (`--fixed`) and Rampart confirms **nothing** — every candidate across every class is *dropped by the false-positive gate*. Vulnerable → proven; fixed → silent.

### Test an LLM endpoint (OWASP LLM Top 10)

```bash
python scripts/demo.py --llm            # toy local LLM: prompt injection, secret leak, insecure output, jailbreak
# or against your own authorized endpoint:
python -m rampart llm-test --scope-file SECURITY.md --target http://127.0.0.1:9090 \
  --chat-path /chat --input-field message --output-field reply --canary "<secret-in-your-system-prompt>"
```

See [docs/LLM_SECURITY_TESTING.md](docs/LLM_SECURITY_TESTING.md) for the probe list and oracle details.

---

## The flagship: the BOLA/IDOR differential validation oracle

Access-control bugs (BOLA/IDOR) are the highest-value, highest-yield class (Parameter reports authorization + IDOR at ~57% of all findings) — so that's the vertical slice Rampart carries end-to-end. A cross-account `200` is **not** automatically a finding. The deterministic oracle requires all of:

| Check | Why it prevents a false positive |
|---|---|
| cross-account probe returns `200` | there is a response to examine |
| victim's *actual* seeded signature is in the body | not a coincidental 200 / empty body |
| probe body ≠ attacker's own object | not an "echo-your-own-object" endpoint |
| victim reading their own object works | the endpoint functions normally |
| unauthenticated → `401/403` | **authentication is enforced** — the defect is isolated to *ownership* |
| nonexistent id → `403/404` | a generic `200` would mean no real leak |
| ≥ 2 reproductions from **clean** sessions | kills flaky one-off results |

All probes are **Tier 1**: read-only, seeded accounts, seeded objects, no real user data, no state change. Enumerating real ids or writing/deleting is Tier 2 (human approval) or Tier 3 (prohibited).

---

## What Rampart tests

Every class below is confirmed by its **own independent deterministic oracle** (controls + 2+ reproductions). The built-in checks need **zero external tools**; external OSS scanners are optional, opt-in leads.

| Area | Class | CWE / OWASP | Oracle (how it's proven) |
|---|---|---|---|
| API | IDOR / BOLA | CWE-639 · API1:2023 | cross-account read with victim signature + auth-enforced + absent controls |
| Web | Reflected XSS | CWE-79 · A03 | unencoded markup reflected in an HTML context, not in encoded/benign controls |
| Web | SQL injection | CWE-89 · A03 | error-based (quote breaks query) **and** boolean-based (1=1 vs 1=2) differential |
| Web | Open redirect | CWE-601 · A01 | off-site `Location` for attacker URL; local control stays on-site / rejected |
| Web | SSRF | CWE-918 · A10/API7 | server-side fetch reaches internal/metadata; external control does not |
| Web | OS command injection | CWE-78 · A03 | injected benign marker command echoed back, not for a benign control |
| Web | Path traversal | CWE-22 · A01 | `../` reaches an out-of-sandbox file marker; in-sandbox control does not |
| API | Broken function-level authz (BFLA) | CWE-285 · API5 | low-priv principal gets privileged data while auth is still enforced |
| API | Excessive data exposure | CWE-213 · API3 | authed response exposes sensitive fields (PII/secrets) |
| Web | Server-side template injection | CWE-1336 · A03 | `{{1337*1338}}` evaluates to `1788906`; the literal control does not |
| Auth | JWT no-signature-verification (alg=none) | CWE-347 · API2 | a forged alg=none token is accepted while unauth is still rejected |
| API | Mass assignment / BOPLA | CWE-915 · API3/6 | client-supplied privileged field persists (round-trip, `--active`) |
| API | GraphQL introspection | CWE-16 · API8 | `__schema` returned to an anonymous client (`--active`) |
| Web | Host-header injection | CWE-644 · A02 | crafted Host reflected into links/body; legit Host is not |
| Web | CSRF *(passive partial)* | CWE-352 · A01 | cookie session w/o SameSite + state-changing endpoints (human-confirm) |
| Config | Sensitive file exposure | CWE-538 · A02 | `/.env` `/.git/config` `/backup.sql`… served, matched by content signature |
| Config | Missing security headers | CWE-693 · A02 | header absent on 2/2 observations |
| Config | Clickjacking | CWE-1021 · A02 | no X-Frame-Options and no CSP `frame-ancestors` |
| Config | Insecure session cookie | CWE-614/1004 · A02 | Set-Cookie missing HttpOnly/Secure/SameSite |
| Config | Permissive CORS | CWE-942 · A02 | `ACAO:*` **with** `ACAC:true` |
| Config | Version disclosure | CWE-200 · A02 | versioned `Server` header |
| **LLM** | Prompt injection, system-prompt/secret leak, insecure output handling, jailbreak | OWASP **LLM Top 10** (LLM01/05/06) | marker/canary appears for the attack prompt, not for a benign control; reproduced |

External adapters (run with `--scanners`, graceful if not installed): **Nuclei** (DAST templates), **Nmap** (services), **Semgrep** (SAST), **Trivy** (SCA/secrets), **testssl.sh** (TLS). Their results are ingested as *unvalidated leads* — only Rampart's oracles mark a finding `confirmed`. Check what's installed with `rampart tools`.

---

## Recon: works with no OpenAPI spec

Pass `--crawl` (or use `rampart pipeline`) and Rampart discovers the attack surface itself — a scope-gated BFS crawler walks the app over the same policy pipeline, extracting links, form/query parameters and a technology fingerprint, then merges them into the application model. So you can point it at a bare URL:

```bash
python -m rampart pipeline --scope-file SECURITY.md --target http://127.0.0.1:8080
```

## Attack-chain intelligence, live exploitation & risk scoring

Confirmed findings are correlated into **multi-step attack chains** (kill-chains) with an aggregate **risk score (0–100)** and a **prioritized remediation roadmap** — the "so what" that turns a findings list into a pentest narrative. Example chains: *SSRF → cloud metadata → IAM credential theft*, *command injection → RCE → pivot*, *broken authz + over-exposed fields → mass data exfiltration*. Every chain cites the confirmed findings it is built from (it never invents impact).

**Live exploitation (`--exploit`, on in `pipeline`)** goes one step further: for each confirmed finding it runs a **bounded, non-destructive, scope-gated** follow-on that *demonstrates* real impact — enumerates other users' records (IDOR), pulls the privileged dataset (BFLA), retrieves internal metadata (SSRF), reads the out-of-sandbox file (traversal), and proves command execution with a harmless marker (cmdi). Read-only, request-capped, never weaponized — proof of impact, not a weapon.

## The agentic layer — reasoning where no oracle exists

Deterministic oracles can't catch **business-logic** abuse, multi-step **authorization-flow** gaps, or novel bugs, because judging them requires understanding the app's *intended* behaviour. That's what the **multi-agent layer** (`--agents`, needs `--intel claude-code`/`openai-compat`) does: a **planner** proposes objectives, an **explorer** agent runs a bounded ReAct loop (every action a GET through the policy choke-point — gated, audited, read-only), and an **adversarial critic** tries to *disprove* each candidate with a control probe. Survivors are reported as **`agent-assessed`** — an honest tier *below* oracle-`confirmed`, flagged for human review, because the conclusion rests on reasoning, not proof.

```
rampart test --agents --intel claude-code ...     # or pipeline (agents on when a reasoning intel is set)
```

This is how Rampart attacks the part automation usually can't — *with* the discipline to never pass off a reasoned guess as proof. Two capabilities make previously-undetectable classes deterministic again:

- **OOB collaborator (`--oob`)** — a self-hosted loopback callback server turns **blind SSRF** (and, next, blind XXE/deserialization) into a deterministic, out-of-band `confirmed` finding: inject a unique-token URL, observe the server call back.
- **Headless browser (`--browser`, optional `[browser]` extra)** — confirms **DOM-based and stored XSS** by actually executing the page and detecting canary script execution — the classes pure HTTP can't reach.

## One command, a dashboard, and an MCP server

```bash
python -m rampart pipeline --config rampart.yaml      # recon + all classes + chains + full report
python -m rampart serve --work-dir .rampart           # zero-dep local web dashboard on :8787
python -m rampart mcp                                  # MCP stdio server (scope-guarded tools for agents)
```

- **`pipeline`** — the full intense run: scope-gate → crawl → map → every class → correlate → report.
- **`serve`** — a dependency-free local dashboard (risk, chains, findings table, full report, and a scope-gated "run a scan" form).
- **`mcp`** — exposes `rampart_scope_check` / `rampart_scan` / `rampart_llm_test` / `rampart_report` to Claude Code and other agents; every tool still passes the `SECURITY.md` scope gate. Register with `claude mcp add rampart -- python -m rampart.mcp`.
- **`rampart.yaml`** — put `scope_file`, `target`, `intel`, `scanners`, `crawl`, etc. in a config file; CLI flags override it.

## Scan modes — run exactly the check you want (black / grey / white box)

Rampart separates concerns so each capability runs in isolation; `pipeline` composes them.

```bash
rampart recon   --target ...                 # discovery only (crawl + map + fingerprint)
rampart dast    --target ...                 # black-box web/API oracle classes + misconfig
rampart api     --target ... --openapi ...   # API-focused (grey-box with a spec/seed)
rampart sast    --target ... --repo .        # white-box: native AST sinks + secrets + deps + IaC
rampart sca     --target ... --repo . --sca-online   # full SCA: deps matched against OSV.dev
rampart iac     --target ... --repo .        # Terraform / CloudFormation / Kubernetes / Dockerfile
rampart grpc    --target grpc://host:50051   # gRPC server-reflection exposure ([grpc] extra)
rampart infra   --target ...                 # live exposed-services scan (scope-gated TCP)
rampart authz   --target ...                 # deep auth: weak JWT secret, expiry-not-enforced
rampart bizlogic --target ...                # deterministic business-logic (economic/parameter tampering)
rampart apiscan --target ...                 # deep API: HTTP verb tampering, GraphQL depth
rampart llm-test --target ...                # OWASP LLM Top 10
rampart agents  --target ... --intel claude-code   # agentic business-logic reasoning
rampart pipeline --target ... --repo .       # everything, correlated, run in parallel
rampart features                             # list every capability + how to run it
```

**White-box (SAST / full SCA / IaC).** A native, zero-dep Python-AST scanner flags high-signal sinks (command/SQL/code injection, insecure deserialization, SSRF, path traversal, weak crypto, debug-mode) — each only when the dangerous argument is non-constant, to keep false positives low — plus a secret scanner. **Full SCA** (`--sca-online`) parses pinned manifests across ecosystems (PyPI, npm, Go, Maven, RubyGems, crates.io), matches each `name@version` against the **OSV.dev** advisory database, recomputes CVSS from the advisory vector, and emits one finding per vulnerable package with the **concrete minimum upgrade** that clears it. It then enriches each with **EPSS** (exploit probability), **CISA KEV** (actively exploited in the wild), and **import-level reachability** (is the vulnerable package actually imported by your first-party source?), and folds them into an **adjusted severity + P0–P3 priority** — so a reachable, KEV-listed dependency rises to the top while a declared-but-unused transitive one is de-prioritised (querying these external services stays an explicit opt-in). A native **IaC scanner** (`--iac`) flags Terraform / CloudFormation / Kubernetes / Dockerfile misconfigurations (public buckets, open security groups, wildcard IAM, privileged/root containers, `:latest`, `curl | sh`). External SAST/SCA (Opengrep, Bandit, Trivy, gitleaks) plug in via SARIF adapters. **SAST↔DAST correlation** is the differentiator: a runtime-`confirmed` finding whose CWE also appears in source is tagged *source-correlated* — "proven at runtime **and** located in source." Static findings are their own tier (never auto-`confirmed`).

**Depth where it counts — API, auth, business logic, infra.** Beyond the 16 oracle classes: **deep auth** (`--authz`) confirms a weak JWT HMAC secret (forging an admin token after a random-secret control proves the server *does* verify signatures — so it's a weak key, not a missing check) and expiry-not-enforced; **API depth** (`--api-scan`) confirms HTTP verb/method-tampering access-control bypass (via the `X-HTTP-Method-Override` header, non-destructive by default) and flags GraphQL field-suggestion and batching; **business logic** (`--bizlogic`) *deterministically confirms* the classic, testable logic flaws — economic/parameter tampering (negative/zero quantity, zero price) proven by the server's own computed total going non-positive against a positive control (novel logic still needs the agentic layer, honestly tiered `agent-assessed`); and **live infrastructure** (`--infra`) does a scope-gated, non-destructive TCP exposed-services scan (databases, caches, container APIs, message queues) with a closed-port negative control — complementing the static IaC scan with the live half.

**Compliance across eight frameworks.** `--report compliance` maps every finding — deterministically, by CWE → security-domain → control — to **SOC 2, ISO 27001:2022, PCI DSS v4.0, NIST 800-53 Rev5 (the FedRAMP baseline), the HIPAA Security Rule, GDPR, OWASP ASVS, and CIS Controls v8**, with a per-framework control-coverage matrix and open-exception list. `--report soc2` additionally produces Type-2-oriented operating-effectiveness evidence from retest.

**Graph orchestrator (parallel multi-agent).** The scan is no longer a fixed, sequential pipeline: hypotheses, workers, and oracles are nodes in a **DAG scheduled across a bounded thread pool**, so independent hypotheses are tested and validated **in parallel**, and a planner node can **spawn new agent/worker tasks at runtime** (decompose-as-you-go) up to hundreds of concurrent tasks. Concurrency is gated by `--parallel N` (default: the scope's `max_concurrent_workers`); the per-host rate limit and total-request budget remain the real throttle on traffic. Every parallel action still flows through the one deterministic policy choke-point and the (thread-safe, hash-chained) audit log — so a parallel run yields the **same confirmed findings** as a sequential one, proven in the test suite. Concurrency changes throughput, never the evidence or safety guarantees.

**Hardened agent harness.** The reasoning agents run under a reliability layer: every LLM decision is schema-validated with one self-repair, repeated actions are detected as loops and halt the objective, and **every planned objective gets a recorded outcome** (coverage) so nothing is silently missed — all auditable in the run record.

## SOC 2 evidence (not an attestation)

`--report soc2` (and `pipeline`) writes `soc2.md` — findings mapped to the SOC 2 **Trust Services Criteria** (CC6.1/6.3/6.6/6.8, CC7.1, CC8.1): a control-coverage summary, open control *exceptions* with remediation, and an **operating-effectiveness** section fed by `rampart retest` (confirmed→Fixed before/after is the before/after evidence a **Type 2** examination relies on). It is **evidence for your auditor, not a SOC 2 report** — only a licensed CPA firm issues that, and a Type 2 opinion needs evidence across the full review period. Hand the auditor this report plus the hash-chained audit log and evidence bundle.

---

## Intelligence: use Claude Code, bring your own key, or run fully deterministic

The reasoning layer ("LLM proposes") is pluggable and **strictly advisory** — every suggestion is re-checked by the deterministic pipeline and the validator, and LLM-proposed hypotheses are dropped if they reference endpoints/objects we didn't actually discover (anti-hallucination).

Rampart runs as a **multi-agent pipeline** — `mapper → planner → specialists (BOLA / injection / LLM) → validator → reporter`. With `--intel claude-code`, the planner, specialist and reporter roles each run as a separate headless `claude -p` call; the **validator and policy pipeline are deliberately never an LLM** (pure deterministic code), which is what keeps the safety guarantees true under a prompt-injected model.

| `--intel` | What it uses | Cost | Setup |
|---|---|---|---|
| `deterministic` *(default)* | rule-based heuristics, no LLM | free | none |
| `claude-code` | your local `claude` CLI (Claude Code) | your Claude plan | `claude` on PATH |
| `openai-compat` | **any** OpenAI-compatible API | your key | env vars (below) |

Bring your own key (works with OpenAI, OpenRouter, Groq, Together, a self-hosted LiteLLM gateway, or fully-local Ollama):

```bash
export RAMPART_LLM_BASE_URL="https://api.openai.com/v1"   # or openrouter/groq/ollama/litellm
export RAMPART_LLM_MODEL="gpt-4o-mini"
export OPENAI_API_KEY="sk-..."                            # or RAMPART_LLM_API_KEY=...
python -m rampart test --intel openai-compat ...
```

See [docs/LLM_AND_API_KEYS.md](docs/LLM_AND_API_KEYS.md) for model recommendations and **free** options for initial testing.

---

## Reliability benchmark

Rampart ships its own reproducible benchmark (the credibility gap the market leaves open — most vendors self-report FP rates):

```bash
python benchmarks/run_benchmark.py --runs 5
```

```
  Precision : 100.0%   (FP=0)
  Recall    : 100.0%   (FN=0)
  F1        : 100.0%
  MTT-find  : 0.18s
```

The harness runs the target in VULNERABLE and FIXED modes (a VAmPI-style on/off switch), scores confirmed findings against ground truth, and writes `benchmarks/results.json`. The design extends to OWASP crAPI / VAmPI / Juice Shop fixtures.

---

## Safety model (safe-by-default, not a disclaimer)

- **R1 — Authorization gate.** No run without a valid, unexpired, in-scope `SECURITY.md` naming an accountable owner. Fail-closed.
- **R2 — Structural scope enforcement.** Every request traverses the single choke-point; no agent code can bypass it.
- **R3/R4 — Non-destructive by default.** Writes/state-change require human approval (Tier 2); DoS/destructive/exfil are prohibited (Tier 3).
- **R5 — Independent validation** before `confirmed`.
- **R6 — Append-only, hash-chained audit log.** `rampart verify-audit` recomputes the chain and detects tampering.
- **R7 — Advisory remediation.** Patches are written as `.patch` artifacts; Rampart never auto-applies or merges.
- **R9 — Untrusted target data.** Target output is treated as data, never as instructions (indirect prompt-injection defense).
- **R10 — Budget & kill-switch.** Per-host rate limits, total caps, and a kill switch.

Full threat model and rationale: this repo's blueprint at `reports/Open source AppSec platform blueprint.md`.

---

## Architecture

```
CLI / serve / mcp ─► Engagement ─► recon(crawl) ─► Supervisor
                         │                 (map → hypothesize → PLAN → test → validate → scan → correlate)
   intelligence (advisory) │          deterministic spine (enforces everything)
   ├ deterministic         │          ├ policy/ ── allowlist → scope → risk → engine → pipeline (choke-point)
   ├ claude-code (multi-agent)│       ├ executor/ ─ gated HTTP client + seeded-session manager
   └ openai-compat         │          ├ audit/ ──── append-only hash-chained log
                           ▼          ├ evidence/ ─ content-addressed, secret-scrubbed store
   workers/ (per class)    │          ├ validation/ ─ oracle REGISTRY + FP gate (separation of duties)
   ├ bola-idor  ├ web (xss/sqli/redirect/ssrf/cmdi/traversal/bfla/exposure)│ correlation/ ─ chains + risk
   └ llm (OWASP LLM Top 10) │          ├ scanners/ ─ built-in misconfig + external adapters (nuclei/nmap/…)
                           ▼          └ reporting/ ─ JSON · SARIF · Markdown · HTML · compliance
                     Validator ──────► (only an independent oracle may mark a finding "confirmed")
```

Repo map: [`rampart/`](rampart) (package) · [`rampart/recon/`](rampart/recon) (crawler) · [`rampart/orchestration/`](rampart/orchestration) (graph scheduler) · [`rampart/agents/`](rampart/agents) (multi-agent reasoning) · [`rampart/exploitation/`](rampart/exploitation) (live impact) · [`rampart/correlation/`](rampart/correlation) (chains + risk) · [`rampart/oob/`](rampart/oob) (blind-SSRF collaborator) · [`rampart/browser/`](rampart/browser) (DOM/stored XSS) · [`rampart/sca/`](rampart/sca) (OSV SCA + EPSS/KEV/reachability) · [`rampart/iac/`](rampart/iac) (cloud-config) · [`rampart/infra/`](rampart/infra) (live exposed-services) · [`rampart/grpc_scan/`](rampart/grpc_scan) (gRPC) · [`rampart/authz/`](rampart/authz) (deep auth) · [`rampart/bizlogic/`](rampart/bizlogic) (business logic) · [`rampart/apiscan/`](rampart/apiscan) (API depth) · [`rampart/compliance/`](rampart/compliance) (8-framework mapping) · [`rampart/llm/`](rampart/llm) · [`rampart/scanners/adapters/`](rampart/scanners/adapters) · [`rampart/server/`](rampart/server) (dashboard) · [`rampart/mcp/`](rampart/mcp) · [`tests/`](tests) · [`benchmarks/`](benchmarks).

---

## Honesty (what this is not, yet)

- It proves **16 web/API classes + the OWASP LLM Top 10** behind independent oracles, confirms **blind SSRF** out-of-band and **DOM/stored XSS** in a real browser, correlates everything into attack chains, **demonstrates** bounded impact, and adds an **agentic layer** for business-logic / auth-flow reasoning.
- The agentic layer **narrows but does not erase** the human gap. Truly novel logic and deep design flaws still need a human — and Rampart is honest about it: agent-reasoned issues are tiered **`agent-assessed` (human review)**, never silently promoted to `confirmed`. This is why PCI/SOC 2 still mandate manual testing, and why Rampart's value is a **best-in-class low-noise first pass + continuous regression + SOC 2 evidence** layer that makes a human pentester far faster — not a one-click "you're secure" button.
- Still roadmap: mass assignment/BOPLA write-side, CSRF, GraphQL, blind XXE/deserialization (OOB server is in place), host-header/smuggling.
- External-scanner results are **unvalidated leads**; agent findings are **agent-assessed** — both clearly separated from oracle-`confirmed`.
- It generates **evidence of control effectiveness**, not a compliance attestation.

## Progress

**Implemented (working, tested, benchmarked):**
- ✅ Authorization gate — parses & enforces the `SECURITY.md` scope contract (fail-closed, auto-expiry)
- ✅ Deterministic safety choke-point — `allowlist → scope → resolved-IP → risk → policy → sandbox → audit`
- ✅ Four-tier action risk classifier with HITL approval for Tier 2 and hard-deny for Tier 3
- ✅ Append-only, hash-chained, tamper-evident audit log (`rampart verify-audit`)
- ✅ **Recon crawler** — discovers endpoints/params + tech fingerprint with no OpenAPI spec (`--crawl`)
- ✅ Application model (endpoints, roles, seeded principals, object ownership) from OpenAPI + seed + crawl
- ✅ **16 web/API classes**, each behind an **independent oracle**: IDOR/BOLA, reflected XSS, SQLi, open redirect, SSRF, OS command injection, path traversal, BFLA, excessive data exposure, SSTI, JWT alg=none, sensitive-file exposure, clickjacking, insecure cookies, CORS, version/header misconfig
- ✅ **LLM VAPT track** — OWASP LLM Top 10 probes with a marker/canary oracle (`rampart llm-test`)
- ✅ **Attack-chain correlation + live exploitation (demonstrated impact) + risk score (0–100) + remediation roadmap**
- ✅ **Agentic reasoning layer** (`--agents`) — planner → explorer → adversarial critic for business-logic / auth-flow flaws, tiered `agent-assessed` (never auto-`confirmed`); scripted-brain tested, real LLM wired
- ✅ **OOB collaborator** (`--oob`) — deterministic **blind-SSRF** confirmation via out-of-band callback
- ✅ **Headless-browser engine** (`--browser`, optional) — **DOM & stored XSS** via real script-execution detection
- ✅ **Graph orchestrator** (`--parallel N`) — DAG-scheduled, **parallel** hypothesis/worker/oracle fan-out with runtime subagent spawning (hundreds of concurrent tasks); thread-safe audit chain; parallel ≡ sequential findings
- ✅ **Full SCA** (`--sca-online`) — pinned deps (PyPI/npm/Go/Maven/RubyGems/crates.io) matched against **OSV.dev**, CVSS recomputed, **EPSS + CISA KEV + import-level reachability → adjusted P0–P3 priority**, **concrete upgrade** remediation per package
- ✅ **IaC / cloud-config scan** (`--iac`) — Terraform / CloudFormation / Kubernetes / Dockerfile misconfig (public buckets, open SGs, wildcard IAM, privileged/root containers)
- ✅ **Live infrastructure scan** (`--infra`) — scope-gated, non-destructive exposed-services detection (DBs, caches, container APIs, queues) with a closed-port negative control
- ✅ **Deep auth** (`--authz`) — weak JWT HMAC secret (with a random-secret control) + expiry-not-enforced, confirmed
- ✅ **Deterministic business logic** (`--bizlogic`) — economic/parameter tampering (negative/zero quantity, zero price) confirmed by the server's own computed total
- ✅ **API depth** (`--api-scan`) — HTTP verb/method-tampering access-control bypass (confirmed) + GraphQL field-suggestion/batching (firm)
- ✅ **gRPC scan** (`--grpc`, optional `[grpc]` extra) — server-reflection exposure (analogous to GraphQL introspection)
- ✅ **Compliance across 8 frameworks** (`--report compliance`) — SOC 2, ISO 27001:2022, PCI DSS v4.0, NIST 800-53 Rev5 (FedRAMP), HIPAA, GDPR, OWASP ASVS, CIS — CWE-mapped control-coverage matrix
- ✅ **SOC 2 evidence report** — Trust Services Criteria mapping + retest operating-effectiveness evidence (`--report soc2`)
- ✅ **External OSS scanner adapters** (Nuclei / Nmap / Semgrep / Trivy / testssl → normalized), graceful + `rampart tools` doctor
- ✅ **Multi-agent pipeline** (mapper → planner → specialists → validator → reporter); Claude Code / BYO-key / deterministic
- ✅ **One-command `pipeline`**, a **zero-dep web dashboard (`serve`)**, and an **MCP server (`mcp`)** for agents
- ✅ Config file (`rampart.yaml`), runtime↔source correlation + **advisory** patch → retest → `Fixed`/`Regression`
- ✅ Reports: JSON · SARIF · Markdown · HTML dashboard (executive summary, coverage, attack chains, roadmap) · compliance bundle
- ✅ CI matrix + composite GitHub Action + Dockerfile/compose
- ✅ Reproducible benchmark — **100% precision/recall across all 10 web/API ground-truth classes**, vulnerable and fixed · 63 tests

**Done since:** ✅ DOM & stored XSS (headless browser) · ✅ OOB collaborator (blind SSRF) · ✅ mass
assignment/BOPLA, GraphQL, host-header injection, CSRF (passive partial) · ✅ GitLab CI template ·
✅ external vulnerable-app benchmark guide (crAPI/VAmPI/Juice Shop).

**Done since:** ✅ **Blind XXE over OOB** (external-entity → collaborator callback, `--active`) ·
✅ **stored-XSS write-half** (store payload → render in headless browser) · ✅ request-smuggling
**passive indicator** (intermediary-detected → manual-review; never actively desynced) ·
✅ **diff-aware SAST** (`--since <ref>` scans only changed files) · ✅ **multi-tenant SQL store**
(`--store sqlite:///… | postgresql://…`) · ✅ **automated external-corpus scoring**
(`benchmarks/corpus_runner.py` + VAmPI CI workflow).

**Remaining (next):**
- ☐ Deserialization: black-box is surfaced white-box (CWE-502 SAST) + OOB class-probe; gadget-chain confirmation stays human-only
- ☐ Object-store for evidence blobs in the multi-tenant deploy (DB docs done; evidence/audit still file-based)
- ☐ Richer PR-annotation (inline review comments) beyond the SARIF code-scanning upload

## License

Apache-2.0. See [LICENSE](LICENSE). GPL/AGPL scanners integrate as separate processes, never linked.

---

## CI / Docker / GitHub Action

Rampart ships self-contained deployment infra. Everything runs on the dependency-free core, so these stay small and fast.

**Local dev (Makefile).** Common tasks are wrapped for convenience:

```bash
make install     # pip install -e .
make test        # python -m pytest
make bench       # python benchmarks/run_benchmark.py  (nonzero exit on FP/FN)
make demo        # scripts/demo.py --no-open   (web/API)
make demo-llm    # scripts/demo.py --llm --no-open
make tools       # rampart tools  (external-scanner doctor)
make docker-build
make lint        # python -m compileall rampart
```

**Project CI (`.github/workflows/ci.yml`).** Matrix tests on Python 3.10 / 3.11 / 3.12, then the benchmark as a hard gate. It installs dev extras with a fallback:

```bash
pip install -e ".[dev]"   # provides pytest via the [dev] extra if configured
# otherwise:
pip install -e . && pip install pytest
```

**Scan your own target in CI.** Two copy-paste paths, both uploading SARIF to the GitHub Security tab:

- `.github/workflows/rampart-scan.yml` — a documented template workflow you copy into your repo.
- `action.yml` — a composite **"Rampart AppSec Scan"** Action:

  ```yaml
  - uses: your-org/rampart@v0.3
    with:
      target: https://staging.example.com   # authorized target (required)
      scope-file: SECURITY.md
      fail-on: high
  - uses: github/codeql-action/upload-sarif@v3
    with:
      sarif_file: ${{ steps.rampart.outputs.sarif-path }}
  ```

  Inputs: `scope-file` (default `SECURITY.md`), `target` (required), `report` (default `sarif`), `fail-on` (default `high`), `scanners` (default none), `work-dir` (default `.rampart`). Output: `sarif-path`. The SARIF lands at `<work-dir>/reports/report.sarif`.

**Docker.** A multi-stage, non-root `python:3.12-slim` image with zero runtime deps:

```bash
docker build -t rampart:local .
docker run --rm -v "$PWD:/work" rampart:local \
  test --scope-file SECURITY.md --target http://host.docker.internal:8080 --report html,md,sarif
# or via compose:
docker compose run --rm rampart test --scope-file SECURITY.md --target ... --report sarif
```

External scanners (nuclei / semgrep / nmap / trivy / testssl.sh) are **optional** and not bundled — layer them into a derived image if you want the `--scanners` adapters. The `rampart-dashboard` service in `docker-compose.yml` runs `rampart serve` (the local dashboard) on port 8787.
