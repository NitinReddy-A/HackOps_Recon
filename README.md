# Rampart

![License](https://img.shields.io/badge/license-Apache--2.0-blue)
![Python](https://img.shields.io/badge/python-3.10%2B-3776AB?logo=python&logoColor=white)
![Runtime deps](https://img.shields.io/badge/runtime%20deps-none-success)
![Tests](https://img.shields.io/badge/tests-42%20passing-brightgreen)
![Benchmark](https://img.shields.io/badge/benchmark-100%25%20precision%20%2F%20recall-brightgreen)
![Coverage](https://img.shields.io/badge/classes-web%20%C2%B7%20API%20%C2%B7%20LLM-blue)
![Status](https://img.shields.io/badge/status-v0.2-orange)

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
| Config | Missing security headers | CWE-693 · A02 | header absent on 2/2 observations |
| Config | Permissive CORS | CWE-942 · A02 | `ACAO:*` **with** `ACAC:true` |
| Config | Version disclosure | CWE-200 · A02 | versioned `Server` header |
| **LLM** | Prompt injection, system-prompt/secret leak, insecure output handling, jailbreak | OWASP **LLM Top 10** (LLM01/05/06) | marker/canary appears for the attack prompt, not for a benign control; reproduced |

External adapters (run with `--scanners`, graceful if not installed): **Nuclei** (DAST templates), **Nmap** (services), **Semgrep** (SAST), **Trivy** (SCA/secrets), **testssl.sh** (TLS). Their results are ingested as *unvalidated leads* — only Rampart's oracles mark a finding `confirmed`. Check what's installed with `rampart tools`.

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
CLI ─► Engagement ─► Supervisor (recon → map → hypothesize → PLAN → test → validate → scan)
                         │
   intelligence (advisory) │          deterministic spine (enforces everything)
   ├ deterministic         │          ├ policy/ ── allowlist → scope → risk → engine → pipeline (choke-point)
   ├ claude-code (multi-agent)│       ├ executor/ ─ gated HTTP client + seeded-session manager
   └ openai-compat         │          ├ audit/ ──── append-only hash-chained log
                           ▼          ├ evidence/ ─ content-addressed, secret-scrubbed store
   workers/ (per class)    │          ├ validation/ ─ oracle REGISTRY + FP gate (separation of duties)
   ├ bola-idor  ├ web (xss/sqli/redirect)│  remediation/ ─ source correlation + advisory patch
   └ llm (OWASP LLM Top 10) │          ├ scanners/ ─ built-in misconfig + external adapters (nuclei/nmap/…)
                           ▼          └ reporting/ ─ JSON · SARIF · Markdown · HTML · compliance
                     Validator ──────► (only an independent oracle may mark a finding "confirmed")
```

Repo map: [`rampart/`](rampart) (package) · [`rampart/llm/`](rampart/llm) (LLM Top-10) · [`rampart/scanners/adapters/`](rampart/scanners/adapters) (external tools) · [`examples/demo_target/`](examples/demo_target) (owned web + LLM targets) · [`tests/`](tests) (A1–A8 + web/LLM/adapter coverage) · [`benchmarks/`](benchmarks) · [`docs/`](docs).

---

## Honesty (what this is not, yet)

- It does **not** replace human pentesters — humans remain best at creative/business-logic flaws.
- It proves several classes end-to-end (BOLA/IDOR, XSS, SQLi, open redirect, misconfig, and the OWASP LLM Top 10) each behind an independent oracle. It does not yet do autonomous multi-step exploit *chaining*, cover all 22 weakness classes, or match commercial infra/lateral-movement breadth.
- External-scanner results are **unvalidated leads**, clearly separated from oracle-confirmed findings.
- It generates **evidence of control effectiveness**, not a compliance attestation.

## Progress

**Implemented (v0.1 — working, tested, benchmarked):**
- ✅ Authorization gate — parses & enforces the `SECURITY.md` scope contract (fail-closed, auto-expiry)
- ✅ Deterministic safety choke-point — `allowlist → scope → resolved-IP → risk → policy → sandbox → audit`
- ✅ Four-tier action risk classifier with HITL approval for Tier 2 and hard-deny for Tier 3
- ✅ Append-only, hash-chained, tamper-evident audit log (`rampart verify-audit`)
- ✅ Application model (endpoints, roles, seeded principals, object ownership) from OpenAPI + seed
- ✅ Multi-class coverage, each behind an **independent oracle** (2+ reproductions + negative controls): BOLA/IDOR, reflected XSS, SQL injection, open redirect, plus CORS / version-disclosure / header misconfig
- ✅ **LLM VAPT track** — OWASP LLM Top 10 probes (prompt injection, system-prompt/secret leak, insecure output handling, jailbreak) with a marker/canary oracle (`rampart llm-test`)
- ✅ **External OSS scanner adapters** (Nuclei / Nmap / Semgrep / Trivy / testssl → normalized), graceful when not installed, with a `rampart tools` doctor
- ✅ **Multi-agent pipeline** (mapper → planner → specialists → validator → reporter); Claude Code / BYO-key / deterministic backends
- ✅ Runtime↔source correlation + **advisory** minimal patch (never auto-applied) → retest → `Fixed`/`Regression`
- ✅ Reports: JSON · SARIF · Markdown · HTML dashboard (now with coverage & methodology) · compliance bundle
- ✅ Reproducible reliability benchmark — **100% precision/recall across all 5 web/API classes**, both vulnerable and fixed
- ✅ Automated test suite (A1–A8 acceptance + web-class, LLM, and adapter coverage)

**Remaining (next):**
- ☐ Autonomous multi-step exploit chaining across classes
- ☐ GitHub Action + GitLab CI templates (SARIF upload, PR annotations, diff-aware runs)
- ☐ First-party MCP server (scope-guarded tools for Claude Code / agents)
- ☐ Thin web UI (live run view, finding triage, evidence rendering)
- ☐ Multi-tenant deployment (Postgres + object storage + per-engagement sandbox)
- ☐ Expanded benchmark corpus (OWASP crAPI / VAmPI / Juice Shop fixtures)

## License

Apache-2.0. See [LICENSE](LICENSE). GPL/AGPL scanners integrate as separate processes, never linked.
