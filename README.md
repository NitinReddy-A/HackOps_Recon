# Rampart

**Find, _prove_, and help _fix_ web/API vulnerabilities in applications you are authorized to test — self-hosted, evidence-first, open source.**

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
  [      recon] liveness GET / -> 200
  [        map] 2 endpoints, 1 ownable, 2 seeded principals
  [       test] security-headers check produced 1 finding(s)
  [hypothesize] 1 hypothesis(es) proposed by deterministic
  [   validate] evidence found; handing to independent validator
  [   validate] validator verdict: CONFIRMED (2 reproductions)

  Results
   2 confirmed · 0 dropped by FP gate · validation rate 100%
   [HIGH]   IDOR/BOLA on GET /api/orders/{id} exposes other users' Orders ✔ CONFIRMED
   [MEDIUM] Missing security headers on / ✔ CONFIRMED
   audit chain: intact · 29 events · cost $0.0 · 0 tokens
```

**The credibility test:** re-run against the patched build (`--fixed`) and Rampart reports **nothing** — the IDOR candidate is *dropped by the false-positive gate*, not confirmed. Vulnerable → proven; fixed → silent.

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

## Intelligence: use Claude Code, bring your own key, or run fully deterministic

The reasoning layer ("LLM proposes") is pluggable and **strictly advisory** — every suggestion is re-checked by the deterministic pipeline and the validator, and LLM-proposed hypotheses are dropped if they reference endpoints/objects we didn't actually discover (anti-hallucination).

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
CLI ─► Engagement ─► Supervisor (phase state machine: recon → map → hypothesize → test → validate)
                         │
   intelligence (advisory) │           deterministic spine (enforces everything)
   ├ deterministic         │           ├ policy/ ── allowlist → scope → risk → engine → pipeline (choke-point)
   ├ claude-code           │           ├ executor/ ─ gated HTTP client + seeded-session manager
   └ openai-compat         │           ├ audit/ ──── append-only hash-chained log
                           ▼           ├ evidence/ ─ content-addressed, secret-scrubbed store
              Test Worker (bola-idor)  ├ validation/ ─ independent oracle + FP gate (separation of duties)
                           ▼           ├ remediation/ ─ source correlation + advisory patch
                     Validator ────────► reporting/ ─ JSON · SARIF · Markdown · HTML · compliance
```

Repo map: [`rampart/`](rampart) (package) · [`examples/demo_target/`](examples/demo_target) (the owned target) · [`tests/`](tests) (28 tests, A1–A8 acceptance) · [`benchmarks/`](benchmarks) · [`docs/`](docs).

---

## Honesty (what this is not, yet)

- It does **not** replace human pentesters — humans remain best at creative/business-logic flaws.
- The MVP proves **one class end-to-end** (BOLA/IDOR) plus safe misconfiguration checks. It does not yet cover all 22 weakness classes, do autonomous multi-step exploit chaining, or match commercial infra/lateral-movement breadth.
- It generates **evidence of control effectiveness**, not a compliance attestation.

## Progress

**Implemented (v0.1 — working, tested, benchmarked):**
- ✅ Authorization gate — parses & enforces the `SECURITY.md` scope contract (fail-closed, auto-expiry)
- ✅ Deterministic safety choke-point — `allowlist → scope → resolved-IP → risk → policy → sandbox → audit`
- ✅ Four-tier action risk classifier with HITL approval for Tier 2 and hard-deny for Tier 3
- ✅ Append-only, hash-chained, tamper-evident audit log (`rampart verify-audit`)
- ✅ Application model (endpoints, roles, seeded principals, object ownership) from OpenAPI + seed
- ✅ BOLA/IDOR vertical slice end-to-end: hypothesis → controlled probe → **independent validation** (2+ reproductions + negative controls) → confirmed finding
- ✅ Safe deterministic checks (security-header / misconfiguration)
- ✅ Runtime↔source correlation + **advisory** minimal patch (never auto-applied) → retest → `Fixed`/`Regression`
- ✅ Three intelligence backends: deterministic (default, free), Claude Code, bring-your-own-key (OpenAI-compatible / Ollama)
- ✅ Reports: JSON · SARIF · Markdown · HTML dashboard · compliance-evidence bundle
- ✅ Reproducible reliability benchmark (100% precision/recall on the shipped corpus)
- ✅ 28 automated tests incl. the full A1–A8 acceptance suite

**Remaining (next):**
- ☐ External scanner adapters (Nuclei / ZAP / Semgrep / Trivy → SARIF normalization)
- ☐ More Test-Worker class profiles (reflected/stored XSS, injection, auth, SSRF)
- ☐ GitHub Action + GitLab CI templates (SARIF upload, PR annotations, diff-aware runs)
- ☐ First-party MCP server (scope-guarded tools for Claude Code / agents)
- ☐ Thin web UI (live run view, finding triage, evidence rendering)
- ☐ Multi-tenant deployment (Postgres + object storage + per-engagement sandbox)
- ☐ Expanded benchmark corpus (OWASP crAPI / VAmPI / Juice Shop fixtures)

## License

Apache-2.0. See [LICENSE](LICENSE). GPL/AGPL scanners integrate as separate processes, never linked.
