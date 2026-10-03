# Rampart — positioning & the funding story

*Written for: prospective investors and design partners.*

## One line

**The open-source, self-hostable AppSec agent that finds, _proves_, and helps _fix_ web/API
vulnerabilities in your own authorized apps — combining source + runtime + independent validation
in your CI, without shipping your code or targets to a SaaS.**

## The problem

Application security today forces a bad trade:

- **Scanners (DAST/SAST)** are cheap and self-hostable but drown teams in unvalidated noise —
  independent data shows even the best AI pen-tester produces ~25% non-actionable reports.
- **Autonomous AI pentest platforms** (Parameter, XBOW, Horizon3, Pentera) sell *proof-of-exploit*
  instead of CVSS lists — a genuinely better product — but they are **closed-source SaaS**. You ship
  your code and production targets to a vendor. That is a non-starter for regulated, security-conscious,
  and air-gapped buyers, and it means the tool can never live natively in your own CI.

No incumbent is **open, self-hostable, AND evidence-first**. That's the wedge.

## The wedge (four properties no incumbent occupies together)

1. **Open + self-hostable** — data never leaves your infra.
2. **Validation + evidence** — an independent component re-derives every finding from a clean state before it's "confirmed"; false positives are dropped, not shipped.
3. **Runtime ↔ source correlation + fix loop** — localizes the bug to a code line and proposes a minimal, advisory patch.
4. **Developer-first** — one CLI, SARIF for CI, auditor-ready evidence — not a security-team console.

## Why it's defensible (and safe enough to trust with autonomy)

Two invariants, enforced in code, not prompts:

- **The LLM proposes; deterministic code disposes.** Every action passes one choke-point
  (`allowlist → scope → resolved-IP → risk → policy → sandbox → audit`), fail-closed. A prompt-injected
  model — a demonstrated, ~100%-success attack against naive security agents — can at worst emit
  requests the policy engine rejects. Safety is a property of the architecture.
- **Evidence over alerts.** A separate validator re-derives proof with a deterministic oracle, 2+
  reproductions, and negative controls. This is the same separation-of-duties move XBOW and Horizon3
  call the most important stage of their pipelines — but ours is open and independently benchmarkable.

## What's built today (v0.1, working)

- The full safety choke-point + append-only, hash-chained, tamper-evident audit log.
- The BOLA/IDOR vertical slice **end-to-end**: scope-gate → app model → hypothesis → controlled probe →
  independent validation → schema-valid finding (CWE-639/API1:2023 + CVSS + evidence bundle) →
  advisory patch (never auto-merged) → retest → `Fixed`/`Regression`.
- Safe deterministic checks (security misconfiguration).
- Three intelligence backends: free deterministic default, Claude Code, and bring-your-own-key
  (any OpenAI-compatible provider, incl. fully-local Ollama).
- Reports: JSON, SARIF (CI), Markdown, HTML dashboard, compliance-evidence bundle.
- **Its own reproducible benchmark**: 100% precision/recall on the shipped vulnerable/fixed corpus,
  extensible to OWASP crAPI / VAmPI / Juice Shop.
- 28 automated tests incl. the full A1–A8 acceptance suite.

Chosen for focus: BOLA/IDOR is ~57% of real finding value (per Parameter's public distribution),
so one class proven honestly beats twenty shallow scanners.

## Market context

XBOW hit #1 on HackerOne and raised $75M Series B; Horizon3 reports 260k+ pentests across 6k+
customers; RunSybil ($40M A), Terra ($30M A), Parameter (YC W26). The category is validated and
funded — and it is almost entirely closed SaaS. Open-core + self-host is the un-served segment
(regulated enterprises, defense, anyone who won't send code to a vendor).

## Business model

Apache-2.0 open core (adoption + contribution + trust), open-core commercial layer for teams
(hosted control plane, SSO/RBAC, multi-tenant orchestration, managed scanner fleet, support/SLA).
GPL/AGPL scanners are integrated as separate processes, never linked — clean licensing for a
commercial offering.

## Roadmap to a fundable milestone

External scanner adapters (Nuclei/ZAP/Semgrep/Trivy → SARIF) · more Test-Worker profiles
(reflected-XSS, injection, misconfig) · GitHub Action + MCP server · thin web UI · Postgres +
object-store deployment · published benchmark vs crAPI/VAmPI/Juice Shop.

## The honest guardrail (a feature, not a hedge)

Rampart **augments, does not replace, expert human pentesters**, and generates *evidence of control
effectiveness*, not compliance attestation. Being honest about the ceiling is exactly what earns
trust with security buyers — and it's the credibility the market's self-reported FP claims lack.
