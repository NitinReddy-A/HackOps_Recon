# Rampart

![License](https://img.shields.io/badge/license-Apache--2.0-blue)
![Python](https://img.shields.io/badge/python-3.10%2B-3776AB?logo=python&logoColor=white)
![Runtime deps](https://img.shields.io/badge/runtime%20deps-none-success)
![Tests](https://img.shields.io/badge/tests-197%20passing-brightgreen)
![Benchmark](https://img.shields.io/badge/benchmark-100%25%20precision%20%2F%20recall-brightgreen)

Rampart finds, **proves**, and helps you **fix** security bugs in web apps, APIs, and LLM
endpoints you're authorized to test. It's the open, self-hostable alternative to the commercial
"autonomous pentest" tools — it runs on your own machines, and it hands you a working proof for
every confirmed finding instead of a pile of maybe-vulnerabilities to triage.

> Rampart is a tool for **authorized testing only** — assets you own or have explicit permission
> to test. It's built to make a human pentester faster, not to replace one.

## What makes it different

- **It runs where you do.** Your code and your targets never leave your infrastructure. The core
  has zero runtime dependencies — it's standard-library Python, so it's easy to install and easy
  to audit.
- **It proves findings instead of guessing.** Nothing is marked `confirmed` until a separate,
  independent oracle re-derives the proof from a clean state, with repeated runs and a negative
  control. That's what keeps the false-positive rate at zero on the benchmark.
- **It's safe by construction.** Every request an agent or scanner wants to make is a typed
  request that passes through one choke-point — scope check, IP allowlist, risk tier, policy,
  budget — and fails closed. A prompt-injected model can, at worst, emit requests the policy
  engine rejects.
- **It's honest.** Reasoned-but-unproven findings are labelled `agent-assessed`, not `confirmed`.
  External-scanner results are labelled as unvalidated leads. The reports say what Rampart knows
  and what it doesn't.

## Requirements

- **Python 3.10 or newer.** That's it for the core.
- Optional extras, only if you want them: a headless browser (Playwright) for DOM/stored XSS,
  `grpcio` for gRPC scanning, and a `claude` CLI or an LLM API key for the reasoning layer.

## Install

```bash
git clone https://github.com/NitinReddy-A/HackOps_Recon.git
cd HackOps_Recon
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e .
```

That gives you the `rampart` command (same as `python -m rampart`).

## Try it in 60 seconds

Rampart ships a small, intentionally-vulnerable app so you can see it work without pointing it at
anything real. This runs entirely on localhost and never touches the internet:

```bash
python scripts/demo.py
```

It starts the demo target, runs a full assessment, and writes an HTML report. You'll see something
like:

```
  7 confirmed · 4 dropped by the false-positive gate
   [HIGH]   IDOR/BOLA on GET /api/orders/{id} exposes other users' orders   ✔ confirmed
   [HIGH]   SQL injection in 'id' on GET /api/products                       ✔ confirmed
   [MEDIUM] Reflected XSS in 'q' on GET /api/search                          ✔ confirmed
   ...
   · dropped: SQLi in 'q', XSS in 'id', ...  (the oracle killed the non-sinks)
   audit chain: intact · 91 events · cost $0.00
```

The dropped rows are the point: the same broad enumeration *also* guessed SQLi on `q` and XSS on
`id`, and the independent oracle threw them out because they aren't real sinks. Re-run against the
patched build and Rampart confirms nothing at all — vulnerable → proven, fixed → silent.

To drive it yourself:

```bash
# 1. start the vulnerable target
python examples/demo_target/vulnerable_app.py --port 8080 &

# 2. run an assessment
rampart test \
  --scope-file examples/demo_target/rampart.scope.yaml \
  --target     http://127.0.0.1:8080 \
  --openapi    examples/demo_target/openapi.json \
  --appmodel-seed examples/demo_target/appmodel_seed.json \
  --repo       examples/demo_target \
  --report     html,md,json,sarif

# 3. open .rampart/reports/report.html
```

## How a scan works

Every run follows the same shape. The important part is that the arrow to your target *always*
goes through the policy choke-point — nothing gets out any other way.

```
rampart.scope.yaml ─► authorization gate (fail closed)
      └─► build the app model (endpoints, roles, seeded accounts)
            └─► propose what to test  ─► orchestrator runs checks in parallel
                  └─► each probe ─► POLICY PIPELINE ─► target
                        (scope · IP · risk · policy · budget · audit)
                        └─► an independent oracle re-proves it ─► confirmed finding
                              └─► correlate · score risk · map to compliance · report
```

You point Rampart at a target three ways, and you can mix them:

- **Black-box** — just a URL (and credentials, if you have them).
- **Grey-box** — add an OpenAPI spec and/or a seed file describing accounts and object ownership.
- **White-box** — add `--repo` to turn on source scanning and runtime↔source correlation.

The full picture of how the code is organized is in
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## What it tests

Each class below is confirmed by its own independent oracle — a probe, a negative control, and at
least two reproductions from a clean state. The built-in checks need no external tools.

**Web & API:** IDOR/BOLA, reflected XSS, SQL injection, open redirect, SSRF, OS command injection,
path traversal, broken function-level authz (BFLA), excessive data exposure, SSTI, JWT `alg=none`,
mass assignment, GraphQL introspection, host-header injection, and the common misconfigurations
(missing headers, clickjacking, insecure cookies, permissive CORS, version disclosure, sensitive
files).

**Deeper checks:** a weak JWT signing secret and expiry-not-enforced (`--authz`); HTTP
verb-tampering access-control bypass and GraphQL depth (`--api-scan`); economic/parameter tampering
(`--bizlogic`); live exposed-services on the network (`--infra`); gRPC reflection and per-RPC
checks (`--grpc`).

**White-box:** a native Python-AST source scanner, a secret scanner, IaC misconfiguration
(Terraform / CloudFormation / Kubernetes / Dockerfile), and full SCA — dependencies matched against
[OSV.dev](https://osv.dev), then prioritized by EPSS, CISA KEV, and a call-graph reachability
analysis (is the vulnerable code actually *called* from your app?).

**Blind & browser-based:** blind SSRF/XXE via a self-hosted out-of-band collaborator (`--oob`), and
DOM/stored XSS via a real headless browser (`--browser`).

**LLM endpoints:** the OWASP LLM Top 10 — prompt injection, system-prompt and secret leakage,
insecure output handling, jailbreaks (`rampart llm-test`).

External OSS scanners (Nuclei, Nmap, Semgrep, Trivy, testssl.sh) plug in as *optional* leads via
`--scanners`; their results are never auto-confirmed. Run `rampart tools` to see what's installed.

## Scan modes

Each capability runs on its own, or `pipeline` runs everything and correlates the results:

```bash
rampart recon    --target ...              # crawl, map, fingerprint
rampart dast     --target ...              # black-box web/API checks
rampart api      --target ... --openapi …  # API-focused (grey-box)
rampart sast     --target ... --repo .     # source + secrets + IaC
rampart sca      --target ... --repo . --sca-online   # dependencies vs OSV.dev
rampart authz    --target ...              # deep auth
rampart bizlogic --target ...              # business-logic tampering
rampart apiscan  --target ...              # verb tampering, GraphQL depth
rampart infra    --target ...              # live exposed-services
rampart grpc     --target grpc://host:50051
rampart llm-test --target ...              # OWASP LLM Top 10
rampart agents   --target ... --intel claude-code   # reasoning layer
rampart pipeline --target ... --repo .     # all of the above, correlated
rampart features                           # list everything and how to run it
```

Write or otherwise active probes are off by default; add `--active` to allow them. Rampart never
does anything destructive — no dropped data, no denial of service.

## Using an LLM (Claude Code, your own key, or none)

The reasoning layer is **optional and strictly advisory** — it only ever *proposes* what to look
at, and everything it proposes is re-checked by the deterministic pipeline and the oracles. The
validator and the policy engine are never an LLM, which is what keeps the safety guarantees true.

| `--intel` | Uses | Cost | Setup |
| --- | --- | --- | --- |
| `deterministic` *(default)* | built-in rules, no LLM | free | none |
| `claude-code` | your local `claude` CLI | your Claude plan | have `claude` on your PATH |
| `openai-compat` | any OpenAI-compatible API | your key | two env vars |

**Claude Code** is the simplest path if you already use it — no API key needed:

```bash
rampart test --intel claude-code --agents --target ... --scope-file rampart.scope.yaml
```

**Bring your own key** works with OpenAI, OpenRouter, Groq, Together, a self-hosted LiteLLM
gateway, or a fully-local Ollama. Keys are read from the environment, never passed on the command
line:

```bash
export RAMPART_LLM_BASE_URL="https://api.openai.com/v1"   # or openrouter / groq / ollama / litellm
export RAMPART_LLM_MODEL="gpt-4o-mini"
export OPENAI_API_KEY="sk-..."                            # or RAMPART_LLM_API_KEY=...
rampart test --intel openai-compat --agents --target ...
```

If you don't set anything, Rampart runs fully deterministically — free, offline, and reproducible.
Model recommendations and free options are in [docs/LLM_AND_API_KEYS.md](docs/LLM_AND_API_KEYS.md).

## Reports and compliance

Pick any combination with `--report`: `json`, `sarif` (for CI code-scanning), `md`, `html`
(a self-contained dashboard), `compliance`, and `soc2`.

The compliance report maps every finding — deterministically, by CWE — to the controls it provides
evidence for across **SOC 2, ISO 27001:2022, PCI DSS v4.0, NIST 800-53 Rev5 (the FedRAMP baseline),
HIPAA, GDPR, OWASP ASVS, and CIS Controls v8**. It's *evidence* for your auditor, not a
certification — only a licensed firm issues those. Hand them this plus the hash-chained audit log
and the evidence bundle.

There's also a local dashboard and an MCP server:

```bash
rampart serve --work-dir .rampart     # zero-dependency web dashboard on :8787
rampart mcp                           # MCP server — scope-guarded tools for Claude Code and agents
```

Register the MCP server with Claude Code: `claude mcp add rampart -- python -m rampart.mcp`.

## The benchmark

Most tools self-report their false-positive rate. Rampart ships a reproducible benchmark instead:

```bash
python benchmarks/run_benchmark.py --runs 5
```

It runs the demo target in vulnerable and fixed modes, scores confirmed findings against ground
truth, and writes `benchmarks/results.json`. It currently reports 100% precision and recall
(15 true positives, 0 false positives, 0 false negatives).

## Safety model

Rampart treats safety as something the architecture guarantees, not something a disclaimer asks for:

- **Authorization gate.** No run without a valid, unexpired, in-scope `rampart.scope.yaml` naming an
  accountable owner. Fail-closed.
- **One choke-point.** Every request goes through it; no agent or scanner code can bypass it.
- **Non-destructive by default.** Writes and state changes require `--active`; destructive actions
  and denial-of-service are never allowed.
- **Independent validation** before anything is `confirmed`.
- **Tamper-evident audit log.** Append-only and hash-chained; `rampart verify-audit` recomputes it
  and detects tampering.
- **Advisory remediation.** Patch suggestions are written as artifacts — Rampart never auto-applies
  or merges them.
- **Target output is data, never instructions** — an indirect prompt-injection defense.
- **Budgets and a kill switch** cap per-host rate, total requests, and spend.

## What it isn't (yet)

Rampart is honest about its limits:

- The reasoning layer narrows the gap to a human pentester, but it doesn't close it. Truly novel
  logic flaws and deep design issues still need a person — which is exactly why Rampart tiers those
  findings as `agent-assessed` and never silently promotes them. Think of it as a strong, low-noise
  first pass plus continuous regression and audit evidence, not a one-click "you're secure" button.
- It has no mobile/Android testing, no deep per-RPC gRPC *fuzzing* beyond reachable unauth checks,
  and no hosted always-on service — it's something you run.
- It produces evidence of control effectiveness, not a compliance attestation.

## Contributing

Contributions are very welcome — new checks, better docs, bug fixes. Start with
[CONTRIBUTING.md](CONTRIBUTING.md); it explains the setup, the two rules that keep Rampart
trustworthy, and how to add a new vulnerability class. By participating you agree to the
[Code of Conduct](CODE_OF_CONDUCT.md).

Found a security issue *in Rampart itself*? Please follow [SECURITY.md](SECURITY.md) rather than
opening a public issue.

## License

Apache-2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE). GPL/AGPL external scanners are integrated
as separate processes, never linked.

Maintained by Nitin (nitin.code2@gmail.com) and the Rampart contributors.
