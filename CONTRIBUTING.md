# Contributing to Rampart

Thanks for being here. Rampart is meant to be the open, self-hostable alternative to the
commercial "autonomous pentest" tools, and it only gets there with contributors. This guide
tells you how to set up, where things live, and — most importantly — the two rules that keep
Rampart trustworthy.

## The two rules (please read before you write code)

Everything in Rampart exists to protect these two invariants. A change that breaks either
one won't be merged, however useful it looks.

1. **The LLM proposes, deterministic code disposes.** No model output, no agent, and no
   scanner ever touches the network or a target directly. Every action is a typed
   `ToolCallRequest` that goes through the one policy choke-point
   ([`rampart/policy/pipeline.py`](rampart/policy/pipeline.py)):
   `allowlist → scope → resolved-IP → risk tier → policy → budget → execute → audit`,
   and it fails closed. If you're adding something that makes a request, it goes through a
   `ProbeRunner`, not `urllib` or `socket`. (The browser, gRPC, and infra engines open their
   own connections by necessity — they are the documented exceptions, and they are only ever
   pointed at an already in-scope host.)

2. **Evidence over alerts.** Nothing is marked `confidence=confirmed` unless an **independent
   oracle** re-derives the proof from a clean state, with 2+ reproductions and a negative
   control. The component that discovers a candidate is never the component that confirms it.
   If you can't prove it deterministically, it ships at a lower tier (`firm`, `agent-assessed`),
   never as `confirmed`.

If you keep those two in mind, you'll fit right in.

## Getting set up

You need **Python 3.10+** and nothing else — the core has zero runtime dependencies.

```bash
git clone https://github.com/NitinReddy-A/HackOps_Recon.git
cd HackOps_Recon
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"        # editable install + pytest + ruff + pre-commit
pre-commit install             # run lint/format on every commit (optional but nice)
```

Optional extras, only if you're working on those parts:

```bash
pip install -e ".[browser]"    # DOM/stored XSS (then: python -m playwright install chromium)
pip install -e ".[grpc]"       # gRPC scanning
pip install -e ".[all]"        # everything at once
```

## Running things

```bash
pytest                          # the full suite (currently ~200 tests)
pytest tests/test_acceptance.py # one file
python benchmarks/run_benchmark.py   # precision/recall against the demo target
ruff check . && ruff format .   # lint + format
```

Every test runs against a throwaway, intentionally-vulnerable demo app on a random
loopback port ([`examples/demo_target/`](examples/demo_target/)) — offline, isolated, and
safe. You never point the test suite at anything real.

## How the repo is laid out

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the full map. The short version:

- `rampart/policy/` — the safety choke-point. The most important code in the project.
- `rampart/schemas/` — the scope contract, the `Finding` shape, typed tool calls.
- `rampart/workers/` + `rampart/validation/` — discover candidates, then confirm them with oracles.
- `rampart/scanners/`, `rampart/sast/`, `rampart/sca/`, `rampart/iac/`, `rampart/infra/`,
  `rampart/authz/`, `rampart/bizlogic/`, `rampart/apiscan/`, `rampart/grpc_scan/` — the checks.
- `rampart/orchestration/` — the parallel task graph.
- `rampart/intelligence/` — the pluggable reasoning layer (deterministic / Claude Code / BYO key).
- `rampart/reporting/`, `rampart/compliance/` — findings → reports and framework mappings.

## Adding a new vulnerability class (the common contribution)

A confirmed class has four parts. Use an existing one as a template — the oracle-backed
classes in [`rampart/validation/`](rampart/validation/) are the cleanest reference.

1. **The worker** proposes a candidate and gathers initial signal.
2. **The oracle** re-derives the proof independently (probe + negative control + 2 reproductions)
   and is the *only* thing allowed to confirm. Register it in
   [`rampart/validation/registry.py`](rampart/validation/registry.py).
3. **The demo target** gets a vulnerable *and* a fixed version of the endpoint
   ([`examples/demo_target/vulnerable_app.py`](examples/demo_target/vulnerable_app.py), gated on
   the `--fixed` flag) so the benchmark can prove both directions. Add the endpoint to
   `examples/demo_target/openapi.json` **and** the inline spec in `tests/conftest.py`.
4. **A test** (and, for a headline oracle class, a benchmark ground-truth entry) proves it
   confirms on the vulnerable target and stays silent on the fixed one.

Self-contained scanner modules (like `iac/`, `infra/`, `grpc_scan/`) are simpler — they return
`Finding` objects directly and carry their own probe/control logic. Look at those if your check
doesn't fit the worker/oracle split.

Write-side or otherwise active probes must be gated behind `--active`. Never add anything
destructive (no dropped data, no DoS, no desync) — if a check can only be confirmed by breaking
something, it stays human-only and we say so.

## Pull requests

- Branch off `main`. Keep PRs focused — one feature or fix.
- Make sure `pytest`, `ruff check`, and `ruff format --check` all pass. CI runs them too.
- If you changed behavior, add or update a test. If you added a class, keep the benchmark at 100%.
- Write a clear PR description: what, why, and how you verified it.
- Be honest about limitations in the finding text and the docs. Overclaiming is the one thing
  this project can't afford.

## Reporting bugs and ideas

Use the [issue templates](.github/ISSUE_TEMPLATE/). For a security issue in Rampart itself,
please follow [`SECURITY.md`](SECURITY.md) instead of opening a public issue.

## Questions

Open a [discussion or issue](https://github.com/NitinReddy-A/HackOps_Recon/issues), or email
**nitin.code2@gmail.com**.

By contributing, you agree that your contributions are licensed under the project's
[Apache-2.0 license](LICENSE).
