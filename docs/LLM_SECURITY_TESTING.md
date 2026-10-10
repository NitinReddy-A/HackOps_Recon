# LLM security testing (OWASP LLM Top 10 — 4 categories)

Rampart probes an authorized LLM-backed endpoint for **4 of the OWASP Top 10 for LLM Applications
(2025)** risk categories — not all ten. The four probe families map to LLM01 Prompt Injection
(direct + jailbreak), LLM05 Improper Output Handling, and LLM07 System Prompt Leakage / LLM02
Sensitive Information Disclosure (listed in full below).
It is **safe by design**: every probe looks for an inert marker or a planted canary to prove a
guardrail was bypassed — it never tries to elicit genuinely harmful content, and the result is
reproducible.

## What it checks

| Probe | OWASP (2025) | How it's proven (oracle) |
|---|---|---|
| Direct prompt injection | LLM01:2025 Prompt Injection | an attacker-chosen marker appears in the reply, not for a benign control |
| Role-play jailbreak | LLM01:2025 Prompt Injection | a persona-switch produces an override marker |
| Insecure output handling | LLM05:2025 Improper Output Handling | the model returns raw active markup (would be XSS if rendered) |
| System-prompt leak | LLM07:2025 System Prompt Leakage (also LLM02:2025) | a secret **canary** you planted in the system prompt appears in the reply |

A finding is `confirmed` only when all of these hold:

- the marker or canary appears in the reply to the attack prompt;
- the reply isn't just quoting the attack instruction back (an endpoint that echoes its input is
  not a vulnerability);
- a control with the same marker but no instruction, and a benign control, do **not** produce it;
- it reproduces 2+ times.

Each probe ends in one of these outcomes:

| Outcome | Meaning |
|---|---|
| `confirmed` | proven, as above |
| `not-vulnerable` | the endpoint answered and the guardrail held |
| `blocked` | the policy pipeline refused the request (out of scope, budget, …) |
| `error` | non-2xx status, connection failure, or timeout: the probe was **not** evaluated |
| `inconclusive` | a reply came back but the `--output-field` path didn't resolve |
| `skipped` | not run, e.g. the system-prompt leak probe without `--canary` |

`llm-test` exits non-zero when no probe could actually be evaluated, so an unreachable or
misconfigured endpoint never looks like a clean pass.

## Running it

Every prompt is a gated POST through the same policy pipeline as the rest of Rampart (scope →
resolved-IP → risk → policy → approval → budget → audit). LLM prompts are Tier 2, so the
`llm-test` command authorizes them for the in-scope endpoint and records the approval in the
audit log.

```bash
# toy local target (ships with Rampart):
python scripts/demo.py --llm

# your own authorized endpoint:
#   --input-field   JSON field that holds the user prompt
#   --output-field  dotted path to the model's reply; list indexes work (choices.0.message.content)
#   --canary        a string you planted in the system prompt (enables the leak probe)
rampart llm-test \
  --scope-file rampart.scope.yaml \
  --target http://127.0.0.1:9090 \
  --chat-path /chat \
  --input-field message \
  --output-field reply \
  --canary "SECRET-IN-YOUR-SYSTEM-PROMPT" \
  --report html,md,json
```

Point `--canary` at a string you have placed in the target's system prompt; the leak oracle
looks for exactly that string, so a hit is unambiguous proof of disclosure.

## Scope

Your `rampart.scope.yaml` must list the LLM host/port in scope and allow `POST` on the chat path, e.g.:

```yaml
scope:
  in_scope:
    - host: "127.0.0.1"
      ports: [9090]
      paths_include: ["/chat", "/"]
      methods: ["GET", "POST"]
  resolved_ip_allowlist: ["127.0.0.1/32"]
```

Only test endpoints you own or are explicitly authorized to test.
