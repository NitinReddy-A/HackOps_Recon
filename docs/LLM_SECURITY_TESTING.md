# LLM security testing (OWASP LLM Top 10)

Rampart can assess an authorized LLM-backed endpoint for the OWASP Top 10 for LLM Applications.
It is **safe by design**: every probe looks for an inert marker or a planted canary to prove a
guardrail was bypassed — it never tries to elicit genuinely harmful content, and the result is
reproducible.

## What it checks

| Probe | OWASP | How it's proven (oracle) |
|---|---|---|
| Direct prompt injection | LLM01 | an attacker-chosen marker appears in the reply, not for a benign control |
| System-prompt / secret leak | LLM06 | a secret **canary** you planted in the system prompt appears in the reply |
| Insecure output handling | LLM05 | the model returns raw active markup (would be XSS if rendered) |
| Role-play jailbreak | LLM01 | a persona-switch produces an override marker |

A finding is `confirmed` only when the marker/canary fires for the attack prompt, does **not**
fire for a benign control, and reproduces 2+ times.

## Running it

Every prompt is a gated POST through the same policy pipeline as the rest of Rampart (scope →
resolved-IP → risk → policy → approval → budget → audit). LLM prompts are Tier 2, so the
`llm-test` command authorizes them for the in-scope endpoint and records the approval in the
audit log.

```bash
# toy local target (ships with Rampart):
python scripts/demo.py --llm

# your own authorized endpoint:
python -m rampart llm-test \
  --scope-file SECURITY.md \
  --target http://127.0.0.1:9090 \
  --chat-path /chat \
  --input-field message \       # JSON field that holds the user prompt
  --output-field reply \        # dotted JSON path to the model's reply
  --canary "SECRET-IN-YOUR-SYSTEM-PROMPT" \
  --report html,md,json
```

Point `--canary` at a string you have placed in the target's system prompt; the leak oracle
looks for exactly that string, so a hit is unambiguous proof of disclosure.

## Scope

Your `SECURITY.md` must list the LLM host/port in scope and allow `POST` on the chat path, e.g.:

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
