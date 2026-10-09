---
apiVersion: security-agent/v1
kind: EngagementScope
authorization:
  owner: "you@localhost"
  authorized_by: "you@localhost"
  ticket: "DEMO-0001"
  attestation: "I own this local demo target and authorize testing it."
  expires: "2099-12-31T23:59:59Z"
scope:
  in_scope:
    - host: "127.0.0.1"
      ports: [8080]
      paths_include: ["/**"]
      methods: ["GET", "POST"]
  out_of_scope:
    paths_exclude: ["/api/admin/**"]
    hosts_exclude: []
  resolved_ip_allowlist: ["127.0.0.1/32"]
limits:
  max_requests_per_host_per_min: 240
  max_total_requests: 5000
  max_concurrent_workers: 2
  budget_usd: 5.00
  max_tokens: 2000000
action_policy:
  default_tier_ceiling: 1
  tier2_requires_approval: true
  tier3: deny
test_accounts:
  - { id: user_a, role: customer, secret_ref: "vault://demo/user_a" }
  - { id: user_b, role: customer, secret_ref: "vault://demo/user_b" }
notify:
  on_start: ["you@localhost"]
  kill_switch_contact: "you@localhost"
---

# Engagement scope — local demo target

This is the machine-readable authorization contract Rampart parses before it will run.
It authorizes testing **only** the local `demo-shop-api` on `127.0.0.1:8080`, using two
seeded, non-production customer accounts. Anything outside this — other hosts, other
ports, write/state-change actions (Tier 2), or destructive actions (Tier 3) — is denied
or requires explicit human approval. The scope auto-expires and fails closed.
