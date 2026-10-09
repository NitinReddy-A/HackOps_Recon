---
apiVersion: security-agent/v1
kind: EngagementScope
authorization:
  owner: "ci@localhost"
  authorized_by: "ci@localhost"
  ticket: "VAMPI-CORPUS"
  attestation: "Authorized testing of a locally-run OWASP VAmPI container in CI."
  expires: "2099-12-31T23:59:59Z"
scope:
  in_scope:
    - host: "127.0.0.1"
      ports: [5000]
      paths_include: ["/**"]
      methods: ["GET", "POST", "PUT", "DELETE"]
  out_of_scope:
    paths_exclude: []
    hosts_exclude: []
  resolved_ip_allowlist: ["127.0.0.1/32"]
limits:
  max_requests_per_host_per_min: 1000
  max_total_requests: 20000
  max_concurrent_workers: 2
  budget_usd: 5.0
  max_tokens: 2000000
action_policy:
  default_tier_ceiling: 1
  tier2_requires_approval: true
  tier3: deny
test_accounts: []
notify: {}
---

# VAmPI corpus scope (CI). Authorizes only the locally-run VAmPI container on 127.0.0.1:5000.
