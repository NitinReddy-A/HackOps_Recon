# Changelog

All notable changes to Rampart are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims to follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed
- Renamed the authorization/scope contract from `SECURITY.md` to `rampart.scope.yaml`, freeing
  `SECURITY.md` for the standard GitHub vulnerability-disclosure policy.
- Productized the repository for open-source contribution: `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`,
  issue/PR templates, `CHANGELOG.md`, `NOTICE`, ruff lint/format config, pre-commit, and an
  `ARCHITECTURE.md`. Rewrote the README around a clear getting-started and LLM-integration flow.

## [1.0.0] — 2026-10-08

### Added
- **Call-graph reachability** for SCA: a static Python call graph decides whether a vulnerable
  dependency's symbol is actually reachable from an entrypoint (`function-reachable` … `unreachable`).
- **Per-RPC gRPC**: method enumeration, plaintext-transport detection, and (under `--active`,
  read-ish methods only) unauthenticated-method-invocation confirmation.
- **Eight-framework compliance mapping** (`--report compliance`): SOC 2, ISO 27001:2022, PCI DSS
  v4.0, NIST 800-53 Rev5 (FedRAMP), HIPAA, GDPR, OWASP ASVS, CIS Controls v8.
- **SCA exploit intelligence**: EPSS + CISA KEV + reachability folded into an adjusted P0–P3 priority.
- **Live infrastructure scan** (`--infra`), **deep auth** (`--authz`, weak JWT secret),
  **deterministic business logic** (`--bizlogic`, economic/parameter tampering), and
  **API depth** (`--api-scan`, HTTP verb tampering + GraphQL depth).

## [0.9.0] — 2026-10-08

### Added
- **Graph orchestrator**: a DAG scheduled across a bounded thread pool, with runtime subagent
  spawning, so independent hypotheses are tested and validated in parallel (`--parallel N`).
- **Full SCA** against OSV.dev with concrete upgrade remediation; **IaC** scanning (Terraform /
  CloudFormation / Kubernetes / Dockerfile); **gRPC** server-reflection exposure.

### Changed
- Thread-safety for parallel runs (session manager, evidence store); parallel runs produce
  byte-identical findings to sequential ones.

## [0.8.0] — 2026-10-08

### Added
- Blind XXE over the OOB collaborator, stored-XSS write-half via the headless browser, a passive
  request-smuggling indicator, a multi-tenant SQL store, diff-aware SAST (`--since`), and an
  external-corpus benchmark runner.

## [0.6.0 – 0.7.0] — 2026-10-08

### Added
- Product scan modes (`recon` / `dast` / `api` / `sast` / `sca` / `agents` / `pipeline`).
- White-box **SAST/SCA** with SAST↔DAST correlation; a hardened multi-agent reasoning harness;
  host-header injection, mass assignment, GraphQL, and partial CSRF classes.

## [0.4.0] — 2026-10-08

### Added
- Multi-step **live exploitation** (bounded, non-destructive proof of impact), five more oracle
  classes (SSTI, JWT alg=none, sensitive-file exposure, clickjacking, insecure cookies), and a
  **SOC 2 evidence** report.

## [0.3.0] — 2026-10-07

### Added
- Recon crawler, attack-chain correlation with a risk score, and product surfaces: the one-shot
  `pipeline`, a zero-dependency web dashboard (`serve`), and an MCP server (`mcp`).

## [0.2.0] — 2026-10-06

### Added
- Expanded from the single BOLA/IDOR slice to multiple web/API classes plus the OWASP LLM Top 10,
  each behind an independent oracle, with external OSS scanner adapters.

## [0.1.0] — 2026-10-01

### Added
- First release: the BOLA/IDOR vertical slice carried end-to-end — scope gate → app model →
  hypothesis → controlled probe → independent validation → finding → advisory patch → retest.

[Unreleased]: https://github.com/NitinReddy-A/HackOps_Recon/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/NitinReddy-A/HackOps_Recon/releases/tag/v1.0.0
