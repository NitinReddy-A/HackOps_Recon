# Coverage manifest

This is the authoritative, code-verified list of what Rampart actually does. It exists so no reader
has to infer coverage from a marketing line: every row below is backed by a specific module, and the
"Not covered" section states the gaps plainly. Honesty about the ceiling is the point of the product.

If this document and any other doc disagree, **this document wins** — please open an issue.

## Evidence tiers

Rampart does not treat every finding as equal. A runtime vulnerability class is labelled by how its
result is proven:

| Tier | What it means |
| --- | --- |
| **oracle-proven** | An independent oracle (a component separate from the discoverer) re-derives the result from a clean state with a **probe + a negative control + 2 or more reproductions**. Only these may carry `confidence=confirmed` through the validator. Source: `rampart/validation/`, `rampart/browser/`. |
| **single-reproduction** | Confirmed, but on **one reproduction plus a negative control** (out-of-band callback) or a **single deterministic observation** (gRPC reflection either lists services or it does not). Source: `rampart/oob/`, `rampart/grpc_scan/`. |
| **observation** | The observation *is* the oracle (a header is present or absent; a service accepts a TCP connection or not), re-checked on a **second request/connect**. Source: `rampart/scanners/`, `rampart/infra/`. |
| **fixture-validated** | oracle-proven in structure, but the current oracle keys on a response **marker/signature the bundled demo emits**, so it can miss the flaw on other apps (false negatives, not false positives). Cross-referenced with the README "Known issues". |
| **static** | Present in source/config; evidence-backed but **not proven at runtime** (`validated=False`). Source: `rampart/sast/`, `rampart/sca/`, `rampart/iac/`. |
| **indicator / lead** | A human-review signal that is deliberately **never auto-confirmed** (partial detectors, passive indicators, external-scanner output). |

## Runtime vulnerability classes

### oracle-proven (probe + negative control + 2+ reproductions)

Registered in `rampart/validation/registry.py` and re-derived by `rampart/validation/validator.py`.
The default reproduction count is 2.

| Class | `vuln_class` | Oracle | Notes |
| --- | --- | --- | --- |
| IDOR / BOLA | `IDOR/BOLA` | `validation/oracle.py` | cross-account read + victim signature + unauth/absent controls |
| SQL injection | `SQLI` | `validation/web_oracles.py` | error-based **and/or** boolean-based, with a benign no-quote control |
| Reflected XSS | `XSS` | `validation/web_oracles.py` | unescaped markup in an HTML context; encoded-reflection control |
| Open redirect | `OPEN_REDIRECT` | `validation/web_oracles.py` | off-site `Location` vs a local-path control (canary host never fetched) |
| Command injection | `CMDI` | `validation/more_oracles.py` | marker echo vs benign control — **see echo caveat below** |
| SSTI | `SSTI` | `validation/more_oracles.py` | arithmetic differential (`{{1337*1338}}` → `1788906`) |
| JWT `alg=none` | `JWT` | `validation/more_oracles.py` | forged token accepted **and** unauth rejected (defect isolated to signature verification) |
| Host-header injection | `HOST_HEADER_INJECTION` | `validation/more_oracles.py` | crafted `Host` reflected; legitimate Host is clean |
| Excessive data exposure | `EXCESSIVE_DATA` | `validation/more_oracles.py` | sensitive field names in an authenticated response |
| Mass assignment / BOPLA | `MASS_ASSIGNMENT` | `validation/more_oracles.py` | privileged field persisted; needs `--active` (write) |
| GraphQL introspection | `GRAPHQL` | `validation/more_oracles.py` | schema returned to an anonymous client |
| Broken function-level authz | `BFLA` | `validation/more_oracles.py` | low-priv principal reaches a privileged function — **see fixture note below** |
| Server-side request forgery | `SSRF` (in-band) | `validation/more_oracles.py` | response-signature oracle — **see fixture note below** |
| Path traversal | `PATH_TRAVERSAL` | `validation/more_oracles.py` | response-signature oracle — **see fixture note below** |
| DOM-based XSS | `DOM_XSS` | `rampart/browser/engine.py` | **execution**-proven in headless Chromium, 2+ renders + benign control; needs `--browser` (Playwright). Runs via the browser side-channel guard, not the HTTP pipeline. |
| Stored XSS | `STORED_XSS` | `rampart/browser/engine.py` | execution-proven on fresh reads, 2+ loads; needs `--browser`. Caller performs the write. |

A class with **no** registered oracle can never be confirmed (fail-closed, `validator.py`).

### single-reproduction (one reproduction + control, or a single deterministic observation)

| Class | `vuln_class` | Source | Evidence |
| --- | --- | --- | --- |
| Blind SSRF | `SSRF` | `rampart/oob/blind.py` | out-of-band callback for a unique token + a never-injected control token that stays silent; `reproductions=1`. Needs `--oob`. |
| Blind XXE | `XXE` | `rampart/oob/blind.py` | external-entity callback + silent control token; `reproductions=1`. Needs `--oob`. XXE is **only** tested out-of-band (no in-band XXE oracle). |
| gRPC server reflection | `information-disclosure` | `rampart/grpc_scan/scan.py` | reflection lists services (a single deterministic observation); `reproductions=1`. Needs `--grpc`. |

gRPC also emits, under `--grpc --active`, a `GRPC_UNAUTH_METHOD` finding that **is** oracle-grade
(two unauthenticated invocations + a negative-control method that enforces auth → `reproductions=2`);
and a firm (`validated=False`) `GRPC_PLAINTEXT` transport observation. These are listed here only for
completeness.

### observation (the observation is the oracle, re-checked once)

| Class | `vuln_class` | Source | Confirmed when… |
| --- | --- | --- | --- |
| Missing security headers | `security-misconfiguration` | `scanners/builtins.py` | the headers are absent on **2/2** observations (else `firm`) |
| Permissive CORS (`ACAO:*` + `ACAC:true`) | `security-misconfiguration` | `scanners/misconfig.py` | observed on 2/2 requests |
| Clickjacking (no XFO / CSP frame-ancestors) | `security-misconfiguration` | `scanners/misconfig.py` | observed on 2/2 requests |
| Insecure session-cookie flags | `security-misconfiguration` | `scanners/misconfig.py` | missing HttpOnly/Secure/SameSite on 2/2 |
| Server/version disclosure | `security-misconfiguration` | `scanners/misconfig.py` | versioned `Server` header on 2/2 |
| Exposed sensitive file | `sensitive-file-exposure` | `scanners/misconfig.py` | 200 + **content signature** on 2/2, gated by a **soft-404 negative control** (a non-existent sibling path must NOT match the signature) |
| Exposed sensitive service | `EXPOSED_SERVICE` | `infra/scanner.py` | open on **2 connects** + a closed in-scope control port (`confirmed`); `firm` when the scope has no spare control port. Needs `--infra`. |
| TLS cert / weak-protocol issues | `TLS_MISCONFIG`, `TLS_WEAK_PROTOCOL` | `infra/scanner.py` | `firm` (`validated=False`) — weaker evidence |

### fixture-validated — and the known caveats (consistent with README "Known issues in v1.2.0")

- **SSRF (in-band), PATH_TRAVERSAL, BFLA** oracles currently recognise the response signatures the
  bundled demo target produces (`RAMPART-SSRF`, `RAMPART-TRAVERSAL`, `RAMPART-BFLA`). On other apps
  they can **miss** the flaw (false negatives), never invent one. Blind SSRF via `--oob` does not
  depend on these markers.
- **CMDI echo caveat**: the command-injection oracle can be satisfied by an endpoint that merely
  **echoes its input** back. Treat a `CMDI` finding on a parameter-reflecting endpoint with extra care.
  (The sensitive-file "soft-404" false positive in this list was fixed in the current development
  line — a non-existent sibling path is now used as a negative control.)

### indicator / lead (never auto-confirmed)

`csrf` (passive partial detector, `firm`), `request-smuggling-indicator` (`tentative`, never actively
tested — a desync would affect real users), and the all-methods-open gRPC "verify intended" indicator
(`firm`). All are tagged `needs-human-review`.

## LLM endpoint probes (`rampart llm-test`)

Exactly **four** probe families — **4 of the 10** OWASP LLM Top 10 (2025) risk categories, not all
ten. Defined in `rampart/llm/probes.py`; a finding is `confirmed` only with a marker/canary hit, an
echo/quote control, a benign control, and 2+ reproductions.

| Probe id | OWASP 2025 | Tests |
| --- | --- | --- |
| `llm01-direct-injection` | LLM01:2025 Prompt Injection | direct instruction-override emits an attacker-chosen marker |
| `llm01-jailbreak-roleplay` | LLM01:2025 Prompt Injection (jailbreak) | role-play persona switch emits an override marker |
| `llm05-insecure-output-handling` | LLM05:2025 Improper Output Handling | model returns raw active markup (XSS if rendered) |
| `llm07-system-prompt-leak` | LLM07:2025 System Prompt Leakage (+ related LLM02:2025 Sensitive Information Disclosure) | a planted system-prompt **canary** appears in the reply; requires `--canary` |

Not covered by the LLM suite: LLM03 (supply chain), LLM04 (data/model poisoning), LLM06 (excessive
agency), LLM08 (vector/embedding weaknesses), LLM09 (misinformation), LLM10 (unbounded consumption).

## White-box (static tier — evidence-backed, not runtime-proven)

All static findings carry `validated=False` and are tiered below runtime-`confirmed` findings.

| Capability | Source | What it does / limits |
| --- | --- | --- |
| **SAST** | `rampart/sast/scanner.py` | **Python only**, structural **AST** analysis (node types + identifier names, never text), sink-pattern matching. Caps at the first **2000** Python files. |
| **Secrets** | `rampart/sast/secrets.py` | regex/shape detection over text files. Caps at **4000** files and reads the first **~512 KB** per file; skips `.git` — **no git-history scan**. |
| **SCA** | `rampart/sca/` | manifest parsers → **OSV.dev** advisories → worst CVSS, enriched with **EPSS** and **CISA KEV**, ranked by **static call-graph reachability**. Reachability is name-resolved and **over-approximate** — a static heuristic, **not** a sound whole-program or runtime-proven analysis. Online OSV needs `--sca-online`. |
| **IaC** | `rampart/iac/scanner.py` | **line/regex** checks (no third-party parser) for Terraform (`*.tf`), CloudFormation (CFN-shaped `*.yaml/*.yml/*.json`), Kubernetes manifests, and Dockerfiles. |

## External scanner adapters (unvalidated leads, never auto-confirmed)

Run via `--scanners`; output is always labelled an **unvalidated lead** — never counted as confirmed,
never fails a CI gate. See [EXTERNAL_TOOLS.md](EXTERNAL_TOOLS.md).

| Adapter | Kind | Adapter | Kind |
| --- | --- | --- | --- |
| `nuclei` | DAST | `opengrep` | SAST |
| `nmap` | infra | `bandit` | SAST (Python) |
| `testssl` | TLS | `gitleaks` | secrets |
| `semgrep` | SAST (registry pack) | `trivy` | SCA |

## Not covered / out of scope

Stated plainly so expectations are correct:

- **No SPA / client-side JS route discovery.** The crawler is **GET-only**; the optional Playwright
  pass (`--browser`) renders known URLs for DOM/stored-XSS execution but does **not** discover
  single-page-app routes, client-rendered links, or API routes behind JavaScript.
- **No general authentication-protocol suite.** No OAuth / OIDC / SAML / MFA / session-management
  testing. Auth coverage is limited to JWT `alg=none` and (via `--authz`) weak JWT signing secret and
  expiry-not-enforced.
- **No stateful race-condition / sequence engine.** No multi-step workflow, TOCTOU, or request-order
  abuse engine.
- **No cloud-account / IAM enumeration.** IaC is a static file scan; the infra scanner only proves
  network reachability of a service on an in-scope host. Rampart never enumerates a cloud account.
- **No native mobile app testing** (iOS/Android binaries or app traffic).
- **Mono-language SAST** — Python source only (other languages need an external adapter such as
  Semgrep/Opengrep).
- **No multi-user control plane.** Rampart runs as a single self-hosted engagement; there is no hosted
  service, RBAC, or multi-tenant control plane (the SQL store exists for persistence, not a console).
