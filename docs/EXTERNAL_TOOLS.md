# External scanners

Rampart's built-in checks need no external tools. If you already use well-known open-source
scanners, Rampart can run them too and fold their output into the same report. Their results are
always labelled **unvalidated leads**: they are never counted as confirmed and never fail a CI gate.

```bash
rampart tools                                     # which adapters are installed, and why any are skipped
rampart test … --scanners nuclei,trivy            # run specific adapters
rampart test … --scanners all                     # run every adapter that's installed
```

Missing tools are skipped with an install hint; they never fail a run.

## Adapters

| Adapter | Kind | Network | What Rampart runs |
| --- | --- | --- | --- |
| `nuclei` | DAST | contacts the target only | `-ni` (no interactsh/OAST callbacks to third-party servers), `-dr` (no redirect following), `-rl` = your scope's `max_requests_per_host_per_min / 60` (min 1), and excludes the `intrusive,dos,fuzz` tags unless `--active` (then only `dos`) |
| `nmap` | infra | contacts the target only | `-sV -Pn` against the single port in `--target` |
| `testssl` | TLS | contacts the target only | `https://` targets only |
| `semgrep` | SAST | only if you use a registry pack | requires `RAMPART_SEMGREP_CONFIG` (see below); skipped otherwise |
| `opengrep` | SAST | no | `RAMPART_OPENGREP_CONFIG` (default `auto`) |
| `bandit` | SAST | no | Python only |
| `gitleaks` | secrets | no | `--no-git --redact`, SARIF written to a temp file (works on Windows) |
| `trivy` | SCA | no | `trivy fs` with SARIF output |

## Configuration

- **`RAMPART_SEMGREP_CONFIG`**: a local rules file or directory keeps Semgrep fully offline. A
  registry pack such as `p/ci` downloads rules from semgrep.dev, and the run is marked as
  network-using in the report. There is deliberately no default.
- **`RAMPART_OPENGREP_CONFIG`**: rules for Opengrep (default `auto`).

## Scope and safety

- External tools run as separate processes with argument lists (never through a shell), so a
  target URL can't inject commands.
- Nuclei's per-path exclusions can't be enforced for a single `-u` target. If your scope uses
  `paths_exclude`, prefer the built-in checks for those areas, or narrow `--target`.
- GPL/AGPL tools are invoked, never linked, so they don't affect Rampart's Apache-2.0 license.
