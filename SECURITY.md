# Security Policy

Rampart is a security tool, so we take vulnerabilities in Rampart itself seriously.

> Looking for the **authorization / scope contract** you point a scan at? That's a separate
> file — see [`rampart.scope.example.yaml`](rampart.scope.example.yaml) and the README.

## Reporting a vulnerability

Please **do not open a public issue** for a security vulnerability.

The preferred channel is GitHub's private vulnerability reporting:
**[Report a vulnerability](https://github.com/NitinReddy-A/Rampart/security/advisories/new)**
(Security tab → *Report a vulnerability*). It keeps the report private until a fix ships.

You can also email **nitin.code2@gmail.com** with:

- a description of the issue and why it matters,
- the version or commit you found it on,
- steps to reproduce (a proof of concept is ideal), and
- any suggested fix, if you have one.

You'll get an acknowledgement within a few days. We'll work with you on a fix and a
disclosure timeline, and we're happy to credit you in the release notes unless you'd
rather stay anonymous.

## What's in scope

- The Rampart code in this repository (the engine, the policy pipeline, the scanners,
  the MCP server, the dashboard).
- The way Rampart handles secrets, credentials, and evidence.
- Anything that lets Rampart act **outside** the authorized scope it was given — that
  would defeat the whole safety model, so we treat it as critical.

## What's out of scope

- Findings produced *by* Rampart against your own targets — those are the tool working
  as intended. Fix them in your app.
- Vulnerabilities in third-party, optional dependencies (Playwright, grpcio, …). Report
  those upstream; tell us if Rampart uses them unsafely.

## Supported versions

Security fixes land on `main` and in the next release. We don't backport to older tags;
please track the latest release.

## Verifying what you run

Releases are built only by the repository's release workflow and published as immutable
GitHub releases with Sigstore-signed build-provenance attestations and an SPDX SBOM. See
"Verifying a release" in the README for the exact `gh attestation verify` commands.

| Version | Supported |
| ------- | --------- |
| latest `main` / release | ✅ |
| older tags | ❌ |
