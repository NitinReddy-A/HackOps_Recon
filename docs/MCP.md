# Using Rampart with Claude Code (MCP)

Rampart ships an [MCP](https://modelcontextprotocol.io) server, which is the cleanest way to use it
from Claude Code or any other MCP client. Claude calls Rampart's tools directly — no glue code — and
every call still goes through the same authorization gate and policy pipeline as the CLI, so Claude
can't make Rampart do anything your scope contract doesn't allow.

## Register it with Claude Code

```bash
claude mcp add rampart -- python -m rampart.mcp
```

That's it. In a Claude Code session you can now say things like *"check my scope file is valid"* or
*"scan http://127.0.0.1:8080 and summarize the confirmed findings"* and Claude will call the tools
below. (Rampart must be installed in the Python that `python` resolves to — `pip install -e .` in
your clone, or `pip install "git+https://github.com/NitinReddy-A/Rampart.git@v1.1.0"`.)

For any other MCP client, run the server over stdio:

```bash
python -m rampart.mcp
```

## The tools

| Tool | What it does |
| --- | --- |
| `rampart_scope_check` | Validate a `rampart.scope.yaml` authorization contract **without touching any target**. Use this first. |
| `rampart_scan` | Run an assessment against an in-scope target. Returns the findings (confirmed vs dropped). |
| `rampart_llm_test` | Assess an authorized LLM endpoint against the OWASP LLM Top 10. |
| `rampart_report` | Render reports (html / md / json / sarif / compliance) from a stored run. |

Each tool takes a `scope_file` and enforces it fail-closed: an out-of-scope target is refused before
any request is made. `rampart_scan` accepts the same grey/white-box inputs as the CLI — `openapi`,
`appmodel_seed`, `repo`, `crawl`, `application`, `work_dir`.

## Why MCP over a plugin or custom glue

The MCP server, the CLI, the Python SDK, and the GitHub Action all route through the one
`Engagement` facade. That's deliberate: it means a scan Claude runs through MCP, a scan you run on
the command line, and a scan your CI runs produce identical results, with the same evidence and the
same safety guarantees. There's no second code path to drift.

## Safety note

Giving an agent a security scanner is exactly the kind of thing that *should* make you nervous — so
Rampart is built for it. The scope contract is the boundary, the policy pipeline enforces it on every
request, nothing destructive is allowed, and the whole session is written to a tamper-evident audit
log you can inspect afterward with `rampart verify-audit`. Point it only at targets your scope
contract authorizes.
