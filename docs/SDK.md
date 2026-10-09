# Python SDK

Rampart has a small, stable Python API so you can run scans from your own code — a test, a CI
script, a notebook. It's a thin wrapper over the same `Engagement` engine the CLI, the MCP server,
and the GitHub Action use, so a scan from code gives you exactly the same findings as one from the
terminal.

## Quick start

```python
from rampart import Rampart

r = Rampart(
    scope="rampart.scope.yaml",  # the authorization contract (required)
    target="http://127.0.0.1:8080",  # an in-scope target (required)
    openapi="openapi.json",  # optional: grey-box
    seed="appmodel_seed.json",  # optional: seeded accounts / ownership
    repo=".",  # optional: turns on source scanning + correlation
)

result = r.scan()

print(result.summary())
# -> "7 confirmed (2 high, 4 medium, 1 low), 1 agent-assessed, 4 dropped by the false-positive gate"

for f in result.confirmed:
    print(f.severity, f.title)
```

`Rampart(...)` raises `rampart.schemas.scope.ScopeError` if the scope contract is missing, invalid,
expired, or doesn't cover the target — the same fail-closed authorization gate as every other
surface. The engagement is built lazily on the first `.scan()`.

## The result object

`scan()` returns a `ScanResult`. Iterating it yields every finding; the useful slices are:

| | |
| --- | --- |
| `result.confirmed` | findings an independent oracle proved |
| `result.agent_assessed` | reasoned-but-unproven findings (review by hand) |
| `result.dropped` | candidates the false-positive gate removed |
| `result.by_severity()` | `{severity: [confirmed findings]}` |
| `result.at_or_above("high")` | confirmed findings at or above a severity |
| `result.failed(on="high")` | `True` if any confirmed finding is at/above `high` — the gate |
| `result.summary()` | a one-line human summary |

Render reports in memory, or write them to the engagement's work dir:

```python
sarif = result.to_sarif()  # also: to_json, to_markdown, to_html, to_compliance, to_soc2
result.save(["html", "json", "sarif"])  # -> {"html": ".rampart/reports/report.html", ...}
```

## As a test / CI gate

Because the result is just data, a security gate is one assertion:

```python
def test_staging_has_no_high_severity_bugs():
    result = Rampart(scope="rampart.scope.yaml", target="https://staging.internal").scan()
    assert not result.failed(on="high"), result.summary()
```

## Running everything

The optional capabilities are keyword arguments — `agents=True`, `oob=True`, `browser=True`,
`sast=True`, `sca=True`, `iac=True`, `infra=True`, `authz=True`, `bizlogic=True`, `api_scan=True`,
`grpc=True`, `active=True`, `parallel=16`, and so on. For the full, everything-on run (the SDK
equivalent of `rampart pipeline`):

```python
result = Rampart(scope="rampart.scope.yaml", target="...", repo=".", full=True).scan()
```

`full=True` turns on the safe aggressive stages. It deliberately does **not** enable `sca_online`,
which sends dependency names to OSV.dev — pass `sca_online=True` yourself if you want it.

## LLM endpoints

```python
r = Rampart(scope="rampart.scope.yaml", target="http://127.0.0.1:9090", application="my-llm")
result = r.llm_test(
    chat_path="/chat", input_field="message", output_field="reply", canary="a-secret-in-your-system-prompt"
)
```

## Escape hatch

If you need a config field the keyword arguments don't expose, build an `EngagementConfig` and use
`Rampart.from_config(...)`:

```python
from rampart import Rampart, EngagementConfig

cfg = EngagementConfig(scope_file="rampart.scope.yaml", target="...", store_url="postgresql://...")
result = Rampart.from_config(cfg).scan()
```

Or drop all the way down to the engine — `from rampart.engagement import Engagement, EngagementConfig` —
if you want the raw `ScanResult` (hypotheses, phase log, correlation, exploitation proofs) that the
SDK wraps.
