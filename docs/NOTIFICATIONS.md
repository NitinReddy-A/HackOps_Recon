# Outbound findings notifications

Rampart can push **CONFIRMED** findings to external remediation workflows the moment a scan
finishes — a generic signed webhook and/or a Slack incoming webhook. Like the GitHub PR comment,
this layer is **explicit, opt-in, and failure-safe**: it does nothing unless you configure a sink,
and a network or HTTP error to a sink **never** raises or changes the scan's result or exit code.

Only findings Rampart has independently validated (`reporting.status.is_confirmed`: validated by
the oracle and still open — not dropped, not fixed-by-retest) are ever sent. Everything is stdlib
(`urllib`, `hmac`, `hashlib`) — no new runtime dependencies.

## Sinks

### Generic webhook

POSTs a compact JSON summary (see [Payload](#payload-webhook)) to your URL with
`Content-Type: application/json`. When a signing secret is set, the request carries an
`X-Rampart-Signature` header so your receiver can verify authenticity (see
[Signature scheme](#signature-scheme)). With no secret it posts **unsigned** and says so in the CLI
output and the result.

### Slack incoming webhook

POSTs Slack's `{"text": ...}` incoming-webhook shape: a one-line header
(`Rampart: N new confirmed finding(s) for <app> — <severity badge>`) followed by one bullet per
finding (`• [severity] title (endpoint)`, capped at 20 with an "…and N more" line).

### Adding a Jira / Linear sink

A new sink is a drop-in: subclass `rampart.integrations.notify.Sink`, set `name` + `url`, and
implement `build(summary) -> (raw_body: bytes, headers: dict)` for that API. Idempotency, scrubbing,
confirmed-only filtering and failure-safety are handled by the shared orchestration.

## Configuration

Sinks are off until a URL is provided. URLs may come from a CLI flag (which wins) or an environment
variable; **the webhook signing secret is read from the environment only** and never from a config
file or CLI flag, so it is never persisted.

| Purpose              | CLI flag (on `test` / `scan` / `pipeline` / modes) | Env fallback                 |
| -------------------- | -------------------------------------------------- | ---------------------------- |
| Generic webhook URL  | `--notify-webhook URL`                             | `RAMPART_WEBHOOK_URL`        |
| Webhook signing secret | *(none — env only)*                              | `RAMPART_WEBHOOK_SECRET`     |
| Slack webhook URL    | `--notify-slack URL`                               | `RAMPART_SLACK_WEBHOOK_URL`  |

Example:

```bash
export RAMPART_WEBHOOK_SECRET='your-shared-signing-secret'
rampart test --target http://127.0.0.1:8080 \
  --notify-webhook https://hooks.example.com/rampart \
  --notify-slack  https://hooks.slack.com/services/T000/B000/XXXX
```

Only `http`/`https` URLs are accepted; anything else is skipped with a note. Each POST is bounded by
a 10-second timeout.

## Payload (webhook)

The webhook body is a single JSON object:

```json
{
  "counts": { "high": 1, "medium": 1 },
  "findings": [
    {
      "title": "IDOR on /api/orders",
      "severity": "high",
      "vuln_class": "IDOR/BOLA",
      "endpoint": "GET http://target/api/orders/1",
      "dedupe_key": "demo:GET:/api/orders/{id}:idor",
      "id": "fnd_a1b2c3d4e5f6"
    }
  ],
  "run": {
    "tool": "rampart",
    "version": "1.2.0",
    "generated_at": "2026-10-10T12:00:00.000Z",
    "confirmed_total": 2,
    "application": "demo-shop-api",
    "target": "http://target:8080",
    "engagement_id": "eng-..."
  }
}
```

- `counts` — confirmed findings in **this** payload, grouped by severity.
- `findings` — one row per confirmed finding being notified (title/severity/vuln_class/endpoint/
  dedupe_key/id). Finding text is run through `scrub_secrets` before it leaves the process.
- `run` — run metadata; `confirmed_total` and the `findings` list reflect the *new* findings in this
  delivery, not the whole run history.

## Signature scheme

When `RAMPART_WEBHOOK_SECRET` is set, the webhook request includes:

```
X-Rampart-Signature: sha256=<hex>
```

where `<hex>` is the lowercase hex digest of:

```
HMAC-SHA256(key = RAMPART_WEBHOOK_SECRET, message = <raw request body bytes>)
```

The signed message is the **exact raw body** Rampart POSTs — canonical JSON with sorted keys and no
whitespace (`json.dumps(payload, sort_keys=True, separators=(",", ":"))`, UTF-8 encoded). Verify it
against the raw bytes you received, before parsing, using a constant-time compare:

```python
import hmac, hashlib, os


def verify(raw_body: bytes, header: str) -> bool:
    secret = os.environ["RAMPART_WEBHOOK_SECRET"].encode()
    expected = "sha256=" + hmac.new(secret, raw_body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, header or "")
```

If no secret is configured, no `X-Rampart-Signature` header is sent (the delivery result records
`"signed": false` with a note). Slack requests are not signed by Rampart — Slack webhook URLs carry
their own secret token in the path.

## Idempotency

Rampart never notifies the same finding to the same sink twice. After a sink's POST succeeds, the
notified finding identities (each finding's `dedupe_key`, or its `id` when it has none) are recorded
**per sink** in `<work_dir>/notified.json`:

```json
{
  "version": 1,
  "sinks": {
    "webhook": ["demo:GET:/api/orders/{id}:idor"],
    "slack":   ["demo:GET:/api/orders/{id}:idor"]
  }
}
```

On a re-run, each sink only receives confirmed findings it has not already seen, so a repeat scan
sends only genuinely **new** findings. The identity cursor advances for a sink **only when that
sink's delivery succeeds** — a failed sink retries its batch on the next run, while a sink that
already succeeded never re-sends. A missing or corrupt `notified.json` is treated as empty (nothing
previously notified). The file holds only finding identities and sink names — never the secret, the
sink URL, or any URL token.

## Safety properties

- **Opt-in**: no sink configured → no network call, nothing written.
- **Confirmed only**: unvalidated candidates, dropped findings and retest-fixed findings are never
  sent.
- **Failure-safe**: a closed port, timeout, `5xx`, or any transport error is caught and returned as
  `posted: false` with a short, **URL-free** reason; the scan result and exit code are unaffected.
- **No secret leak**: the signing secret and the sink URL (including any token) never appear in
  logs, the CLI output, the returned result structure, or `notified.json`.
- **Bounded**: every request uses a 10-second timeout.
