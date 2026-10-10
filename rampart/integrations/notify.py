"""Outbound findings notifications — post CONFIRMED findings to a webhook and/or Slack.

Stdlib only (``urllib``/``hmac``/``hashlib``). Like the GitHub poster this layer is explicit,
opt-in and graceful: it does nothing unless a sink is configured, and a network/HTTP failure to
any sink NEVER raises or breaks a scan — it is recorded as ``posted=False`` with a short reason.

Two sinks ship today and a Jira/Linear sink is a drop-in third:

* :class:`WebhookSink` POSTs a compact JSON summary and signs the *raw body* with
  ``X-Rampart-Signature: sha256=<hex>`` = ``HMAC-SHA256(secret, raw_body)`` so a receiver can
  verify authenticity. With no secret it posts unsigned and says so.
* :class:`SlackSink` POSTs Slack's ``{"text": ...}`` incoming-webhook shape.

Idempotency: notified finding identities (``dedupe_key`` or ``id``) are persisted **per sink** in
``<work_dir>/notified.json`` so a re-run only sends findings that sink has not seen. A missing or
corrupt manifest is treated as empty. Only CONFIRMED findings (``reporting.status.is_confirmed``)
are ever sent, finding text is run through ``scrub_secrets``, and the webhook secret / URL token
are never logged, returned, or written to the manifest.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import urllib.error
import urllib.request
from urllib.parse import urlsplit

from ..reporting.status import is_confirmed, norm_severity
from ..util import now_iso, scrub_secrets
from ..version import __version__

DEFAULT_TIMEOUT = 10.0
NOTIFIED_FILE = "notified.json"
_MANIFEST_VERSION = 1
_ALLOWED_SCHEMES = ("http", "https")


def _get(obj, key, default=None):
    """Read a field from a dataclass-ish Finding or a report-JSON finding dict."""
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


def _identity(f) -> str:
    """The stable identity used for de-duplication: the dedupe key, else the finding id."""
    return str(_get(f, "dedupe_key", "") or _get(f, "id", "") or "")


def _endpoint_str(f) -> str:
    """A compact location string: ``METHOD url`` for runtime findings, else source/asset coords."""
    ep = _get(f, "endpoint", {}) or {}
    url = _get(ep, "url", "") if ep else ""
    if url:
        method = _get(ep, "method", "") or ""
        return f"{method} {url}".strip()
    affected = _get(f, "affected_code", None)
    if affected:
        file = _get(affected, "file", "")
        line = _get(affected, "start_line", 0)
        if file:
            return f"{file}:{line}" if line else str(file)
    asset = _get(f, "asset", {}) or {}
    return str(_get(asset, "target", "") or "")


def confirmed_items(findings) -> list[dict]:
    """Every CONFIRMED finding as a small, secret-scrubbed, JSON-safe dict (first occurrence wins).

    Works on live ``Finding`` objects and on report-JSON finding dicts alike."""
    items: list[dict] = []
    seen: set[str] = set()
    for f in findings or []:
        if not is_confirmed(f):
            continue
        ident = _identity(f)
        if ident and ident in seen:
            continue
        if ident:
            seen.add(ident)
        items.append(
            {
                "title": scrub_secrets(str(_get(f, "title", "") or "")),
                "severity": norm_severity(_get(f, "severity", "info")),
                "vuln_class": str(_get(f, "vuln_class", "") or ""),
                "endpoint": scrub_secrets(_endpoint_str(f)),
                "dedupe_key": str(_get(f, "dedupe_key", "") or ""),
                "id": str(_get(f, "id", "") or ""),
                "identity": ident,
            }
        )
    return items


def build_summary(items: list[dict], *, run: dict) -> dict:
    """A compact findings summary: severity counts, the finding list, and run metadata.

    ``items`` are rows from :func:`confirmed_items` (already scrubbed). The internal ``identity``
    key is dropped from the emitted finding rows."""
    counts: dict[str, int] = {}
    findings_out = []
    for it in items:
        sev = it["severity"]
        counts[sev] = counts.get(sev, 0) + 1
        findings_out.append(
            {
                "title": it["title"],
                "severity": sev,
                "vuln_class": it["vuln_class"],
                "endpoint": it["endpoint"],
                "dedupe_key": it["dedupe_key"],
                "id": it["id"],
            }
        )
    meta = {
        "tool": "rampart",
        "version": __version__,
        "generated_at": now_iso(),
        "confirmed_total": len(items),
        **{k: v for k, v in (run or {}).items() if v not in (None, "")},
    }
    return {"counts": counts, "findings": findings_out, "run": meta}


def _body_bytes(obj: dict) -> bytes:
    """Deterministic, compact JSON bytes — exactly what is POSTed and (for the webhook) signed."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_body(body: bytes, secret: bytes | str) -> str:
    """``sha256=<hex>`` HMAC-SHA256 of the raw body, the value of ``X-Rampart-Signature``."""
    if isinstance(secret, str):
        secret = secret.encode("utf-8")
    return "sha256=" + hmac.new(secret, body, hashlib.sha256).hexdigest()


def _valid_url(url: str) -> bool:
    try:
        return urlsplit(url or "").scheme in _ALLOWED_SCHEMES and bool(urlsplit(url).netloc)
    except ValueError:
        return False


def _post(url: str, body: bytes, headers: dict, timeout: float) -> None:
    """POST raw bytes; raise on any transport/HTTP error (the caller turns that into a result)."""
    req = urllib.request.Request(url, data=body, method="POST")
    for k, v in headers.items():
        req.add_header(k, v)
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # operator-configured sink URL
        resp.read()


def _fail_reason(exc: Exception) -> str:
    """A short, URL-free reason (never echo the sink URL / token into a log or result)."""
    if isinstance(exc, urllib.error.HTTPError):
        return f"HTTP {exc.code}"
    if isinstance(exc, urllib.error.URLError):
        return f"connection error: {getattr(exc, 'reason', exc)}"
    return f"{type(exc).__name__}: {exc}"


class Sink:
    """A notification destination. Subclasses turn a summary into a signed/formatted POST.

    A Jira/Linear sink is a trivial addition: subclass, set ``name`` + ``url``, and implement
    :meth:`build` to return the request body and headers for that API."""

    name = "sink"

    def __init__(self, url: str):
        self.url = url

    def build(self, summary: dict) -> tuple[bytes, dict]:
        """Return ``(raw_body, headers)`` to POST for this summary."""
        raise NotImplementedError

    def deliver(self, summary: dict, *, timeout: float = DEFAULT_TIMEOUT) -> dict:
        """POST the summary. Returns a result dict and NEVER raises. No URL/secret is included."""
        result = {"sink": self.name, "count": len(summary.get("findings", []))}
        try:
            body, headers = self.build(summary)
            _post(self.url, body, headers, timeout)
            result["posted"] = True
        except (urllib.error.URLError, urllib.error.HTTPError, OSError, ValueError, TimeoutError) as exc:
            result["posted"] = False
            result["reason"] = _fail_reason(exc)
        return result


class WebhookSink(Sink):
    """Generic signed webhook: POST the JSON summary, sign the raw body when a secret is set."""

    name = "webhook"

    def __init__(self, url: str, secret: bytes | str = b""):
        super().__init__(url)
        self.secret = secret or b""

    def build(self, summary: dict) -> tuple[bytes, dict]:
        body = _body_bytes(summary)
        headers = {"Content-Type": "application/json", "User-Agent": "rampart"}
        if self.secret:
            headers["X-Rampart-Signature"] = sign_body(body, self.secret)
        return body, headers

    def deliver(self, summary: dict, *, timeout: float = DEFAULT_TIMEOUT) -> dict:
        result = super().deliver(summary, timeout=timeout)
        result["signed"] = bool(self.secret)
        if not self.secret:
            result["note"] = "unsigned: set RAMPART_WEBHOOK_SECRET to sign the body"
        return result


def slack_text(summary: dict) -> str:
    """A readable Slack message body for a summary (scrubbed upstream)."""
    run = summary.get("run", {}) or {}
    findings = summary.get("findings", []) or []
    app = run.get("application") or "target"
    header = f"Rampart: {len(findings)} new confirmed finding(s) for {app}"
    counts = summary.get("counts", {}) or {}
    order = ("critical", "high", "medium", "low", "info")
    badge = " · ".join(f"{counts[s]} {s}" for s in order if counts.get(s))
    lines = [header + (f" — {badge}" if badge else "")]
    for it in findings[:20]:
        loc = f" ({it['endpoint']})" if it.get("endpoint") else ""
        lines.append(f"• [{it['severity']}] {it['title']}{loc}")
    if len(findings) > 20:
        lines.append(f"…and {len(findings) - 20} more")
    return "\n".join(lines)


class SlackSink(Sink):
    """Slack incoming webhook: POST ``{"text": ...}``."""

    name = "slack"

    def build(self, summary: dict) -> tuple[bytes, dict]:
        body = json.dumps({"text": slack_text(summary)}).encode("utf-8")
        return body, {"Content-Type": "application/json", "User-Agent": "rampart"}


def build_sinks(webhook_url: str = "", slack_url: str = "", webhook_secret: bytes | str = b"") -> list[Sink]:
    """Build the configured sinks, skipping any with a missing or non-http(s) URL."""
    sinks: list[Sink] = []
    if webhook_url and _valid_url(webhook_url):
        sinks.append(WebhookSink(webhook_url, webhook_secret))
    if slack_url and _valid_url(slack_url):
        sinks.append(SlackSink(slack_url))
    return sinks


# ------------------------------------------------------------------ idempotency manifest
def _manifest_path(work_dir: str) -> str:
    return os.path.join(work_dir or "", NOTIFIED_FILE)


def load_notified(work_dir: str) -> dict[str, set[str]]:
    """Per-sink sets of already-notified identities. Missing/corrupt manifest -> empty (robust)."""
    try:
        with open(_manifest_path(work_dir), encoding="utf-8") as fh:
            data = json.load(fh)
        sinks = data.get("sinks", {}) if isinstance(data, dict) else {}
        out: dict[str, set[str]] = {}
        for name, ids in (sinks or {}).items():
            if isinstance(ids, list):
                out[str(name)] = {str(i) for i in ids}
        return out
    except (OSError, ValueError, TypeError, AttributeError):
        return {}


def save_notified(work_dir: str, notified: dict[str, set[str]]) -> None:
    """Persist the per-sink identity sets. Best-effort: a write error never breaks a scan."""
    payload = {
        "version": _MANIFEST_VERSION,
        "sinks": {name: sorted(ids) for name, ids in notified.items()},
    }
    try:
        os.makedirs(work_dir or ".", exist_ok=True)
        with open(_manifest_path(work_dir), "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)
    except OSError:
        pass


# ------------------------------------------------------------------ orchestration
def notify(
    findings,
    *,
    work_dir: str,
    webhook_url: str = "",
    slack_url: str = "",
    webhook_secret: bytes | str = b"",
    application: str = "",
    target: str = "",
    engagement_id: str = "",
    timeout: float = DEFAULT_TIMEOUT,
) -> dict:
    """Send NEW confirmed findings to every configured sink. Opt-in and failure-safe.

    Returns ``{"enabled", "sinks": [<per-sink result>], "sent"}``; ``enabled`` is False (and no
    HTTP is made) when no sink is configured. A finding is recorded as notified for a sink only
    once that sink's POST succeeds, so a failed sink retries on the next run and a succeeding sink
    never double-notifies. The returned structure never contains the secret or a sink URL."""
    sinks = build_sinks(webhook_url, slack_url, webhook_secret)
    if not sinks:
        return {"enabled": False, "sinks": [], "sent": 0}

    items = confirmed_items(findings)
    run_meta = {"application": application, "target": target, "engagement_id": engagement_id}
    notified = load_notified(work_dir)
    results = []
    sent = 0
    changed = False
    for sink in sinks:
        seen = notified.setdefault(sink.name, set())
        new_items = [it for it in items if it["identity"] not in seen]
        if not new_items:
            results.append({"sink": sink.name, "posted": True, "count": 0, "note": "nothing new"})
            continue
        summary = build_summary(new_items, run=run_meta)
        res = sink.deliver(summary, timeout=timeout)
        results.append(res)
        if res.get("posted"):
            sent += res.get("count", 0)
            # advance the cursor only for identities that actually resolve to a key
            for it in new_items:
                if it["identity"]:
                    seen.add(it["identity"])
                    changed = True
    if changed:
        save_notified(work_dir, notified)
    return {"enabled": True, "sinks": results, "sent": sent}
