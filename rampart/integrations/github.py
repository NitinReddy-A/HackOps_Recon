"""Post (or update) a Rampart report as a GitHub pull-request comment.

Stdlib only (``urllib``). It keeps a single *sticky* comment per PR: it finds the previous Rampart
comment by a hidden marker and edits it, so re-runs don't pile up. Everything is graceful — if the
token, repo, or PR number is missing, or the API call fails, it returns a result dict with
``posted=False`` and a reason, and never raises.

In GitHub Actions the context (repo, PR number, token) is read from the environment automatically;
pass ``repo`` / ``pr`` / ``token`` explicitly to override or to run outside Actions.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

from ..reporting.pr_comment import MARKER


def _event_pr_number() -> int | None:
    path = os.environ.get("GITHUB_EVENT_PATH")
    if path and os.path.isfile(path):
        try:
            with open(path, encoding="utf-8") as fh:
                event = json.load(fh)
            num = (event.get("pull_request") or {}).get("number")
            if num:
                return int(num)
            num = (event.get("issue") or {}).get("number")
            if num:
                return int(num)
        except (OSError, ValueError, TypeError):
            pass
    ref = os.environ.get("GITHUB_REF", "")  # refs/pull/<n>/merge
    parts = ref.split("/")
    if len(parts) >= 3 and parts[1] == "pull" and parts[2].isdigit():
        return int(parts[2])
    return None


def resolve_context(repo: str | None = None, pr: int | None = None, token: str | None = None) -> dict:
    """Resolve (repo, pr, token, api_url) from arguments, falling back to the GitHub Actions env."""
    return {
        "repo": repo or os.environ.get("GITHUB_REPOSITORY", ""),
        "pr": pr if pr is not None else _event_pr_number(),
        "token": token or os.environ.get("GITHUB_TOKEN", ""),
        "api_url": os.environ.get("GITHUB_API_URL", "https://api.github.com").rstrip("/"),
    }


def _request(method: str, url: str, token: str, body: dict | None = None, timeout: float = 20.0):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("X-GitHub-Api-Version", "2022-11-28")
    req.add_header("User-Agent", "rampart")
    if data is not None:
        req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - fixed GitHub API host
        raw = resp.read().decode("utf-8", errors="replace")
    return json.loads(raw) if raw else {}


def _find_sticky(api_url: str, repo: str, pr: int, token: str) -> int | None:
    page = 1
    while page <= 10:
        url = f"{api_url}/repos/{repo}/issues/{pr}/comments?per_page=100&page={page}"
        batch = _request("GET", url, token)
        if not isinstance(batch, list) or not batch:
            return None
        for c in batch:
            if MARKER in (c.get("body") or ""):
                return c.get("id")
        if len(batch) < 100:
            return None
        page += 1
    return None


def post_or_update_comment(
    body: str,
    *,
    repo: str | None = None,
    pr: int | None = None,
    token: str | None = None,
    api_url: str | None = None,
) -> dict:
    """Create or update the sticky Rampart comment on a PR. Returns a result dict; never raises."""
    ctx = resolve_context(repo, pr, token)
    repo, pr, token = ctx["repo"], ctx["pr"], ctx["token"]
    api_url = api_url or ctx["api_url"]
    if not token:
        return {"posted": False, "reason": "no GITHUB_TOKEN available"}
    if not repo:
        return {"posted": False, "reason": "no repository (set GITHUB_REPOSITORY or pass repo=)"}
    if not pr:
        return {"posted": False, "reason": "no pull-request number (not a PR event? pass pr=)"}
    try:
        existing = _find_sticky(api_url, repo, pr, token)
        if existing:
            res = _request(
                "PATCH", f"{api_url}/repos/{repo}/issues/comments/{existing}", token, {"body": body}
            )
            return {"posted": True, "action": "updated", "url": res.get("html_url", ""), "id": existing}
        res = _request("POST", f"{api_url}/repos/{repo}/issues/{pr}/comments", token, {"body": body})
        return {"posted": True, "action": "created", "url": res.get("html_url", ""), "id": res.get("id")}
    except (urllib.error.URLError, urllib.error.HTTPError, OSError, ValueError) as exc:
        return {"posted": False, "reason": f"GitHub API error: {exc}"}
