"""Session manager for seeded test accounts.

Authenticates seeded, non-production principals with credentials resolved from the vault,
caches their tokens, and injects them into requests. The LLM never sees a raw token — it
only references an account id (``use_session``). Establishing a *fresh* session on demand
is what lets the validator "reproduce from a clean state" (blueprint section 21).

Authenticating our own seeded accounts is a setup operation (we own these credentials), but
the login request still goes through the policy choke-point: with a pipeline attached it is
executed via :meth:`PolicyPipeline.execute_setup` (scope host/port/scheme/path/method,
resolved-IP allowlist, expiry, budget, before/after audit — the risk tier/approval stages are
skipped because a login is not an attack action). Credentials are never sent to a port, path
or host the scope contract does not cover.
"""

from __future__ import annotations

import http.client
import json
import threading
from dataclasses import dataclass, field

from ..schemas.audit import AuditEvent
from ..schemas.toolcall import ToolAction, ToolCallRequest
from .credentials import SecretsProvider
from .http_client import raw_request


@dataclass
class LoginConfig:
    scheme: str = "http"
    host: str = "127.0.0.1"
    port: int = 8080
    path: str = "/api/login"
    method: str = "POST"
    username_field: str = "username"
    password_field: str = "password"
    token_json_path: str = "token"  # dotted path into the JSON response
    auth_header: str = "Authorization"
    auth_scheme: str = "Bearer"
    extra_headers: dict = field(default_factory=dict)


class SessionError(RuntimeError):
    pass


def _dig(obj, dotted: str):
    cur = obj
    for part in dotted.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


class SessionManager:
    """Seeded-account session cache.

    When a :class:`~rampart.policy.PolicyPipeline` is attached (``pipeline=`` or
    :meth:`attach_pipeline`; a pipeline attaches itself to its executor's session manager),
    every login goes through :meth:`PolicyPipeline.execute_setup`. Without a pipeline the same
    deterministic expiry + allowlist + scope checks run locally (no budget) and the login is
    audited. With no scope at all, login is refused (fail-closed).
    """

    def __init__(
        self, scope, secrets: SecretsProvider, login: LoginConfig, resolver, audit_log=None, pipeline=None
    ):
        self.scope = scope
        self.secrets = secrets
        self.login = login
        self.resolver = resolver
        self.audit = audit_log
        self.pipeline = pipeline
        self._tokens: dict[str, str] = {}
        # One lock guards the cache dict; per-account locks let different accounts
        # authenticate in parallel while the *same* account dedupes to a single login.
        self._cache_lock = threading.Lock()
        self._acct_locks: dict[str, threading.Lock] = {}

    def attach_pipeline(self, pipeline) -> None:
        """Route all subsequent logins through ``pipeline`` (scope + budget + audit)."""
        self.pipeline = pipeline

    def _acct_lock(self, account_id: str) -> threading.Lock:
        with self._cache_lock:
            lock = self._acct_locks.get(account_id)
            if lock is None:
                lock = threading.Lock()
                self._acct_locks[account_id] = lock
            return lock

    # ------------------------------------------------------------- login I/O
    def _login_action(self, body: str) -> ToolAction:
        lc = self.login
        headers = {"Content-Type": "application/json", **(lc.extra_headers or {})}
        return ToolAction(
            method=str(lc.method or "").upper(),
            target_host=str(lc.host or "").lower(),
            port=lc.port,
            scheme=str(lc.scheme or "").lower(),
            path=lc.path,
            body=body,
            body_class="json",
            headers=headers,
            payload_class="canary",
        )

    def _send(self, action: ToolAction, resolved_ip: str):
        try:
            return raw_request(
                action.scheme,
                action.target_host,
                action.port,
                resolved_ip,
                action.method,
                action.path,
                headers=dict(action.headers),
                body=action.body,
            )
        except (OSError, http.client.HTTPException, ValueError) as exc:
            raise SessionError(
                f"login request to {action.scheme}://{action.target_host}:{action.port}{action.path} "
                f"failed: {exc}"
            ) from exc

    def _do_login(self, account_id: str, body: str):
        """Perform the login request through the policy layer. Returns (response, resolved_ip)."""
        if self.scope is None:
            raise SessionError("no scope contract bound to the session manager; refusing to log in")
        action = self._login_action(body)
        if self.pipeline is not None:
            req = ToolCallRequest(
                engagement_id=self.scope.authorization.ticket or "engagement",
                tool="login",
                phase="setup",
                actor_role="session-manager",
                action=action,
                rationale=f"seeded-account login for {account_id}",
            )
            res = self.pipeline.execute_setup(req, self._send)
            if not res.executed:
                raise SessionError(f"login for {account_id!r} not performed: {res.blocked_reason}")
            return res.response, res.resolved_ip

        # Standalone (no pipeline attached): the same deterministic checks, locally.
        from ..policy import allowlist, scope_validator

        if self.scope.is_expired():
            raise SessionError("scope contract expired; refusing to log in (fail-closed)")
        al = allowlist.check(self.scope, action, self.resolver)
        if not al.ok:
            raise SessionError(f"login refused by allowlist: {al.reason}")
        sc = scope_validator.check(self.scope, action)
        if not sc.ok:
            raise SessionError(f"login refused by scope: {sc.reason}")
        resp = self._send(action, al.resolved_ip)
        self._audit_session(account_id, al.resolved_ip, getattr(resp, "status", None))
        return resp, al.resolved_ip

    def establish(self, account_id: str, fresh: bool = False) -> str:
        if not fresh:
            with self._cache_lock:
                cached = self._tokens.get(account_id)
            if cached is not None:
                return cached
        # Serialize logins for this one account so parallel callers don't all hit /login.
        with self._acct_lock(account_id):
            if not fresh:
                with self._cache_lock:
                    cached = self._tokens.get(account_id)
                if cached is not None:
                    return cached
            acct = self.scope.account(account_id) if self.scope is not None else None
            if acct is None:
                raise SessionError(f"unknown seeded account {account_id!r}")
            creds = self.secrets.resolve(acct.secret_ref)
            body = json.dumps(
                {
                    self.login.username_field: creds["username"],
                    self.login.password_field: creds["password"],
                }
            )
            resp, _ip = self._do_login(account_id, body)
            if resp.status != 200:
                raise SessionError(f"login for {account_id!r} failed with HTTP {resp.status}")
            try:
                token = _dig(json.loads(resp.body), self.login.token_json_path)
            except json.JSONDecodeError as exc:
                raise SessionError(f"login response for {account_id!r} was not JSON: {exc}") from exc
            if not token:
                raise SessionError(f"no token at {self.login.token_json_path!r} for {account_id!r}")
            with self._cache_lock:
                self._tokens[account_id] = token
            return token

    def fresh_session(self, account_id: str) -> str:
        return self.establish(account_id, fresh=True)

    def auth_headers(self, account_id: str) -> dict:
        if account_id is None:
            return {}
        token = self.establish(account_id)
        value = f"{self.login.auth_scheme} {token}".strip()
        return {self.login.auth_header: value}

    def _audit_session(self, account_id: str, ip: str, status=None) -> None:
        if self.audit is None:
            return
        self.audit.append(
            AuditEvent(
                engagement_id=self.scope.authorization.ticket or "engagement",
                phase="setup",
                actor={"type": "system", "agent_role": "session-manager"},
                action={
                    "tool": "login",
                    "method": self.login.method,
                    "scheme": self.login.scheme,
                    "target_host": self.login.host,
                    "port": self.login.port,
                    "resolved_ip": ip,
                    "path": self.login.path,
                    "account": account_id,
                },
                policy_decision={
                    "decision": "ALLOW",
                    "reason": "seeded-account session establishment (scope + allowlist checked locally)",
                },
                execution={"status": "executed", "response_status": status},
            )
        )
