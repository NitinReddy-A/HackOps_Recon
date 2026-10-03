"""Session manager for seeded test accounts.

Authenticates seeded, non-production principals with credentials resolved from the vault,
caches their tokens, and injects them into requests. The LLM never sees a raw token — it
only references an account id (``use_session``). Establishing a *fresh* session on demand
is what lets the validator "reproduce from a clean state" (blueprint section 21).

Authenticating our own seeded accounts is a setup operation (we own these credentials);
it is recorded in the audit log as a ``system`` event but does not run as an attack action.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field

from ..schemas.audit import AuditEvent
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
    token_json_path: str = "token"        # dotted path into the JSON response
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
    def __init__(self, scope, secrets: SecretsProvider, login: LoginConfig,
                 resolver, audit_log=None):
        self.scope = scope
        self.secrets = secrets
        self.login = login
        self.resolver = resolver
        self.audit = audit_log
        self._tokens: dict[str, str] = {}

    def _resolve_ip(self, host: str) -> str:
        ips = self.resolver(host)
        if not ips or not self.scope.ip_allowed(ips[0]):
            raise SessionError(f"login host {host!r} did not resolve to an allowlisted IP")
        return ips[0]

    def establish(self, account_id: str, fresh: bool = False) -> str:
        if not fresh and account_id in self._tokens:
            return self._tokens[account_id]
        acct = self.scope.account(account_id)
        if acct is None:
            raise SessionError(f"unknown seeded account {account_id!r}")
        creds = self.secrets.resolve(acct.secret_ref)
        body = json.dumps({
            self.login.username_field: creds["username"],
            self.login.password_field: creds["password"],
        })
        ip = self._resolve_ip(self.login.host)
        headers = {"Content-Type": "application/json", **self.login.extra_headers}
        resp = raw_request(self.login.scheme, self.login.host, self.login.port, ip,
                           self.login.method, self.login.path, headers=headers, body=body)
        if resp.status != 200:
            raise SessionError(f"login for {account_id!r} failed with HTTP {resp.status}")
        try:
            token = _dig(json.loads(resp.body), self.login.token_json_path)
        except json.JSONDecodeError as exc:
            raise SessionError(f"login response for {account_id!r} was not JSON: {exc}") from exc
        if not token:
            raise SessionError(f"no token at {self.login.token_json_path!r} for {account_id!r}")
        self._tokens[account_id] = token
        self._audit_session(account_id, ip, fresh)
        return token

    def fresh_session(self, account_id: str) -> str:
        return self.establish(account_id, fresh=True)

    def auth_headers(self, account_id: str) -> dict:
        if account_id is None:
            return {}
        token = self.establish(account_id)
        value = f"{self.login.auth_scheme} {token}".strip()
        return {self.login.auth_header: value}

    def _audit_session(self, account_id: str, ip: str, fresh: bool) -> None:
        if self.audit is None:
            return
        self.audit.append(AuditEvent(
            engagement_id=self.scope.authorization.ticket or "engagement",
            phase="setup",
            actor={"type": "system", "agent_role": "session-manager"},
            action={"tool": "login", "target_host": self.login.host, "resolved_ip": ip,
                    "path": self.login.path, "account": account_id, "fresh": fresh},
            policy_decision={"decision": "ALLOW", "reason": "seeded-account session establishment"},
            execution={"status": "executed"},
        ))
