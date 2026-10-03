"""Credential vault indirection.

The model never holds raw credentials (blueprint section 23, threat #3). Test-account
secrets are referenced by ``secret_ref`` (e.g. ``vault://eng/user_a``) and resolved here.
For the MVP demo we ship a file-backed provider; a real deployment backs this with a
KMS/secrets manager. Secrets are never written to the audit log or evidence.
"""
from __future__ import annotations

import json
import os


class SecretsProvider:
    def resolve(self, secret_ref: str) -> dict:
        raise NotImplementedError


class DictSecretsProvider(SecretsProvider):
    def __init__(self, mapping: dict[str, dict]):
        self._m = dict(mapping)

    def resolve(self, secret_ref: str) -> dict:
        if secret_ref not in self._m:
            raise KeyError(f"no secret for ref {secret_ref!r}")
        return self._m[secret_ref]


class FileSecretsProvider(SecretsProvider):
    """Reads a local JSON file mapping secret_ref -> {"username":..., "password":...}.

    The file should be gitignored. Missing file or missing ref raises (fail-closed).
    """

    def __init__(self, path: str):
        self.path = path
        if not os.path.exists(path):
            raise FileNotFoundError(f"secrets file not found: {path}")
        with open(path, "r", encoding="utf-8") as fh:
            self._m = json.load(fh)

    def resolve(self, secret_ref: str) -> dict:
        if secret_ref not in self._m:
            raise KeyError(f"no secret for ref {secret_ref!r} in {self.path}")
        return self._m[secret_ref]
