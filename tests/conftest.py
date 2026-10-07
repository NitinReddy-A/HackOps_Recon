"""Shared pytest fixtures: an ephemeral, isolated demo target + a temp engagement.

Every test runs against a throwaway instance of the intentionally-vulnerable demo app on a
random loopback port (blueprint section 25: isolated, offline, no route to any real asset).
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
import urllib.request

import pytest

HERE = os.path.dirname(__file__)
PLATFORM = os.path.abspath(os.path.join(HERE, ".."))
DEMO = os.path.join(PLATFORM, "examples", "demo_target", "vulnerable_app.py")
sys.path.insert(0, PLATFORM)


def _wait_healthy(base_url, tries=50):
    for _ in range(tries):
        try:
            urllib.request.urlopen(base_url + "/", timeout=1)
            return True
        except Exception:  # noqa: BLE001
            time.sleep(0.1)
    return False


class Server:
    def __init__(self, fixed: bool):
        cmd = [sys.executable, DEMO, "--port", "0", "--host", "127.0.0.1"]
        if fixed:
            cmd.append("--fixed")
        self.proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        line = self.proc.stdout.readline()
        m = re.search(r"http://127\.0\.0\.1:(\d+)", line)
        if not m:
            raise RuntimeError(f"demo target did not start: {line!r}")
        self.port = int(m.group(1))
        self.base_url = f"http://127.0.0.1:{self.port}"
        assert _wait_healthy(self.base_url), "demo target not healthy"

    def stop(self):
        self.proc.terminate()
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()


@pytest.fixture
def vuln_server():
    s = Server(fixed=False)
    yield s
    s.stop()


@pytest.fixture
def fixed_server():
    s = Server(fixed=True)
    yield s
    s.stop()


def write_engagement(tmp_path, port, ceiling=1) -> str:
    """Write SECURITY.md + secrets + openapi + seed into tmp_path; return the scope path."""
    scope = f"""apiVersion: security-agent/v1
kind: EngagementScope
authorization:
  owner: "t@localhost"
  authorized_by: "t@localhost"
  ticket: "TEST-0001"
  attestation: "I own this local test target."
  expires: "2099-12-31T23:59:59Z"
scope:
  in_scope:
    - host: "127.0.0.1"
      ports: [{port}]
      paths_include: ["/**"]
      methods: ["GET", "POST"]
  out_of_scope:
    paths_exclude: ["/api/admin/**"]
    hosts_exclude: []
  resolved_ip_allowlist: ["127.0.0.1/32"]
limits:
  max_requests_per_host_per_min: 500
  max_total_requests: 5000
  max_concurrent_workers: 2
  budget_usd: 5.0
  max_tokens: 1000000
action_policy:
  default_tier_ceiling: {ceiling}
  tier2_requires_approval: true
  tier3: deny
test_accounts:
  - {{ id: user_a, role: customer, secret_ref: "vault://demo/user_a" }}
  - {{ id: user_b, role: customer, secret_ref: "vault://demo/user_b" }}
notify:
  on_start: ["t@localhost"]
"""
    (tmp_path / "SECURITY.md").write_text(scope, encoding="utf-8")
    (tmp_path / "secrets.json").write_text(json.dumps({
        "vault://demo/user_a": {"username": "user_a", "password": "demo-pw-a"},
        "vault://demo/user_b": {"username": "user_b", "password": "demo-pw-b"},
    }), encoding="utf-8")
    (tmp_path / "openapi.json").write_text(json.dumps({
        "openapi": "3.0.0", "info": {"title": "t", "version": "1"},
        "paths": {
            "/api/login": {"post": {"security": []}},
            "/api/orders/{id}": {"get": {"security": [{"bearerAuth": []}]}},
            "/api/search": {"get": {"security": [],
                "parameters": [{"name": "q", "in": "query", "schema": {"type": "string"}}]}},
            "/api/products": {"get": {"security": [],
                "parameters": [{"name": "id", "in": "query", "schema": {"type": "string"}}]}},
            "/api/go": {"get": {"security": [],
                "parameters": [{"name": "next", "in": "query", "schema": {"type": "string"}}]}},
            "/api/fetch": {"get": {"security": [],
                "parameters": [{"name": "url", "in": "query", "schema": {"type": "string"}}]}},
            "/api/ping": {"get": {"security": [],
                "parameters": [{"name": "host", "in": "query", "schema": {"type": "string"}}]}},
            "/api/file": {"get": {"security": [],
                "parameters": [{"name": "name", "in": "query", "schema": {"type": "string"}}]}},
            "/api/reports/orders": {"get": {"security": [{"bearerAuth": []}]}},
            "/api/profile": {"get": {"security": [{"bearerAuth": []}]}},
            "/api/greet": {"get": {"security": [],
                "parameters": [{"name": "name", "in": "query", "schema": {"type": "string"}}]}},
            "/api/me": {"get": {"security": [{"bearerAuth": []}]}},
        },
    }), encoding="utf-8")
    (tmp_path / "seed.json").write_text(json.dumps({
        "roles": ["customer"],
        "endpoint_hints": [{"path": "/api/orders/{id}", "method": "GET",
                            "returns_object_type": "Order",
                            "object_selector": {"param": "id", "in": "path"}}],
        "objects": [
            {"type": "Order", "id": "1043", "owner_principal": "user_a", "seeded": True,
             "signature": "SIGNATURE-A-4f9c1e77"},
            {"type": "Order", "id": "2087", "owner_principal": "user_b", "seeded": True,
             "signature": "SIGNATURE-B-1a2b3c4d"},
        ],
        "permissions": [{"role": "customer", "object_type": "Order", "action": "read",
                         "constraint": "owner_only"}],
    }), encoding="utf-8")
    return str(tmp_path / "SECURITY.md")


def make_engagement(tmp_path, port, repo="", intel="deterministic", ceiling=1):
    from rampart.engagement import Engagement, EngagementConfig
    scope_file = write_engagement(tmp_path, port, ceiling=ceiling)
    cfg = EngagementConfig(
        scope_file=scope_file,
        target=f"http://127.0.0.1:{port}",
        work_dir=str(tmp_path / ".rampart"),
        openapi=str(tmp_path / "openapi.json"),
        appmodel_seed=str(tmp_path / "seed.json"),
        application="demo-shop-api",
        intel=intel,
        repo=repo,
    )
    return Engagement(cfg)
