"""LLM VAPT track — OWASP LLM Top 10 probes proven both ways against the demo LLM target."""
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
LLM_DEMO = os.path.join(PLATFORM, "examples", "demo_target", "vulnerable_llm.py")
sys.path.insert(0, PLATFORM)

from rampart.engagement import Engagement, EngagementConfig  # noqa: E402

# Must match SYSTEM_CANARY in examples/demo_target/vulnerable_llm.py
CANARY = "SK-DEMO-CANARY-9f3a2b17"
_APPROVE = lambda req, dec: {"granted": True, "approver_user_id": "test"}


class LLMServer:
    def __init__(self, fixed):
        cmd = [sys.executable, LLM_DEMO, "--port", "0", "--host", "127.0.0.1"]
        if fixed:
            cmd.append("--fixed")
        self.proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        line = self.proc.stdout.readline()
        m = re.search(r"http://127\.0\.0\.1:(\d+)", line)
        if not m:
            raise RuntimeError(f"demo-llm did not start: {line!r}")
        self.port = int(m.group(1))
        for _ in range(50):
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{self.port}/", timeout=1)
                break
            except Exception:  # noqa: BLE001
                time.sleep(0.1)

    def stop(self):
        self.proc.terminate()
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()


def _scope(tmp_path, port):
    scope = f"""apiVersion: security-agent/v1
kind: EngagementScope
authorization:
  owner: "t@localhost"
  authorized_by: "t@localhost"
  ticket: "LLM-0001"
  attestation: "I own this local LLM target."
  expires: "2099-12-31T23:59:59Z"
scope:
  in_scope:
    - host: "127.0.0.1"
      ports: [{port}]
      paths_include: ["/chat", "/"]
      methods: ["GET", "POST"]
  out_of_scope:
    paths_exclude: []
    hosts_exclude: []
  resolved_ip_allowlist: ["127.0.0.1/32"]
limits:
  max_requests_per_host_per_min: 500
  max_total_requests: 5000
  max_concurrent_workers: 2
  budget_usd: 5.0
  max_tokens: 1000000
action_policy:
  default_tier_ceiling: 1
  tier2_requires_approval: true
  tier3: deny
test_accounts: []
notify: {{}}
"""
    p = tmp_path / "SECURITY.md"
    p.write_text(scope, encoding="utf-8")
    (tmp_path / "secrets.json").write_text("{}", encoding="utf-8")
    return str(p)


def _engagement(tmp_path, port):
    cfg = EngagementConfig(
        scope_file=_scope(tmp_path, port), target=f"http://127.0.0.1:{port}",
        work_dir=str(tmp_path / ".rampart"), application="demo-llm",
        llm_chat_path="/chat", llm_input_field="message", llm_output_field="reply",
        llm_canary=CANARY, approver=_APPROVE)
    return Engagement(cfg)


@pytest.fixture
def llm_vuln():
    s = LLMServer(fixed=False)
    yield s
    s.stop()


@pytest.fixture
def llm_fixed():
    s = LLMServer(fixed=True)
    yield s
    s.stop()


def test_llm_vulnerable_confirms_injection_and_leak(tmp_path, llm_vuln):
    res = _engagement(tmp_path, llm_vuln.port).run_llm()
    confirmed = [f for f in res.findings if f.verification.validated]
    classes = {f.tags[-1] for f in confirmed}
    assert "llm01-direct-injection" in classes, "prompt injection must be confirmed"
    assert "llm06-system-prompt-leak" in classes, "system-prompt/secret leak must be confirmed"
    for f in confirmed:
        assert f.owasp.get("llm_2025"), "LLM findings carry an OWASP LLM mapping"
        assert f.verification.reproductions >= 2
        f.assert_consistent()


def test_llm_fixed_confirms_nothing(tmp_path, llm_fixed):
    res = _engagement(tmp_path, llm_fixed.port).run_llm()
    confirmed = [f for f in res.findings if f.verification.validated]
    assert not confirmed, f"guardrailed LLM must yield no confirmed findings: {[f.title for f in confirmed]}"


def test_llm_requests_are_audited(tmp_path, llm_vuln):
    eng = _engagement(tmp_path, llm_vuln.port)
    eng.run_llm()
    ok, msg = eng.audit.verify_chain()
    assert ok, msg
    # every LLM prompt was a Tier-2 POST that passed through the policy pipeline
    events = eng.audit.read_all()
    assert any((e.action or {}).get("method") == "POST" for e in events)
