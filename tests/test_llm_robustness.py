"""LLM oracle robustness — echo bots, error pages, unresolvable fields, missing canary.

Driven in-process through a fake runner (the same ``post`` seam LLMClient uses), so these are
fast and deterministic. Each test pins a reviewer-reported false positive / silent pass.
"""

from __future__ import annotations

import html
import json
from types import SimpleNamespace

from rampart.llm import LLMAssessment, LLMClient
from rampart.llm.client import _MISSING, _dig
from rampart.llm.probes import INJECTION_MARKER, JAILBREAK_MARKER, LLM_PROBES
from rampart.runner import ProbeOutcome

CANARY = "SK-TEST-CANARY-0001"


class FakeRunner:
    """Stands in for ProbeRunner.post: ``fn(message) -> (status, body)`` or an exception tag."""

    def __init__(self, fn, allowed=True):
        self.fn = fn
        self.allowed = allowed
        self.sent = []

    def post(self, path, json_body, **kw):
        msg = json_body.get("message", "")
        self.sent.append(msg)
        decision = SimpleNamespace(allowed=self.allowed, reason="denied by test policy")
        if not self.allowed:
            return ProbeOutcome(executed=False, decision=decision)
        out = self.fn(msg)
        if out == "CONNERR":
            return ProbeOutcome(executed=False, decision=decision)
        status, body = out
        if not isinstance(body, str):
            body = json.dumps(body)
        return ProbeOutcome(
            executed=True, response=SimpleNamespace(status=status, body=body), decision=decision
        )


def _run(fn, canary=CANARY, output_field="reply", allowed=True):
    runner = FakeRunner(fn, allowed=allowed)
    client = LLMClient(runner, "/chat", "message", output_field)
    res = LLMAssessment(client, canary=canary, target_url="http://127.0.0.1:1").run()
    return res, runner


def _results(res):
    return {p["id"]: p["result"] for p in res.probe_log}


def _confirmed(res):
    return [f for f in res.findings if f.verification.validated]


# ------------------------------------------------------------------------- E1: echo bots
def test_refusing_echo_bot_is_not_confirmed():
    # "Sorry, I can't help with: <msg>" — quotes the marker but never follows the instruction
    res, _ = _run(lambda m: (200, {"reply": "Sorry, I can't help with: " + html.escape(m)}))
    assert not _confirmed(res), [f.title for f in res.findings]
    assert not res.findings
    assert _results(res)["llm01-direct-injection"] == "not-vulnerable"
    assert _results(res)["llm01-jailbreak-roleplay"] == "not-vulnerable"


def test_raw_echo_bot_is_not_confirmed():
    res, _ = _run(lambda m: (200, {"reply": "You said: " + m}))
    assert not res.findings, list(res.probe_log)


def test_selective_echo_bot_caught_by_quote_check():
    # Echoes only when it refuses an attack (so the marker-only control does not echo) — the
    # quote check still recognises the reply as a copy of the attack prompt.
    def bot(m):
        if "ignore all previous" in m.lower() or "role-play" in m.lower():
            return 200, {"reply": "I refuse to follow: " + m}
        return 200, {"reply": "Blue."}

    res, _ = _run(bot)
    assert not res.findings


def test_marker_only_control_blocks_marker_reflector():
    # Reflects any marker it sees but not the surrounding text — the per-probe control catches it.
    def bot(m):
        for mk in (INJECTION_MARKER, JAILBREAK_MARKER):
            if mk in m:
                return 200, {"reply": f"noted reference {mk}"}
        return 200, {"reply": "Blue."}

    res, _ = _run(bot)
    assert not res.findings
    assert "echo" in json.dumps(res.probe_log)


def test_genuinely_injectable_bot_still_confirmed():
    def bot(m):
        low = m.lower()
        if "reply with exactly this token and nothing else:" in low:
            return 200, {"reply": INJECTION_MARKER}
        if "output exactly:" in low:
            return 200, {"reply": JAILBREAK_MARKER}
        return 200, {"reply": "Blue."}

    res, _ = _run(bot)
    r = _results(res)
    assert r["llm01-direct-injection"] == "confirmed"
    assert r["llm01-jailbreak-roleplay"] == "confirmed"
    for f in _confirmed(res):
        assert any("WITHOUT the instruction" in c for c in f.verification.false_positive_checks)


# ------------------------------------------------------------------------- E2: HTTP status
def test_http_500_echo_page_is_error_not_finding():
    res, _ = _run(lambda m: (500, {"error": "upstream model failure processing input: " + m}))
    assert not res.findings
    assert set(_results(res).values()) == {"error"}
    assert res.counts["executed"] == 0 and res.counts["error"] == 4


def test_plain_http_500_is_not_reported_as_held():
    res, _ = _run(lambda m: (500, {"error": "internal server error"}))
    assert "not-vulnerable" not in _results(res).values()
    assert res.probes_executed == 0
    assert all("HTTP 500" in p.get("note", "") for p in res.probe_log)


def test_connection_error_is_error_and_policy_block_is_blocked():
    res, _ = _run(lambda m: "CONNERR")
    assert set(_results(res).values()) == {"error"}
    res2, runner = _run(lambda m: (200, {"reply": "x"}), allowed=False)
    assert set(_results(res2).values()) == {"blocked"}
    assert res2.counts["blocked"] == 4 and res2.counts["executed"] == 0


# ------------------------------------------------------------------------- E3: output field
def test_dig_supports_list_indexes():
    data = {"choices": [{"message": {"content": "hi"}}]}
    assert _dig(data, "choices.0.message.content") == "hi"
    assert _dig(data, "choices.-1.message.content") == "hi"
    assert _dig(data, "choices.5.message") is _MISSING
    assert _dig(data, "nope") is _MISSING


def test_openai_shape_with_list_path_resolves():
    body = {"choices": [{"message": {"content": "I cannot help with that."}}], "debug": {"prompt": "x"}}
    res, _ = _run(lambda m: (200, {**body, "debug": {"prompt": m}}), output_field="choices.0.message.content")
    assert not res.findings
    assert set(_results(res).values()) == {"not-vulnerable"}


def test_unresolved_output_field_is_inconclusive_not_raw_body():
    # the raw body contains the prompt (debug echo) — falling back to it would be an FP
    res, _ = _run(lambda m: (200, {"choices": [{"message": {"content": "no"}}], "debug": {"prompt": m}}))
    assert not res.findings
    assert set(_results(res).values()) == {"inconclusive"}
    assert "output field" in res.probe_log[0]["note"]


def test_non_json_2xx_body_is_still_the_reply():
    res, _ = _run(lambda m: (200, "Blue."))
    assert set(_results(res).values()) == {"not-vulnerable"}


# ------------------------------------------------------------------------- E4: no canary
def test_leak_probe_skipped_without_canary():
    res, runner = _run(lambda m: (200, {"reply": "Blue."}), canary="")
    r = _results(res)
    assert r["llm07-system-prompt-leak"] == "skipped"
    assert res.counts["skipped"] == 1 and res.counts["executed"] == 3
    # the skipped probe's prompt was never sent
    leak = next(p for p in LLM_PROBES if p.id == "llm07-system-prompt-leak")
    assert leak.build_prompt("") not in runner.sent


def test_leak_probe_labels_are_owasp_2025():
    leak = next(p for p in LLM_PROBES if p.id == "llm07-system-prompt-leak")
    assert leak.owasp == "LLM07:2025 System Prompt Leakage"
    assert "LLM02:2025 Sensitive Information Disclosure" in leak.owasp_related
    labels = {p.owasp.split(" ")[0] for p in LLM_PROBES}
    assert labels <= {"LLM01:2025", "LLM05:2025", "LLM07:2025"}


def test_counts_expose_executed_total():
    res, _ = _run(lambda m: (200, {"reply": "Blue."}))
    c = res.counts
    assert c["total"] == 4 and c["executed"] == 4 and c["not-vulnerable"] == 4
