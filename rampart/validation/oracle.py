"""The BOLA/IDOR differential validation oracle (blueprint section 31).

A cross-account ``200`` is NOT automatically a finding. The oracle re-derives proof with
baselines, the probe, and negative controls, and requires the victim's *actual* seeded data
in the response plus 2+ reproductions from clean sessions. This is the deterministic
false-positive gate — not an LLM guess.

    leak = probe.200
           AND victim's signature present in probe body
           AND probe body != attacker's own object      (not an echo-your-own endpoint)
           AND victim-owns-their-object baseline == 200  (endpoint works normally)
           AND unauth in (401,403)                       (auth IS enforced; defect is ownership)
           AND absent in (403,404)                       (200 for a missing id would be generic)
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..executor.differ import contains_signature, diff_summary


@dataclass
class OracleVerdict:
    validated: bool
    vuln_class: str
    reasons: list = field(default_factory=list)
    false_positive_checks: list = field(default_factory=list)
    reproductions: int = 0
    evidence: list = field(default_factory=list)
    diff: dict = field(default_factory=dict)
    controls: dict = field(default_factory=dict)
    # Control health. ``controls_ok`` is False when the baselines that make a verdict meaningful
    # failed (target down/erroring, owner can't read their own object). ``inconclusive`` means a
    # "not validated" result must NOT be read as "fixed". Defaults keep oracles that don't set
    # them behaving exactly as before.
    controls_ok: bool = True
    inconclusive: bool = False


def _path_for(hyp: dict, object_id: str) -> str:
    param = hyp["selector_param"]
    return hyp["endpoint_path"].replace("{" + param + "}", str(object_id))


def run_bola_oracle(
    runner, session_manager, hyp: dict, reproductions: int = 2, fresh_sessions: bool = True
) -> OracleVerdict:
    attacker = hyp["attacker_principal"]
    victim = hyp["victim_principal"]
    atk_obj = hyp["attacker_object"]
    vic_obj = hyp["victim_object"]
    vic_sig = vic_obj.get("signature", "")
    nonexistent = "999999999"

    if fresh_sessions and session_manager is not None:
        # reproduce-from-clean-state: brand-new sessions for both principals
        session_manager.fresh_session(attacker)
        session_manager.fresh_session(victim)

    hid = hyp.get("id")
    b_own = runner.get(
        _path_for(hyp, atk_obj["id"]),
        session=attacker,
        rationale="baseline: attacker reads own object",
        hypothesis_id=hid,
        summary="baseline attacker-own",
    )
    a_own = runner.get(
        _path_for(hyp, vic_obj["id"]),
        session=victim,
        rationale="baseline: victim reads own object",
        hypothesis_id=hid,
        summary="baseline victim-own",
    )
    probe = runner.get(
        _path_for(hyp, vic_obj["id"]),
        session=attacker,
        rationale="probe: attacker reads victim's object (cross-account)",
        hypothesis_id=hid,
        summary="probe cross-account",
    )
    unauth = runner.get(
        _path_for(hyp, vic_obj["id"]),
        session=None,
        payload_class="benign-read",
        rationale="negative control: unauthenticated read",
        hypothesis_id=hid,
        summary="control unauth",
    )
    absent = runner.get(
        _path_for(hyp, nonexistent),
        session=attacker,
        rationale="negative control: nonexistent object id",
        hypothesis_id=hid,
        summary="control absent",
    )

    reasons, fp = [], []
    checks = {
        "probe_status": probe.status,
        "victim_own_status": a_own.status,
        "attacker_own_status": b_own.status,
        "unauth_status": unauth.status,
        "absent_status": absent.status,
    }

    sig_present = contains_signature(probe.body, vic_sig)
    not_echo = probe.body != b_own.body
    endpoint_ok = a_own.status == 200
    auth_enforced = unauth.status in (401, 403)
    absent_ok = absent.status in (403, 404)
    probe_200 = probe.status == 200

    def note(ok, msg):
        (reasons if ok else reasons).append(("PASS" if ok else "FAIL") + ": " + msg)
        return ok

    all_ok = True
    all_ok &= note(probe_200, f"cross-account probe returned {probe.status} (want 200)")
    all_ok &= note(sig_present, f"victim signature {'found' if sig_present else 'absent'} in probe body")
    all_ok &= note(not_echo, "probe body differs from attacker's own object (not an echo endpoint)")
    all_ok &= note(endpoint_ok, f"victim reading own object works ({a_own.status})")
    fp.append(
        f"unauthenticated -> {unauth.status} "
        + ("(auth enforced)" if auth_enforced else "(WEAK: auth not enforced)")
    )
    all_ok &= note(auth_enforced, "authentication is enforced (defect isolated to ownership)")
    fp.append(
        f"nonexistent id -> {absent.status} "
        + ("(distinguishes real leak)" if absent_ok else "(WARN: generic 200?)")
    )
    all_ok &= note(absent_ok, "nonexistent id is rejected (probe 200 is a real object, not a generic body)")

    # reproductions from clean state
    repro_ok = 0
    if all_ok:
        for i in range(reproductions):
            if fresh_sessions and session_manager is not None:
                session_manager.fresh_session(attacker)
            r = runner.get(
                _path_for(hyp, vic_obj["id"]),
                session=attacker,
                rationale=f"reproduction #{i + 1} from clean session",
                hypothesis_id=hid,
                summary=f"reproduction {i + 1}",
            )
            if r.status == 200 and contains_signature(r.body, vic_sig):
                repro_ok += 1
        fp.append(f"reproduced {repro_ok}/{reproductions} times from clean sessions")

    validated = all_ok and repro_ok >= reproductions

    # Control health: without working baselines a negative result says nothing about the fix.
    executed_all = all(getattr(o, "executed", True) for o in (b_own, a_own, probe, unauth, absent))
    controls_ok = (
        executed_all
        and a_own.status == 200
        and contains_signature(a_own.body, vic_sig)
        and isinstance(b_own.status, int)
        and 200 <= b_own.status < 300
    )
    # A real denial: the cross-account read is refused, or succeeds without the victim's data.
    probe_denied = probe.status in (401, 403, 404) or (
        isinstance(probe.status, int) and 200 <= probe.status < 300 and not sig_present
    )
    inconclusive = (not validated) and not (controls_ok and probe_denied)
    if not controls_ok:
        fp.append(
            "INCONCLUSIVE: baseline controls failed "
            f"(executed={executed_all}, victim-own={a_own.status}, attacker-own={b_own.status})"
        )
    elif inconclusive:
        fp.append(f"INCONCLUSIVE: probe returned {probe.status}, not a clear denial")

    evidence = []
    for outcome in (b_own, a_own, probe, unauth, absent):
        evidence.extend(outcome.evidence)

    return OracleVerdict(
        validated=validated,
        vuln_class=hyp.get("vuln_class", "IDOR/BOLA"),
        reasons=reasons,
        false_positive_checks=fp,
        reproductions=repro_ok,
        evidence=evidence,
        diff=diff_summary(b_own.response, probe.response),
        controls=checks,
        controls_ok=controls_ok,
        inconclusive=inconclusive,
    )
