"""Finding-driven escalation — deterministic, bounded, auditable deep-scan fan-out.

When a hypothesis is independently *validated*, the scan has proven a real weakness. A human
assessor would then look harder in that spot: the same parameter via the other injection
classes, the same access-control gap on sibling endpoints that return the same object type.
This module turns that instinct into **deterministic control flow**, so the agentic layer is
*dynamic* (it reacts to results mid-run) without ever going haywire.

Design guarantees (the anti-runaway contract):

* **Control flow is fixed code, never an LLM.** A model may enrich *what* to look at elsewhere,
  but how many follow-ups run, and how deep, is decided here — capped, deduped, and recorded.
* **Escalation never weakens the evidence bar.** Every follow-up is an ordinary hypothesis: it
  runs on the same gated worker and is re-proven by the same independent oracle. An escalated
  finding is ``confirmed`` only when an oracle proves it from a clean state.
* **Hard bounds.** ``max_depth`` (how many escalation hops), ``max_total`` (whole run), and
  ``max_per_finding`` (fan-out from one finding), plus a dedup set keyed on the investigation
  identity, so the same test never runs twice and a finding can never trigger unbounded work.
* **Deterministic.** Follow-ups are generated and admitted in a stable, completion-order-
  independent sequence, so a parallel run escalates to exactly the same set as a serial one.
* **Nothing is silent.** The count admitted and the count dropped by each cap are tallied, so a
  truncated escalation is always visible, never mistaken for "there was nothing more to test".

This module is pure: no I/O, no model calls, no shared mutable state except the explicitly
thread-safe :class:`EscalationBudget`. That keeps it trivially unit-testable and audit-friendly.
"""

from __future__ import annotations

import threading

# Input-injection classes whose signal generalises: a confirmed hit proves the parameter is a
# live, attacker-controlled sink. Any of these CONFIRMED is a valid trigger to look harder on
# that same parameter — the initial enumeration only proposes SSRF/CMDI/traversal/redirect when
# the parameter *name* matches a hint, so an oddly-named sink is otherwise never deep-tested.
INJECTION_CLASSES = ("SQLI", "XSS", "SSTI", "SSRF", "CMDI", "PATH_TRAVERSAL", "OPEN_REDIRECT")

_INJECTION_SET = frozenset(INJECTION_CLASSES)

# Classes that are SAFE TO ESCALATE INTO. Escalation multiplies whatever the oracles do, so a
# follow-up class is only admitted when its oracle proves the class from a clean state with a
# negative control — otherwise escalation would amplify that oracle's false-positive mode into
# a swarm of false findings (precisely the "agent gone haywire" failure). CMDI is deliberately
# EXCLUDED until its oracle stops confirming on plain input reflection (a documented known issue):
# on reflection endpoints it would otherwise manufacture a command-injection finding per hot
# parameter. A confirmed CMDI still *triggers* escalation into the sound classes below; it is
# only excluded as a *target*. Re-add it here once the CMDI oracle requires computed proof.
ESCALATION_INJECTION_CLASSES = ("SQLI", "XSS", "SSTI", "SSRF", "PATH_TRAVERSAL", "OPEN_REDIRECT")


def escalation_identity(hyp: dict) -> str:
    """The investigation identity used for dedup: (class, method, path, param).

    Two hypotheses with the same identity test the same thing, so only one ever runs — whether
    it came from the initial enumeration or from any depth of escalation.
    """
    return "|".join(
        (
            str(hyp.get("vuln_class", "")),
            str(hyp.get("endpoint_method", "GET")).upper(),
            str(hyp.get("endpoint_path", "")),
            str(hyp.get("selector_param", "")),
        )
    )


def _injection_siblings(hyp: dict, done_class: str) -> list[dict]:
    """Other injection classes on the SAME endpoint+param as a confirmed injection finding."""
    method = str(hyp.get("endpoint_method", "GET"))
    path = str(hyp.get("endpoint_path", ""))
    param = str(hyp.get("selector_param", ""))
    if not path or not param:
        return []  # need a concrete query parameter to pivot on
    out: list[dict] = []
    for cls in ESCALATION_INJECTION_CLASSES:
        if cls == done_class:
            continue
        out.append(
            {
                "vuln_class": cls,
                "endpoint_method": method,
                "endpoint_path": path,
                "selector_param": param,
                "rationale": (
                    f"param '{param}' on {path} is a proven injection sink "
                    f"({done_class} confirmed); escalate to test {cls} on the same parameter"
                ),
                "_origin": "escalation:injection-sibling",
            }
        )
    return out


def _object_type_neighbors(hyp: dict, appmodel) -> list[dict]:
    """Sibling ownable endpoints returning the same object type as a confirmed IDOR/BOLA.

    The seeded attacker/victim principals and objects from the originating hypothesis are reused
    (they are of the same object type, so they remain valid test fixtures); only the endpoint and
    its selector parameter change. The oracle still proves ownership crossing from a clean state.
    """
    object_type = hyp.get("object_type")
    if not object_type:
        return []
    required = ("attacker_principal", "victim_principal", "victim_object", "attacker_object")
    if any(hyp.get(k) in (None, "") for k in required):
        return []  # cannot build a well-formed BOLA hypothesis without the seeded fixtures
    origin_path = str(hyp.get("endpoint_path", ""))
    out: list[dict] = []
    for ep in _ownable_endpoints(appmodel):
        if ep.get("returns_object_type") != object_type:
            continue
        if str(ep.get("path", "")) == origin_path:
            continue  # the endpoint we already confirmed
        param = (ep.get("object_selector") or {}).get("param")
        if not param:
            continue
        out.append(
            {
                "vuln_class": "IDOR/BOLA",
                "endpoint_method": str(ep.get("method", "GET")),
                "endpoint_path": str(ep.get("path", "")),
                "selector_param": str(param),
                "object_type": object_type,
                "attacker_principal": hyp["attacker_principal"],
                "victim_principal": hyp["victim_principal"],
                "victim_object": hyp["victim_object"],
                "attacker_object": hyp["attacker_object"],
                "rationale": (
                    f"object type '{object_type}' has a proven ownership gap on {origin_path}; "
                    f"sweep sibling endpoint {ep.get('path')} that returns the same type"
                ),
                "_origin": "escalation:object-type-neighbor",
            }
        )
    return out


def _ownable_endpoints(appmodel) -> list[dict]:
    """Normalise ``appmodel`` (object or dict) to a list of ownable-endpoint dicts."""
    if appmodel is None:
        return []
    fn = getattr(appmodel, "ownable_endpoints", None)
    if callable(fn):
        eps = fn()
        return [
            {
                "method": getattr(e, "method", "GET"),
                "path": getattr(e, "path", ""),
                "returns_object_type": getattr(e, "returns_object_type", None),
                "object_selector": getattr(e, "object_selector", {}) or {},
            }
            for e in eps
        ]
    # dict form (appmodel.to_dict())
    eps = appmodel.get("endpoints", []) if isinstance(appmodel, dict) else []
    return [
        e for e in eps if isinstance(e, dict) and e.get("returns_object_type") and e.get("object_selector")
    ]


def follow_ups(finding, hyp: dict, appmodel) -> list[dict]:
    """Map a VALIDATED finding to candidate follow-up hypotheses. Pure; returns fresh dicts.

    The caller admits the result through an :class:`EscalationBudget` and runs each admitted
    hypothesis through the same gated worker + independent oracle. Returns ``[]`` for classes
    with no sound escalation (misconfiguration, sensitive-file, etc.).
    """
    vclass = getattr(finding, "vuln_class", None) or (
        finding.get("vuln_class") if isinstance(finding, dict) else None
    )
    if not isinstance(hyp, dict):
        return []
    try:
        if vclass in _INJECTION_SET:
            return _injection_siblings(hyp, vclass)
        if vclass == "IDOR/BOLA":
            return _object_type_neighbors(hyp, appmodel)
    except Exception:  # noqa: BLE001 - escalation is advisory; a generation error yields no follow-ups
        return []
    return []


class EscalationBudget:
    """Thread-safe bounds on finding-driven escalation — the anti-runaway control.

    Every follow-up must be admitted here first. Admission enforces three hard caps and a dedup
    set, and tallies exactly how many follow-ups were admitted versus dropped by each cap, so a
    truncated deep-scan is always visible and the fan-out can never be unbounded or repeated.
    """

    def __init__(
        self,
        enabled: bool = False,
        max_depth: int = 2,
        max_total: int = 24,
        max_per_finding: int = 6,
    ):
        self.enabled = bool(enabled)
        self.max_depth = max(0, int(max_depth))
        self.max_total = max(0, int(max_total))
        self.max_per_finding = max(0, int(max_per_finding))
        self._seen: set[str] = set()
        self._total = 0
        self._lock = threading.Lock()
        self.stats = {
            "admitted": 0,
            "dropped_duplicate": 0,
            "dropped_per_finding": 0,
            "dropped_total": 0,
            "dropped_depth": 0,
        }

    def seed(self, hyps) -> None:
        """Register the initial hypotheses so escalation never repeats an already-planned test."""
        with self._lock:
            for h in hyps:
                if isinstance(h, dict):
                    self._seen.add(escalation_identity(h))

    def admit_batch(self, candidates: list[dict], depth: int) -> list[dict]:
        """Return the subset of one finding's follow-ups that fit within every cap.

        ``depth`` is the depth of the task that produced the finding; admitted follow-ups are
        stamped ``_depth = depth + 1``. Order within ``candidates`` is honoured, so a caller that
        sorts its findings deterministically gets completion-order-independent admission.
        """
        if not self.enabled or not candidates:
            return []
        admitted: list[dict] = []
        with self._lock:
            if depth >= self.max_depth:
                self.stats["dropped_depth"] += len(candidates)
                return []
            per_finding = 0
            for cand in candidates:
                ident = escalation_identity(cand)
                if ident in self._seen:
                    self.stats["dropped_duplicate"] += 1
                    continue
                if per_finding >= self.max_per_finding:
                    self.stats["dropped_per_finding"] += 1
                    continue
                if self._total >= self.max_total:
                    self.stats["dropped_total"] += 1
                    continue
                self._seen.add(ident)
                self._total += 1
                per_finding += 1
                self.stats["admitted"] += 1
                cand = dict(cand)
                cand["_depth"] = depth + 1
                admitted.append(cand)
        return admitted

    def summary(self) -> dict:
        """A JSON-safe snapshot of the caps and what happened under them (for the plan/report)."""
        with self._lock:
            return {
                "enabled": self.enabled,
                "max_depth": self.max_depth,
                "max_total": self.max_total,
                "max_per_finding": self.max_per_finding,
                "admitted": self.stats["admitted"],
                "dropped": {
                    "duplicate": self.stats["dropped_duplicate"],
                    "per_finding": self.stats["dropped_per_finding"],
                    "total": self.stats["dropped_total"],
                    "depth": self.stats["dropped_depth"],
                },
            }
