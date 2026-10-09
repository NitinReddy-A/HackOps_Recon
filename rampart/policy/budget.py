"""Adaptive tool budgeting + circuit breaker (ASI02/ASI08; blueprint section 12).

Hard caps live here as the last quantitative gate before execution:

* ``max_total_requests`` — hard cap; once reached every further request is DENIED.
* ``max_requests_per_host_per_min`` — a *throttle*: a request over the per-host rate waits
  until the sliding 60 s window frees a slot (bounded by ``max_rate_wait_s``, default 60 s) and
  is only denied if it would have to wait longer than that. Denying instead of waiting would
  silently skip checks (false negatives), so every denial is counted in :attr:`denials`.
* ``budget_usd`` / ``max_tokens`` — LLM spend. Providers call :meth:`can_spend_llm` before a
  model call and :meth:`charge_llm` after it; once either cap is reached further LLM calls are
  refused (:class:`BudgetExceeded` from :meth:`require_llm_budget`).
* kill switch — :meth:`kill`, a ``KILL`` file in the work dir (checked on every request and LLM
  call), or SIGINT/SIGTERM via :func:`install_kill_signal_handlers`. Once killed, every request
  and LLM call is denied for the rest of the run.
"""

from __future__ import annotations

import os
import signal
import threading
import time
from collections import defaultdict, deque

from ..schemas.scope import Limits

KILL_FILE_NAME = "KILL"
DEFAULT_MAX_RATE_WAIT_S = 60.0


class BudgetExceeded(RuntimeError):
    """Raised by :meth:`BudgetTracker.require_llm_budget` when LLM spend is not allowed."""


class BudgetTracker:
    def __init__(
        self,
        limits: Limits,
        kill_file: str | None = None,
        max_rate_wait_s: float = DEFAULT_MAX_RATE_WAIT_S,
        sleep=time.sleep,
        clock=time.monotonic,
    ):
        self.limits = limits
        self.kill_file = kill_file
        self.max_rate_wait_s = float(max_rate_wait_s)
        self._sleep = sleep
        self._clock = clock
        self._lock = threading.Lock()
        self._per_host: dict[str, deque] = defaultdict(deque)
        self.total_requests = 0
        self.tokens_used = 0
        self.usd_spent = 0.0
        self.llm_calls = 0
        self.killed = False
        self.kill_reason = ""
        # every request/LLM call the budget refused, by cause — surfaced in snapshot()/reports so
        # a budget-starved run can never masquerade as a clean "0 findings" run
        self.denials: dict[str, int] = {
            "kill_switch": 0,
            "max_total_requests": 0,
            "rate_limit": 0,
            "llm_budget": 0,
        }
        self.throttled_requests = 0
        self.throttle_wait_s = 0.0

    @classmethod
    def for_work_dir(cls, limits: Limits, work_dir: str, **kw) -> BudgetTracker:
        """A tracker whose kill switch also trips when ``<work_dir>/KILL`` exists."""
        return cls(limits, kill_file=os.path.join(work_dir, KILL_FILE_NAME), **kw)

    # ------------------------------------------------------------ kill switch
    def kill(self, reason: str = "manual kill-switch") -> None:
        with self._lock:
            if not self.killed:
                self.killed = True
                self.kill_reason = reason

    def _check_kill_file(self) -> None:
        if self.killed or not self.kill_file:
            return
        try:
            exists = os.path.exists(self.kill_file)
        except OSError:  # pragma: no cover - fail closed on a broken path
            exists = True
        if exists:
            self.kill(f"kill file present: {self.kill_file}")

    def is_killed(self) -> bool:
        self._check_kill_file()
        return self.killed

    def denied_total(self) -> int:
        with self._lock:
            return sum(self.denials.values())

    # --------------------------------------------------------------- requests
    def try_consume_request(self, host: str, now: float | None = None) -> tuple[bool, str]:
        """Reserve one request against the caps. Over the per-host rate it waits (throttles)
        for up to ``max_rate_wait_s``; when ``now`` is passed explicitly it never sleeps."""
        self._check_kill_file()
        can_wait = now is None
        waited = 0.0
        while True:
            t = self._clock() if now is None else now
            with self._lock:
                if self.killed:
                    self.denials["kill_switch"] += 1
                    return False, f"kill-switch engaged: {self.kill_reason}"
                if self.total_requests >= self.limits.max_total_requests:
                    self.denials["max_total_requests"] += 1
                    return False, f"max_total_requests reached ({self.limits.max_total_requests})"
                window = self._per_host[host]
                cutoff = t - 60.0
                while window and window[0] <= cutoff:
                    window.popleft()
                if len(window) < self.limits.max_requests_per_host_per_min:
                    window.append(t)
                    self.total_requests += 1
                    if waited:
                        self.throttled_requests += 1
                        self.throttle_wait_s += waited
                    return True, "within budget" if not waited else f"within budget (throttled {waited:.1f}s)"
                wait = max(0.01, window[0] + 60.0 - t)
                if not can_wait or waited + wait > self.max_rate_wait_s:
                    self.denials["rate_limit"] += 1
                    return False, (
                        f"rate limit for {host}: {self.limits.max_requests_per_host_per_min}/min exceeded"
                        + (f" (waited {waited:.1f}s, max {self.max_rate_wait_s:.0f}s)" if can_wait else "")
                    )
            self._sleep(wait)
            waited += wait
            self._check_kill_file()

    # -------------------------------------------------------------- LLM spend
    def _llm_block_reason(self) -> str:
        if self.killed:
            return f"kill-switch engaged: {self.kill_reason}"
        if self.usd_spent >= self.limits.budget_usd:
            return f"budget_usd exhausted (${self.usd_spent:.4f} >= ${self.limits.budget_usd:.2f})"
        if self.tokens_used >= self.limits.max_tokens:
            return f"max_tokens exhausted ({self.tokens_used} >= {self.limits.max_tokens})"
        return ""

    def can_spend_llm(self) -> tuple[bool, str]:
        """Call BEFORE every model call. (False, reason) once killed or a spend cap is reached."""
        self._check_kill_file()
        with self._lock:
            why = self._llm_block_reason()
            if why:
                self.denials["llm_budget"] += 1
                return False, why
            return True, "within LLM budget"

    def require_llm_budget(self) -> None:
        ok, why = self.can_spend_llm()
        if not ok:
            raise BudgetExceeded(why)

    def charge_llm(self, tokens: int = 0, usd: float = 0.0) -> tuple[bool, str]:
        """Call AFTER every model call with its usage. Returns whether further spend is allowed."""
        with self._lock:
            self.llm_calls += 1
            self.tokens_used += max(0, int(tokens or 0))
            self.usd_spent += max(0.0, float(usd or 0.0))
            why = self._llm_block_reason()
            return (False, why) if why else (True, "within LLM budget")

    # backwards-compatible recorders (do not enforce; prefer charge_llm)
    def record_tokens(self, n: int) -> None:
        with self._lock:
            self.tokens_used += max(0, int(n))

    def record_cost(self, usd: float) -> None:
        with self._lock:
            self.usd_spent += max(0.0, float(usd))

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "requests_used": self.total_requests,
                "requests_cap": self.limits.max_total_requests,
                "tokens_used": self.tokens_used,
                "tokens_cap": self.limits.max_tokens,
                "usd_spent": round(self.usd_spent, 4),
                "budget_usd": self.limits.budget_usd,
                "killed": self.killed,
                "denied": dict(self.denials),
                "throttled_requests": self.throttled_requests,
                "throttle_wait_s": round(self.throttle_wait_s, 2),
            }


def install_kill_signal_handlers(tracker: BudgetTracker, signals=None) -> dict:
    """Make SIGINT/SIGTERM engage ``tracker``'s kill switch (in-flight requests finish, every new
    request and LLM call is denied). A second signal falls through to the previous handler (so a
    second Ctrl-C still aborts). Must be called from the main thread; returns the previous
    handlers ({} if not installable), which :func:`restore_signal_handlers` puts back."""
    if threading.current_thread() is not threading.main_thread():
        return {}
    if signals is None:
        signals = [signal.SIGINT] + ([signal.SIGTERM] if hasattr(signal, "SIGTERM") else [])
    previous: dict = {}

    def _handler(signum, frame):
        if not tracker.killed:
            tracker.kill(f"signal {signal.Signals(signum).name}")
            return
        prev = previous.get(signum)
        if callable(prev):
            prev(signum, frame)
        elif signum == signal.SIGINT:
            raise KeyboardInterrupt

    for s in signals:
        try:
            previous[s] = signal.signal(s, _handler)
        except (ValueError, OSError):  # pragma: no cover - platform without this signal
            continue
    return previous


def restore_signal_handlers(previous: dict) -> None:
    for s, h in (previous or {}).items():
        try:
            signal.signal(s, h)
        except (ValueError, OSError, TypeError):  # pragma: no cover
            pass
