"""Adaptive tool budgeting + circuit breaker (ASI02/ASI08; blueprint section 12).

Hard caps live here as the last quantitative gate before execution: max requests per
host per minute, max total requests, plus a per-engagement kill switch. Token/cost
accounting is tracked for the "cost per validated finding" KPI (section 25).
"""
from __future__ import annotations

import threading
import time
from collections import defaultdict, deque

from ..schemas.scope import Limits


class BudgetTracker:
    def __init__(self, limits: Limits):
        self.limits = limits
        self._lock = threading.Lock()
        self._per_host: dict[str, deque] = defaultdict(deque)
        self.total_requests = 0
        self.tokens_used = 0
        self.usd_spent = 0.0
        self.killed = False
        self.kill_reason = ""

    def kill(self, reason: str = "manual kill-switch") -> None:
        with self._lock:
            self.killed = True
            self.kill_reason = reason

    def try_consume_request(self, host: str, now: float | None = None) -> tuple[bool, str]:
        now = now if now is not None else time.monotonic()
        with self._lock:
            if self.killed:
                return False, f"kill-switch engaged: {self.kill_reason}"
            if self.total_requests >= self.limits.max_total_requests:
                return False, f"max_total_requests reached ({self.limits.max_total_requests})"
            window = self._per_host[host]
            cutoff = now - 60.0
            while window and window[0] < cutoff:
                window.popleft()
            if len(window) >= self.limits.max_requests_per_host_per_min:
                return False, (f"rate limit for {host}: "
                               f"{self.limits.max_requests_per_host_per_min}/min exceeded")
            window.append(now)
            self.total_requests += 1
            return True, "within budget"

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
                "usd_spent": round(self.usd_spent, 4),
                "budget_usd": self.limits.budget_usd,
                "killed": self.killed,
            }
