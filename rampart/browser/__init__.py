"""Optional headless-browser engine — execution-proven stored/DOM XSS (graceful if absent).

OPTIONAL extra. The zero-dependency core never imports Playwright at load time; it is imported
lazily inside :class:`PlaywrightDriver` methods, so this package always imports cleanly. When
Playwright (and a browser binary) are not installed, the engine degrades to a no-op and the
oracles simply do not confirm.

Trust boundary: a headless browser makes its OWN network requests and is NOT policed by
Rampart's scope choke-point, so a driver must only ever be pointed at an already in-scope,
authorized URL — the caller guarantees this. A browser-execution finding is proof that
attacker-controlled JavaScript ran in the live DOM.
"""

from __future__ import annotations

from .engine import (
    DOMXSS_TOKEN,
    BrowserDriver,
    PlaywrightDriver,
    RenderResult,
    StubDriver,
    available,
    run_dom_xss_oracle,
    run_stored_xss_oracle,
)

__all__ = [
    "BrowserDriver",
    "PlaywrightDriver",
    "StubDriver",
    "RenderResult",
    "run_dom_xss_oracle",
    "run_stored_xss_oracle",
    "available",
    "DOMXSS_TOKEN",
]
