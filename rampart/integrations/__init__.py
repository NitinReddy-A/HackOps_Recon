"""Outbound integrations (posting results to third-party services).

These are the only places Rampart talks to something other than the target under test, so they
are explicit, opt-in, and graceful — a failure here never breaks a scan.
"""

from .github import post_or_update_comment, resolve_context

__all__ = ["post_or_update_comment", "resolve_context"]
