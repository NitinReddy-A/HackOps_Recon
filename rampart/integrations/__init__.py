"""Outbound integrations (posting results to third-party services).

These are the only places Rampart talks to something other than the target under test, so they
are explicit, opt-in, and graceful — a failure here never breaks a scan.
"""

# NB: the orchestration entrypoint is ``rampart.integrations.notify.notify`` — we deliberately do
# NOT re-export the ``notify`` function here, so the ``notify`` submodule is never shadowed.
from .github import post_or_update_comment, resolve_context
from .notify import Sink, SlackSink, WebhookSink, build_summary

__all__ = [
    "Sink",
    "SlackSink",
    "WebhookSink",
    "build_summary",
    "post_or_update_comment",
    "resolve_context",
]
