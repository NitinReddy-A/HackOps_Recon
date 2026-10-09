"""Correlation & intelligence layer — turn a list of findings into an attack story.

Takes the *confirmed* findings and derives (deterministically): multi-step attack chains
(kill-chains) that compose individual findings into realistic end-to-end impact, an aggregate
risk score/band, and a prioritized remediation roadmap. This is the "so what" layer that
makes the output read like a pentest, not a scanner dump.
"""

from .engine import CorrelationResult, correlate

__all__ = ["correlate", "CorrelationResult"]
