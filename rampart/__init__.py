"""Rampart — an open-source, self-hostable, evidence-first application-security agent.

North star: *find, prove, and help fix web/API vulnerabilities in applications you
are authorized to test* — combining runtime testing with an independent validation
loop, inside your own infrastructure, without shipping your code or targets to a SaaS.

Two load-bearing invariants (see the blueprint, sections 10, 12 and 21):

1. **The LLM proposes; deterministic code disposes.** No model output reaches the
   network or filesystem except as a typed :class:`ToolCallRequest` that has passed
   the single policy choke-point (allowlist -> scope -> resolved-IP -> risk -> policy
   -> sandbox -> audit), fail-closed at every stage.
2. **Evidence over alerts.** No finding is reported as ``confirmed`` until a *separate*
   validator re-derives the proof from a clean state with a deterministic oracle.

This is a defensive tool for assets you own or are authorized to test. It augments —
it does not replace — expert human pentesters.
"""

from .version import __version__

__all__ = ["__version__"]
