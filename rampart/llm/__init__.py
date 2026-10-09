"""LLM application security testing — mapped to the OWASP Top 10 for LLM Applications.

The probes are deliberately *marker/canary-based*: each tests whether the target model
follows an injected instruction or leaks a planted secret, detected by a deterministic
string oracle — never by eliciting genuinely harmful content. That makes the result
reproducible and the method safe for authorized testing of a system you own.
"""

from .assessment import LLMAssessment
from .client import LLMClient
from .probes import LLM_PROBES, LLMProbe

__all__ = ["LLM_PROBES", "LLMProbe", "LLMClient", "LLMAssessment"]
