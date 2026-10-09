"""Deterministic business-logic scanner (economic tampering + workflow step-skip).

Closes the business-logic gap against LLM-reasoning competitors by *deterministically*
confirming the classic, high-value logic bugs with oracles (probe + negative control +
reproductions), rather than reasoning about them.
"""

from .scanner import (
    bizlogic_scan,
    economic_tampering_scan,
    workflow_skip_scan,
)

__all__ = [
    "bizlogic_scan",
    "economic_tampering_scan",
    "workflow_skip_scan",
]
