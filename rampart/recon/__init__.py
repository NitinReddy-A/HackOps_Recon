"""Reconnaissance — discover the attack surface when there is no OpenAPI spec.

A scope-gated crawler that walks the application over the same policy pipeline as every
other action (so it can never leave scope), extracting endpoints, parameters and a light
technology fingerprint. Its output augments the application model, so the hypothesis/worker
layer works on real apps, not only spec-described ones.
"""

from .crawler import Crawler, CrawlResult, merge_into_model

__all__ = ["Crawler", "CrawlResult", "merge_into_model"]
