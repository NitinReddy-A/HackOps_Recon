"""Deeper authentication / access-control scanning (weak JWT secret, expiry-not-enforced).

Complements the existing alg=none JWT oracle and the IDOR/BOLA/BFLA access-control oracles. Every
finding is confirmed with a probe + negative controls (incl. a random-secret control that proves the
server *does* verify signatures, so a hit is a weak key rather than a missing check) + reproductions.
"""
from .scanner import WEAK_SECRETS, authz_scan, forge_hs256, jwt_secret_scan

__all__ = ["authz_scan", "jwt_secret_scan", "forge_hs256", "WEAK_SECRETS"]
