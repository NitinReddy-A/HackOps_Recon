"""Oracle registry — maps a finding's ``vuln_class`` to its independent deterministic oracle.

The validator looks a finding up here instead of hard-coding one class, so adding a new
vulnerability class is: write its oracle, register it, done. Every oracle is normalised to
the same signature ``(runner, sessions, hyp, reproductions) -> OracleVerdict`` so the
validator stays class-agnostic. Classes with no registered oracle cannot be confirmed
(fail-closed): only an oracle may grant ``confidence=confirmed``.
"""
from __future__ import annotations

from .oracle import run_bola_oracle
from .web_oracles import run_redirect_oracle, run_sqli_oracle, run_xss_oracle


def _bola(runner, sessions, hyp, reproductions):
    return run_bola_oracle(runner, sessions, hyp, reproductions=reproductions, fresh_sessions=True)


def _xss(runner, sessions, hyp, reproductions):
    return run_xss_oracle(runner, hyp, reproductions=reproductions)


def _sqli(runner, sessions, hyp, reproductions):
    return run_sqli_oracle(runner, hyp, reproductions=reproductions)


def _redirect(runner, sessions, hyp, reproductions):
    return run_redirect_oracle(runner, hyp, reproductions=reproductions)


ORACLES = {
    "IDOR/BOLA": _bola,
    "XSS": _xss,
    "SQLI": _sqli,
    "OPEN_REDIRECT": _redirect,
}


def get_oracle(vuln_class: str):
    return ORACLES.get(vuln_class)
