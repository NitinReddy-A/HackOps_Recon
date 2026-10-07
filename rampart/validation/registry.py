"""Oracle registry — maps a finding's ``vuln_class`` to its independent deterministic oracle.

The validator looks a finding up here instead of hard-coding one class, so adding a new
vulnerability class is: write its oracle, register it, done. Every oracle is normalised to
the same signature ``(runner, sessions, hyp, reproductions) -> OracleVerdict`` so the
validator stays class-agnostic. Classes with no registered oracle cannot be confirmed
(fail-closed): only an oracle may grant ``confidence=confirmed``.
"""
from __future__ import annotations

from .more_oracles import (run_bfla_oracle, run_cmdi_oracle, run_exposure_oracle, run_graphql_oracle,
                           run_hostheader_oracle, run_jwt_oracle, run_mass_assignment_oracle,
                           run_ssrf_oracle, run_ssti_oracle, run_traversal_oracle)
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


def _ssrf(runner, sessions, hyp, reproductions):
    return run_ssrf_oracle(runner, hyp, reproductions=reproductions)


def _cmdi(runner, sessions, hyp, reproductions):
    return run_cmdi_oracle(runner, hyp, reproductions=reproductions)


def _traversal(runner, sessions, hyp, reproductions):
    return run_traversal_oracle(runner, hyp, reproductions=reproductions)


def _ssti(runner, sessions, hyp, reproductions):
    return run_ssti_oracle(runner, hyp, reproductions=reproductions)


def _jwt(runner, sessions, hyp, reproductions):
    return run_jwt_oracle(runner, hyp, reproductions=reproductions)


def _hhi(runner, sessions, hyp, reproductions):
    return run_hostheader_oracle(runner, hyp, reproductions=reproductions)


def _mass_assign(runner, sessions, hyp, reproductions):
    return run_mass_assignment_oracle(runner, hyp, reproductions=reproductions)


def _graphql(runner, sessions, hyp, reproductions):
    return run_graphql_oracle(runner, hyp, reproductions=reproductions)


ORACLES = {
    "IDOR/BOLA": _bola,
    "XSS": _xss,
    "SQLI": _sqli,
    "OPEN_REDIRECT": _redirect,
    "SSRF": _ssrf,
    "CMDI": _cmdi,
    "PATH_TRAVERSAL": _traversal,
    "BFLA": run_bfla_oracle,            # already (runner, sessions, hyp, reproductions)
    "EXCESSIVE_DATA": run_exposure_oracle,
    "SSTI": _ssti,
    "JWT": _jwt,
    "HOST_HEADER_INJECTION": _hhi,
    "MASS_ASSIGNMENT": _mass_assign,
    "GRAPHQL": _graphql,
}


def get_oracle(vuln_class: str):
    return ORACLES.get(vuln_class)
