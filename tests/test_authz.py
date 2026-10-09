"""Unit tests for the deep-auth scanner (rampart.authz) — mock runner, no network."""

from dataclasses import dataclass, field

from rampart.authz.scanner import _candidate_paths, authz_scan


@dataclass
class _Ep:
    method: str
    path: str
    auth_required: bool = True
    parameters: list = field(default_factory=list)


@dataclass
class _Model:
    endpoints: list


@dataclass
class _Out:
    executed: bool
    status: int
    body: str = ""
    evidence: list = field(default_factory=list)


class _Runner:
    engagement_id = "E"

    def __init__(self):
        self.paths = []

    def get(self, path, session=None, headers=None, **kw):
        self.paths.append(path)
        if "{" in path:
            return _Out(True, 404, "not found")  # a literal template path never exists
        return _Out(True, 401, "unauthorized")


def test_candidate_paths_substitute_templates():
    """Regression C-14: probes used to hit the literal '/api/orders/{id}'."""
    model = _Model([_Ep("GET", "/api/orders/{id}"), _Ep("GET", "/api/users/{uid}/cards/{cid}")])
    assert _candidate_paths(model) == ["/api/orders/1", "/api/users/1/cards/1"]
    assert _candidate_paths(model, probe_paths=["/x/{id}"]) == ["/x/1"]


def test_authz_scan_never_requests_a_literal_template():
    runner = _Runner()
    authz_scan(runner, _Model([_Ep("GET", "/api/orders/{id}")]), "http://t", "demo", "E")
    assert runner.paths and all("{" not in p for p in runner.paths)
    assert "/api/orders/1" in runner.paths
