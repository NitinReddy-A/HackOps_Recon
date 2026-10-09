"""Scope contract parsing + validation (the R1 gate)."""

from rampart.schemas.scope import EngagementScope

VALID = """
apiVersion: security-agent/v1
kind: EngagementScope
authorization:
  owner: "o@x"
  authorized_by: "c@x"
  ticket: "T-1"
  attestation: "authorized"
  expires: "2099-01-01T00:00:00Z"
scope:
  in_scope:
    - host: "127.0.0.1"
      ports: [8080]
      paths_include: ["/api/**"]
      methods: ["GET", "POST"]
  out_of_scope:
    paths_exclude: ["/api/admin/**"]
    hosts_exclude: ["*.prod.example.com"]
  resolved_ip_allowlist: ["127.0.0.1/32"]
limits:
  max_requests_per_host_per_min: 60
action_policy:
  default_tier_ceiling: 1
test_accounts:
  - { id: user_a, role: customer, secret_ref: "v://a" }
"""


def test_parses_and_validates():
    s = EngagementScope.from_text(VALID)
    assert s.validate() == []
    assert s.account("user_a").role == "customer"
    assert s.host_scope("127.0.0.1") is not None
    assert s.host_scope("evil.com") is None
    assert s.path_excluded("/api/admin/x") is True
    assert s.path_excluded("/api/orders/1") is False


def test_ip_allowlist_and_hard_block():
    s = EngagementScope.from_text(VALID)
    assert s.ip_allowed("127.0.0.1") is True
    assert s.ip_allowed("10.0.0.5") is False  # not in allowlist
    assert s.ip_allowed("169.254.169.254") is False  # cloud-metadata hard block
    assert s.ip_allowed("not-an-ip") is False


def test_excluded_host_glob():
    s = EngagementScope.from_text(VALID)
    assert s.host_scope("api.prod.example.com") is None  # excluded by *.prod.example.com


def test_missing_fields_fail_closed():
    s = EngagementScope.from_text(VALID.replace('owner: "o@x"', 'owner: ""'))
    errs = s.validate()
    assert any("owner" in e for e in errs)


def test_expired_scope_is_rejected():
    s = EngagementScope.from_text(VALID.replace("2099-01-01T00:00:00Z", "2000-01-01T00:00:00Z"))
    errs = s.validate()
    assert any("expire" in e.lower() for e in errs)


def test_missing_ip_allowlist_rejected():
    s = EngagementScope.from_text(
        VALID.replace('resolved_ip_allowlist: ["127.0.0.1/32"]', "resolved_ip_allowlist: []")
    )
    errs = s.validate()
    assert any("resolved_ip_allowlist" in e for e in errs)
