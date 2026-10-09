"""Scope contract hardening: strict types, blank owners, path canonicalization, host globs,
hard-blocked metadata IPs (reviewer findings A4/A6/A12/A13/A14/A15/A18f)."""

import pytest

from rampart.schemas.scope import EngagementScope, PathError, ScopeError, canonical_path

BASE = """apiVersion: v1
kind: EngagementScope
authorization:
  owner: {owner}
  authorized_by: "b"
  ticket: "T"
  attestation: {att}
  expires: {exp}
scope:
  in_scope:
    - host: "127.0.0.1"
      ports: {ports}
      paths_include: ["/**"]
      methods: ["GET"]
  out_of_scope:
    paths_exclude: {pex}
    hosts_exclude: {hex}
  resolved_ip_allowlist: ["127.0.0.1/32", "::/0", "0.0.0.0/0"]
limits:
  max_total_requests: {mtr}
"""


def mk(owner='"o"', att='"a"', exp='"2099-01-01T00:00:00Z"', ports="[18100]", pex='["/api/admin/**", "/logout"]',
       hex="[]", mtr="5000"):  # fmt: skip
    return BASE.format(owner=owner, att=att, exp=exp, ports=ports, pex=pex, hex=hex, mtr=mtr)


# ------------------------------------------------------------------ A4: strict list types
@pytest.mark.parametrize("pex", ['"/api/products"', "|\n      /api/products", "{a: b}", "[1, 2]", '[["/a"]]'])
def test_non_list_of_strings_is_rejected(pex):
    with pytest.raises(ScopeError):
        EngagementScope.from_text(mk(pex=pex))


def test_exclude_pattern_must_be_a_path():
    with pytest.raises(ScopeError):
        EngagementScope.from_text(mk(pex='["admin/**"]'))


# ---------------------------------------------------------------- A12: blank owner/attestation
@pytest.mark.parametrize("owner", ["", "null", "~", '"None"', '"  "', "null  # nobody"])
def test_blank_owner_fails_validation(owner):
    s = EngagementScope.from_text(mk(owner=owner))
    assert s.authorization.owner == ""
    assert any("owner" in e for e in s.validate())


def test_empty_attestation_fails_validation():
    s = EngagementScope.from_text(mk(att='""'))
    assert any("attestation" in e for e in s.validate())


def test_unparseable_expiry_message():
    errs = EngagementScope.from_text(mk(exp='"never"')).validate()
    assert any("unparseable" in e for e in errs)
    assert not any("in the past" in e for e in errs)


def test_unquoted_timestamp_expiry_works():
    s = EngagementScope.from_text(mk(exp="2099-01-01T00:00:00Z"))
    assert s.validate() == [] and not s.is_expired()
    assert EngagementScope.from_text(mk(exp="2020-01-01")).is_expired()


# ---------------------------------------------------------------- A13: malformed types
def test_scalar_ports_rejected():
    with pytest.raises(ScopeError):
        EngagementScope.from_text(mk(ports="18100"))


def test_numeric_string_limit_is_coerced_and_junk_rejected():
    assert EngagementScope.from_text(mk(mtr='"5000"')).limits.max_total_requests == 5000
    with pytest.raises(ScopeError):
        EngagementScope.from_text(mk(mtr='"lots"'))
    with pytest.raises(ScopeError):
        EngagementScope.from_text(mk(mtr="true"))


def test_unknown_limit_or_policy_key_rejected():
    with pytest.raises(ScopeError):
        EngagementScope.from_text(mk() + "  max_total_request: 5\n")
    with pytest.raises(ScopeError):
        EngagementScope.from_text(mk() + 'action_policy: {tier2_requires_approval: "no"}\n')


# ---------------------------------------------------------------- A6: path canonicalization
@pytest.mark.parametrize(
    "path",
    [
        "/api/admin/users",
        "/api/admin",
        "/api/admin/",
        "/API/admin/users",
        "//api/admin/users",
        "/api//admin/users",
        "/api/./admin/users",
        "/x/../api/admin/users",
        "/api/%61dmin/users",
        "/api/%2561dmin/users",  # double-encoded
        "/api/admin%2fusers",
        "/api/admin%2Fusers",
        "/api\\admin\\users",
        "/api/admin;x=1/users",
        "/api/admin%3bx/users",
        "/logout",
        "/logout/",
        "/LOGOUT",
        "/logout;jsessionid=1",
        "/logout?x=1",
        "/logout#frag",
        "/a/../logout",
    ],
)
def test_exclusion_cannot_be_bypassed_with_noncanonical_paths(path):
    s = EngagementScope.from_text(mk())
    assert s.path_excluded(path), path


@pytest.mark.parametrize("path", ["/api/administrator", "/logoutx", "/api/products", "/"])
def test_exclusion_does_not_overmatch(path):
    assert not EngagementScope.from_text(mk()).path_excluded(path)


@pytest.mark.parametrize(
    "path", ["/ok\r\nHost: x", "/a%00b", "/a%0d%0ab", "x", "http://evil.example/x", "", "/%25252561"]
)
def test_malformed_paths_fail_closed(path):
    with pytest.raises(PathError):
        canonical_path(path)
    assert EngagementScope.from_text(mk()).path_excluded(path)


def test_canonical_path_examples():
    assert canonical_path("/x/../api//v1/./items/?q=1") == "/api/v1/items"
    assert canonical_path("/a%2fb") == "/a/b"
    assert canonical_path("/../..") == "/"


def test_include_requires_every_decoding_to_match():
    s = EngagementScope.from_text(mk().replace('paths_include: ["/**"]', 'paths_include: ["/api/**"]'))
    hs = s.host_scope("127.0.0.1")
    assert s.path_included(hs, "/api/x")
    assert s.path_included(hs, "/api/%61")
    assert s.path_included(hs, "/x/../api/y")  # normalized form is inside /api
    assert not s.path_included(hs, "/api/../etc/passwd")
    assert not s.path_included(hs, "/%2e%2e/api")  # decodes to /../api -> /api, raw -> /%2e%2e/api


# ---------------------------------------------------------------- A15: host exclusion globs
@pytest.mark.parametrize("pattern", ['["*.acme.com"]', '["**.acme.com"]'])
def test_host_exclusion_any_depth(pattern):
    s = EngagementScope.from_text(mk(hex=pattern))
    for h in ("a.acme.com", "a.b.acme.com", "x.y.z.acme.com", "A.B.ACME.COM", "a.acme.com."):
        assert s.host_excluded(h), h
    assert not s.host_excluded("acme.com")
    assert not s.host_excluded("evilacme.com")


# ---------------------------------------------------------------- A14: hard-blocked IPs
@pytest.mark.parametrize(
    "ip",
    [
        "169.254.169.254",
        "::ffff:169.254.169.254",
        "::ffff:a9fe:a9fe",
        "64:ff9b::a9fe:a9fe",
        "64:ff9b::169.254.169.254",
        "2002:a9fe:a9fe::1",  # 6to4
        "::169.254.169.254",  # IPv4-compatible
        "fd00:ec2::254",
        "100.100.100.200",
        "168.63.129.16",
        "fe80::1%eth0",
        "ff02::1",
        "224.0.0.1",
    ],
)
def test_metadata_and_embedded_ipv4_forms_hard_blocked(ip):
    s = EngagementScope.from_text(mk())  # allowlist is 0.0.0.0/0 + ::/0
    assert not s.ip_allowed(ip), ip


def test_ordinary_ips_still_allowed():
    s = EngagementScope.from_text(mk())
    assert s.ip_allowed("127.0.0.1") and s.ip_allowed("10.0.0.5") and s.ip_allowed("::1")
