"""The fail-closed YAML fallback: every input either parses exactly like PyYAML or is rejected.

A silently mis-parsed ``paths_exclude`` widens the authorized scope, so these tests pin the
reviewer's repros (tabs, anchors, trailing comments, quoted colons/hashes, block scalars) and
run a differential check against PyYAML when it is installed.
"""

import datetime

import pytest

from rampart import yaml_lite
from rampart.schemas.scope import EngagementScope, ScopeError
from rampart.yaml_lite import YamlError, _load_lite

try:
    import yaml as _pyyaml
except Exception:  # noqa: BLE001
    _pyyaml = None

HEAD = """apiVersion: v1
kind: EngagementScope
authorization:
  owner: o
  authorized_by: b
  attestation: a
  expires: "2099-01-01T00:00:00Z"
scope:
  in_scope:
    - host: "127.0.0.1"
      ports: [18100]
  resolved_ip_allowlist: ["127.0.0.1/32"]
  out_of_scope:
"""


@pytest.fixture
def lite(monkeypatch):
    """Force the stdlib fallback parser (the default install has no PyYAML)."""
    monkeypatch.setattr(yaml_lite, "_pyyaml", None)


@pytest.mark.parametrize(
    "tail",
    [
        '\tpaths_exclude: ["/api/admin/**"]\n',  # tab indentation used to yield an EMPTY list
        '    paths_exclude: &ex ["/api/admin/**"]\n',  # anchor used to yield a string
        "    paths_exclude: |\n      /api/admin/**\n",  # block scalar
        '    paths_exclude: ["/api/admin/**",\n      "/x"]\n',  # unclosed flow on the line
        "    paths_exclude: *ex\n",  # alias
        "    paths_exclude: !!seq [a]\n",  # tag
    ],
)
def test_lite_rejects_constructs_it_does_not_understand(lite, tail):
    with pytest.raises(ScopeError):
        EngagementScope.from_text(HEAD + tail)


@pytest.mark.parametrize(
    "tail,expected",
    [
        ('    paths_exclude: ["/api/admin/**"]#note\n', ["/api/admin/**"]),
        ('    paths_exclude: ["/api/admin/**"]  # keep admin out\n', ["/api/admin/**"]),
        (
            '    paths_exclude:\n      - "/v1/jobs:cancel"\n      - "/api/admin/**"\n',
            ["/v1/jobs:cancel", "/api/admin/**"],
        ),
        ('    paths_exclude:\n    - "/api/admin/**"\n', ["/api/admin/**"]),
        ('    paths_exclude: ["/a\\" #x", "/api/admin/**"]\n', ['/a" #x', "/api/admin/**"]),
        ("    paths_exclude: ['/it''s', /api/admin/**]\n", ["/it's", "/api/admin/**"]),
        ("    paths_exclude: [/a#b/**, /api/admin/**]\n", ["/a#b/**", "/api/admin/**"]),
    ],
)
def test_lite_parses_reviewer_cases_like_pyyaml(lite, tail, expected):
    s = EngagementScope.from_text(HEAD + tail)
    assert s.paths_exclude == expected
    assert s.path_excluded("/api/admin/x")
    if _pyyaml is not None:
        assert _pyyaml.safe_load(HEAD + tail)["scope"]["out_of_scope"]["paths_exclude"] == expected


def test_lite_dash_item_is_a_map_only_when_colon_space_outside_quotes():
    assert _load_lite('- "/v1/jobs:cancel"\n- "a: b"\n- k: v\n') == ["/v1/jobs:cancel", "a: b", {"k": "v"}]


def test_lite_comments_only_outside_quotes():
    assert _load_lite("a: \"x # not a comment\" # comment\nb: 'y #z'\n") == {
        "a": "x # not a comment",
        "b": "y #z",
    }
    assert _load_lite("a: x#y\n") == {"a": "x#y"}


def test_lite_rejects_tabs_duplicates_and_ambiguous_scalars():
    for doc in ("a:\n\t- 1\n", "a: 1\na: 2\n", "a: 010\n", "a: 0x10\n", "a: 1:20\n", "a: x: y\n", "on: 1\n"):
        with pytest.raises(YamlError):
            _load_lite(doc)


def test_lite_timestamps_match_pyyaml():
    got = _load_lite("a: 2099-01-01T00:00:00Z\nb: 2020-01-02\n")
    assert got["a"] == datetime.datetime(2099, 1, 1, tzinfo=datetime.timezone.utc)
    assert got["b"] == datetime.date(2020, 1, 2)


def test_duplicate_keys_rejected_with_pyyaml_too():
    if _pyyaml is None:
        pytest.skip("PyYAML not installed")
    with pytest.raises(ScopeError):
        EngagementScope.from_text(
            HEAD + '    paths_exclude: ["/a/**"]\n  out_of_scope:\n    paths_exclude: []\n'
        )


_DIFF_DOCS = [
    "a:\n  b: 1\n  c:\n  - x\n  - y\n",
    "a:\n- 1\n- 2\nb: 3\n",
    "a:\n  - b: 1\n    c: 2\n  - d\n",
    "-   a: 1\n    b: 2\n",
    "a: [1, 2.5, true, null, ~, 'q', \"r\"]\n",
    "a: {b: [c, d], e: f}\n",
    "a: -1\nb: +2\nc: 1.\nd: .5\ne: 08\nf: 1e5\ng: 127.0.0.1\n",
    "a: yes\nb: No\nc: off\nd: y\ne: tRue\n",
    'a: don\'t\nb: say "hi"\n',
    "--- \na: 1\n...\n",
    "a:   # c\n  b: 1\n",
    "a: [x]  # note\n",
    "k: '/v1/jobs: cancel'\n",
    '"a b": 1\n',
    "- [a]\n- {b: c}\n",
    "\ufeffa: 1\r\nb: 2\r\n",
]


@pytest.mark.parametrize("doc", _DIFF_DOCS)
def test_lite_matches_pyyaml_or_rejects(doc):
    if _pyyaml is None:
        pytest.skip("PyYAML not installed")
    try:
        got = _load_lite(doc)
    except YamlError:
        return
    assert got == _pyyaml.safe_load(doc)


def test_lite_differential_fuzz():
    """Random token soup: whatever the fallback accepts, PyYAML must accept identically."""
    if _pyyaml is None:
        pytest.skip("PyYAML not installed")
    import random

    tok = ["a", "k", "/p/**", "1", "0", "1.5", "true", "null", "~", "-", "- ", ": ", ":", " ", "  ", "\n",
           "\n  ", "\n- ", "#", " #c", "'", '"', "[", "]", "{", "}", ", ", "&a ", "*a", "!", "|", ">", "?",
           "\t", "\\", "%", "2020-01-01", "on", "08", "010"]  # fmt: skip
    rnd = random.Random(1234)
    for _ in range(20000):
        d = "".join(rnd.choice(tok) for _ in range(rnd.randint(1, 12)))
        try:
            got = _load_lite(d)
        except YamlError:
            continue
        assert repr(got) == repr(_pyyaml.safe_load(d)), d
