"""Full Software Composition Analysis (SCA) for Rampart.

Parses pinned dependency manifests across ecosystems (PyPI, npm, Go, Maven, RubyGems, crates.io),
matches each ``name@version`` against the OSV.dev advisory database, and emits one security-only,
upgrade-focused finding per vulnerable package (worst CVSS severity + the minimum safe version to
bump to). Stdlib-only; the OSV network call is an operator opt-in and fully graceful offline.
"""
from .scanner import scan_sca
from .parsers import Dep, collect_dependencies

__all__ = ["scan_sca", "collect_dependencies", "Dep"]
