"""``python -m rampart.mcp`` — start the Rampart MCP stdio server.

Speaks JSON-RPC 2.0 over stdin/stdout (line-delimited JSON). Register it with an
MCP client (e.g. Claude Code) as a stdio server running ``python -m rampart.mcp``.
Exits cleanly when stdin reaches EOF.
"""
from __future__ import annotations

import sys

from .server import serve_stdio


def main(argv=None):
    serve_stdio(sys.stdin, sys.stdout)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
