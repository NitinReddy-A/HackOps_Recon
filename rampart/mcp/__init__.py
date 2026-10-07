"""Rampart MCP (Model Context Protocol) stdio server.

Exposes Rampart's scope-guarded assessment capabilities as MCP tools so that an
agent (e.g. Claude Code) can run *authorized* security assessments. Every tool
runs through :class:`rampart.engagement.Engagement`, so the SECURITY.md scope gate
(R1, fail-closed) is always enforced — the server can never scan a target that the
provided scope contract does not authorize.

Zero external dependencies: JSON-RPC 2.0 over stdin/stdout, line-delimited JSON,
stdlib only.
"""
from __future__ import annotations

from .server import serve_stdio

__all__ = ["serve_stdio"]
