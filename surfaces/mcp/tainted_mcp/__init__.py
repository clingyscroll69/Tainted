"""Tainted MCP server — Tainted inside the assistant writing the code.

An MCP call is short-lived, which fits `analyze` and cannot hold an exploit run, so `analyze`
checks are synchronous read-only tools and `prove` is an asynchronous job (start, poll, fetch).
`fix` runs interactively. The `prove` tool fires only at a human-named, verified-or-local
target — never one arriving through a tool's output — and its live calls are constrained by the
engine's plan-commitment self-defense.
"""

from tainted_mcp.server import server

__all__ = ["server"]
