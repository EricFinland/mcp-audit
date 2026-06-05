"""Live MCP server introspection.

Uses the official `mcp` Python SDK. Verified client API:
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client
    from mcp.client.streamable_http import streamable_http_client

We connect, initialize, list tools, and return a normalized list[ToolInfo]. We never call
any tool - introspection only. This keeps even a malicious server from doing work.
"""
from __future__ import annotations

import asyncio
import os
import shlex

from .detectors.base import ToolInfo


def _split_cmdline(cmdline: str) -> list[str]:
    """Split a shell-style command line into argv, cross-platform.

    POSIX `shlex` treats backslashes as escapes, which mangles Windows paths
    like ``C:\\Users\\me\\python.exe`` into ``C:Usersmepython.exe``. On Windows
    we parse in non-POSIX mode and strip the surrounding quotes shlex leaves on.
    """
    if os.name == "nt":
        out: list[str] = []
        for part in shlex.split(cmdline, posix=False):
            if len(part) >= 2 and part[0] == part[-1] and part[0] in ("'", '"'):
                part = part[1:-1]
            out.append(part)
        return out
    return shlex.split(cmdline)


async def _collect(session) -> list[ToolInfo]:
    await session.initialize()
    resp = await session.list_tools()
    out: list[ToolInfo] = []
    for t in resp.tools:
        out.append(ToolInfo(
            name=t.name,
            description=t.description or "",
            input_schema=getattr(t, "inputSchema", {}) or {},
        ))
    return out


async def _introspect_stdio_async(command: str, args: list[str]) -> list[ToolInfo]:
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    params = StdioServerParameters(command=command, args=args, env=None)
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            return await _collect(session)


async def _introspect_http_async(url: str) -> list[ToolInfo]:
    from mcp import ClientSession
    from mcp.client.streamable_http import streamable_http_client

    async with streamable_http_client(url) as (read, write, _):
        async with ClientSession(read, write) as session:
            return await _collect(session)


def introspect_stdio(cmdline: str) -> list[ToolInfo]:
    """`cmdline` is a shell-style string, e.g. 'python fixtures/evil_server.py'."""
    parts = _split_cmdline(cmdline)
    if not parts:
        raise ValueError("empty stdio command")
    return asyncio.run(_introspect_stdio_async(parts[0], parts[1:]))


def introspect_http(url: str) -> list[ToolInfo]:
    return asyncio.run(_introspect_http_async(url))
