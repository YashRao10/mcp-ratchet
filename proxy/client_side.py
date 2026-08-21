"""Holds one persistent connection to the real, downstream MCP server this
proxy is fronting.

Unlike scanner/connect.py's enumerate_target (a one-shot connect-list-
disconnect helper for the static scanner), this stays connected for the
whole lifetime of a proxy session, since a real client (Claude Code,
Cursor) will make many tool_call requests over time, not one.
"""

from __future__ import annotations

from contextlib import AsyncExitStack

from scanner.connect import HttpTargetSpec, TargetSpec, open_session


class DownstreamClient:
    """Wraps a live ClientSession to the real target server.

    Use as an async context manager:
        async with DownstreamClient(target) as downstream:
            result = await downstream.list_tools()
    """

    def __init__(self, target: TargetSpec | HttpTargetSpec):
        self._target = target
        self._stack: AsyncExitStack | None = None
        self._session = None

    async def __aenter__(self) -> "DownstreamClient":
        self._stack = AsyncExitStack()
        self._session = await self._stack.enter_async_context(open_session(self._target))
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        if self._stack is not None:
            await self._stack.aclose()
        self._session = None
        self._stack = None

    async def list_tools(self):
        if self._session is None:
            raise RuntimeError("DownstreamClient used outside of its async context manager")
        return await self._session.list_tools()

    async def call_tool(self, name: str, arguments: dict | None = None):
        if self._session is None:
            raise RuntimeError("DownstreamClient used outside of its async context manager")
        return await self._session.call_tool(name, arguments or {})
