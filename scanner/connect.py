"""Connect to a target MCP server — over stdio (a local launch command) or
HTTP (a remote server, e.g. one behind a Bearer-token-authenticated
endpoint like PACT's pact-stage) — and enumerate its real surface.

Mirrors the error-handling convention already established in this user's
own MCP client code (PACT Work/08-Self-Learning-Extension/server/
pact-mcp-client.js): a connection or protocol failure is caught and
returned as a descriptive string/result, never allowed to propagate as a
raw, unhandled exception up to a CLI user.
"""

from __future__ import annotations

import shlex
from contextlib import asynccontextmanager
from dataclasses import dataclass, field

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.client.streamable_http import streamable_http_client


@dataclass
class TargetSpec:
    """A launchable, local MCP server target (stdio transport)."""

    command: str
    args: list[str] = field(default_factory=list)
    env: dict[str, str] | None = None
    cwd: str | None = None

    @classmethod
    def from_command_string(cls, command_string: str, cwd: str | None = None) -> "TargetSpec":
        """Parse a shell-style launch string, e.g. 'python server.py --flag'.

        Only correct when no individual argument contains whitespace —
        shlex has no way to recover a boundary that quoting already lost.
        Prefer from_argv when the argv list is already available (e.g. from
        argparse's REMAINDER), which is every real call site in this repo;
        this string-based constructor exists for the case where only a
        single already-typed command string is available (e.g. read from a
        config file's launch-command field).
        """
        parts = shlex.split(command_string, posix=False)
        if not parts:
            raise ValueError("Empty launch command")
        return cls(command=parts[0], args=parts[1:], cwd=cwd)

    @classmethod
    def from_argv(cls, parts: list[str], cwd: str | None = None) -> "TargetSpec":
        """Build a target directly from an already-tokenized argv list.

        Use this instead of from_command_string whenever the caller already
        has the command as separate argv elements (e.g. argparse's
        `nargs=REMAINDER`, which the OS/shell already split correctly). A
        join-then-reparse round trip through from_command_string silently
        drops any whitespace inside a single argument — a real launch
        command on Windows, e.g. `python "C:\\Users\\Yash Rao\\...\\server.py"`,
        breaks that way because the path itself contains a space.
        """
        if not parts:
            raise ValueError("Empty launch command")
        return cls(command=parts[0], args=list(parts[1:]), cwd=cwd)

    def to_stdio_params(self) -> StdioServerParameters:
        return StdioServerParameters(
            command=self.command,
            args=self.args,
            env=self.env,
            cwd=self.cwd,
        )


@dataclass
class HttpTargetSpec:
    """A remote MCP server target reached over streamable HTTP, optionally
    with a Bearer token (e.g. a personal-access-token-authenticated
    endpoint like https://stage.acs-pact.com/mcp)."""

    url: str
    bearer_token: str | None = None


@dataclass
class ConnectResult:
    ok: bool
    tools: list = field(default_factory=list)
    resources: list = field(default_factory=list)
    server_name: str | None = None
    server_version: str | None = None
    error: str | None = None


@asynccontextmanager
async def _raw_streams(target: TargetSpec | HttpTargetSpec):
    """Yields (read_stream, write_stream) for either transport kind, so
    open_session below has exactly one code path after this point."""
    if isinstance(target, HttpTargetSpec):
        import httpx2

        headers = {"Authorization": f"Bearer {target.bearer_token}"} if target.bearer_token else {}
        http_client = httpx2.AsyncClient(headers=headers)
        async with http_client:
            async with streamable_http_client(target.url, http_client=http_client) as (
                read_stream,
                write_stream,
            ):
                yield read_stream, write_stream
    else:
        params = target.to_stdio_params()
        async with stdio_client(params) as (read_stream, write_stream):
            yield read_stream, write_stream


@asynccontextmanager
async def open_session(target: TargetSpec | HttpTargetSpec):
    """Async context manager yielding a live, initialized ClientSession.

    Left as a separate primitive (rather than folded into enumerate_target)
    so Phase 2's proxy client_side.py can hold a session open across many
    calls instead of reconnecting per-request.
    """
    async with _raw_streams(target) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            yield session


async def enumerate_target(target: TargetSpec | HttpTargetSpec) -> ConnectResult:
    """Connect to the target, list its tools and resources, then disconnect.

    A one-shot helper for the static scanner (scanner/run_scan.py). Any
    failure — the process/connection not starting, the handshake failing,
    a malformed response — is caught here and returned as
    ConnectResult(ok=False, error=...) rather than raised, matching the
    project's established "never throw raw at the CLI user" convention.
    """
    try:
        async with open_session(target) as session:
            tools_result = await session.list_tools()
            try:
                resources_result = await session.list_resources()
                resources = resources_result.resources
            except Exception:
                # Not every server implements resources/list — a server
                # that simply doesn't support it isn't a scan failure.
                resources = []

            server_info = session.server_info
            return ConnectResult(
                ok=True,
                tools=tools_result.tools,
                resources=resources,
                server_name=getattr(server_info, "name", None),
                server_version=getattr(server_info, "version", None),
            )
    except Exception as exc:  # noqa: BLE001 - deliberate: any failure -> descriptive result
        return ConnectResult(
            ok=False,
            error=f"{type(exc).__name__}: {exc}",
        )
