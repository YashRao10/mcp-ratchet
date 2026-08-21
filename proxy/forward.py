"""Transparent request/response forwarding to the real downstream server.

Kept as its own module, separate from drift/audit-log concerns, so
transparency — the proxy must never alter what the real server actually
said — is independently testable: a unit test can assert this module's
output is byte-identical to the real downstream response, without needing
to also exercise drift detection or logging to prove that.
"""

from __future__ import annotations

from proxy.client_side import DownstreamClient


async def forward_list_tools(downstream: DownstreamClient):
    """Return the real downstream tools/list result, completely unmodified.

    Callers (server_side.py) are responsible for handing this same result
    to drift.py/audit_log.py on the way through — this function's only job
    is to not touch it.
    """
    return await downstream.list_tools()


async def forward_call_tool(downstream: DownstreamClient, name: str, arguments: dict | None):
    """Return the real downstream tool-call result, completely unmodified."""
    return await downstream.call_tool(name, arguments)
