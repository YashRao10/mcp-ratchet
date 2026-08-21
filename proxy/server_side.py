"""Presents this proxy as an MCP server to the real upstream client (Claude
Code, Cursor, etc.), forwarding every request to the real downstream
target while diffing tool-list responses against the Phase 1 baseline and
logging every call.

Uses the low-level Server API (callback-based construction in SDK 2.0.0)
rather than the high-level MCPServer/.tool() decorator pattern already
used in finance-projects/financial-analysis-mcp/server.py — that pattern
is for a fixed, known-in-advance set of tools; this server's tools are
whatever the downstream target happens to declare, discovered at runtime,
so they can't be registered ahead of time with .tool().
"""

from __future__ import annotations

import time

from mcp import types
from mcp.server.lowlevel import Server

from proxy import forward
from proxy.audit_log import AuditLogWriter
from proxy.client_side import DownstreamClient
from proxy.drift import diff_against_baseline
from scanner.fingerprint import ServerFingerprint


def build_proxy_server(
    downstream: DownstreamClient,
    baseline: ServerFingerprint | None,
    audit_log: AuditLogWriter,
    server_name: str = "mcp-ratchet-proxy",
) -> Server:
    """Construct the low-level Server that fronts `downstream`.

    `baseline` may be None (no Phase 1 scan has been run for this target
    yet) — in that case drift detection is skipped and this is noted
    explicitly rather than silently treated as "no drift."
    """

    async def on_list_tools(ctx, params) -> types.ListToolsResult:
        result = await forward.forward_list_tools(downstream)

        if baseline is None:
            audit_log.error(
                error_type="no_baseline",
                error_message="No Phase 1 baseline exists for this target; drift detection skipped this call.",
            )
        else:
            live_fp, drift_events = diff_against_baseline(result.tools, baseline)
            audit_log.tools_list_snapshot(
                tool_count=live_fp.tool_count,
                whole_server_hash=live_fp.whole_server_hash,
                per_tool_hashes=live_fp.per_tool_hashes,
            )
            for event in drift_events:
                audit_log.drift_event(event)

        # Transparency requirement: forward the real result unmodified,
        # even if drift was detected — this proxy monitors, it doesn't
        # block. A blocking mode is a documented future direction, not
        # this version's behavior (see README).
        return result

    async def on_call_tool(ctx, params: types.CallToolRequestParams):
        start = time.monotonic()
        anomaly_flags = []
        if baseline is not None and params.name not in baseline.per_tool_hashes:
            anomaly_flags.append("tool_not_in_baseline")

        try:
            result = await forward.forward_call_tool(downstream, params.name, params.arguments)
            duration_ms = (time.monotonic() - start) * 1000
            audit_log.tool_call(
                tool_name=params.name,
                arguments=params.arguments,
                result_status="error" if getattr(result, "is_error", False) else "success",
                result_shape=result,
                duration_ms=duration_ms,
                anomaly_flags=anomaly_flags,
            )
            return result
        except Exception as exc:
            duration_ms = (time.monotonic() - start) * 1000
            audit_log.tool_call(
                tool_name=params.name,
                arguments=params.arguments,
                result_status="error",
                result_shape=None,
                duration_ms=duration_ms,
                anomaly_flags=anomaly_flags + ["forward_exception"],
            )
            audit_log.error(error_type=type(exc).__name__, error_message=str(exc))
            raise

    return Server(
        server_name,
        on_list_tools=on_list_tools,
        on_call_tool=on_call_tool,
    )
