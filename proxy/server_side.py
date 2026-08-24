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
from proxy.drift import DRIFT_TOOL_REMOVED, diff_against_baseline
from proxy.policy import PolicyStore
from scanner.fingerprint import ServerFingerprint


def build_proxy_server(
    downstream: DownstreamClient,
    baseline: ServerFingerprint | None,
    audit_log: AuditLogWriter,
    server_name: str = "mcp-ratchet-proxy",
    block_on_drift: bool = False,
    policy_store: PolicyStore | None = None,
) -> Server:
    """Construct the low-level Server that fronts `downstream`.

    `baseline` may be None (no Phase 1 scan has been run for this target
    yet) — in that case drift detection is skipped and this is noted
    explicitly rather than silently treated as "no drift."

    `block_on_drift` (off by default, matching the README's long-standing
    "the proxy only monitors" default): when True, a call to any tool this
    proxy currently believes has drifted from baseline — added, or an
    existing tool with a changed description/schema/annotations — is
    refused locally, without ever reaching `downstream`, instead of just
    being logged. "Currently believes" means as of the most recent
    `tools/list` diff this session; a tool call made before this proxy has
    ever listed tools yet cannot be assessed and is allowed through
    (fail-open on missing information, same posture the rest of this
    check-suite takes — see dependency_cve.py's network-failure handling
    for the same principle applied elsewhere). A tool removed from
    baseline is not tracked here for blocking purposes: downstream will
    already reject a call to a tool it no longer declares.

    `policy_store` (optional; see proxy/policy.py) holds drift transitions a
    human has already reviewed and durably approved, keyed to the exact
    tool_name+baseline_hash+current_hash transition — not just the tool
    name, so a *further* drift on an already-approved tool blocks again. A
    drift event this session that matches an approved entry is excluded
    from blocking here, but it is still logged via audit_log.drift_event()
    below exactly as before: approval never erases or suppresses the drift
    record itself, only whether a call is refused. When policy_store is
    None (or empty), behavior is unchanged from before this feature
    existed — every currently-drifted tool blocks.
    """
    drifted_tool_names: set[str] = set()

    async def on_list_tools(ctx, params) -> types.ListToolsResult:
        nonlocal drifted_tool_names
        result = await forward.forward_list_tools(downstream)

        if baseline is None:
            audit_log.error(
                error_type="no_baseline",
                error_message="No Phase 1 baseline exists for this target; drift detection skipped this call.",
            )
            drifted_tool_names = set()
        else:
            live_fp, drift_events = diff_against_baseline(result.tools, baseline)
            audit_log.tools_list_snapshot(
                tool_count=live_fp.tool_count,
                whole_server_hash=live_fp.whole_server_hash,
                per_tool_hashes=live_fp.per_tool_hashes,
            )
            for event in drift_events:
                audit_log.drift_event(event)
            # Replaces, not accumulates: reflects what's drifted as of this
            # latest list, not every drift ever seen across the session.
            # A drift event matching an approved policy_store entry is
            # excluded here — it was still logged above unconditionally,
            # it just doesn't contribute to blocking.
            drifted_tool_names = {
                event.tool_name
                for event in drift_events
                if event.drift_type != DRIFT_TOOL_REMOVED
                and not (policy_store is not None and policy_store.is_approved(event))
            }

        # Transparency requirement: forward the real tools/list result
        # unmodified, even if drift was detected — a client always sees
        # the server's true declared tool surface. Blocking, when enabled,
        # only ever intercepts a subsequent tool *call*, in on_call_tool
        # below, never this listing itself.
        return result

    async def on_call_tool(ctx, params: types.CallToolRequestParams):
        start = time.monotonic()
        anomaly_flags = []
        if baseline is not None and params.name not in baseline.per_tool_hashes:
            anomaly_flags.append("tool_not_in_baseline")

        if block_on_drift and params.name in drifted_tool_names:
            duration_ms = (time.monotonic() - start) * 1000
            reason = (
                f"Tool '{params.name}' has drifted from its baseline fingerprint "
                "(added or changed since the last approved scan) and this proxy is "
                "running with --block-on-drift. Call refused before reaching the "
                "downstream server. If this drift has been reviewed and is safe, "
                "approve it with 'python -m proxy.approve_drift <target> "
                f"{params.name}' to durably allow this exact change."
            )
            audit_log.blocked_call(tool_name=params.name, reason=reason, arguments=params.arguments)
            return types.CallToolResult(
                content=[types.TextContent(type="text", text=reason)],
                is_error=True,
            )

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
