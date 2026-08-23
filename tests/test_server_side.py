"""Proves proxy/server_side.py's --block-on-drift mode against a real,
live toy MCP server — the drift-blocking equivalent of test_drift.py's
"baseline against the original, then a real edit, then a second real
connection" pattern, extended one step further into an actual blocked
tool call.

Uses build_proxy_server's handler closures directly (retrieved off the
constructed Server via get_request_handler(...).handler) rather than a
second stdio subprocess hop — test_proxy_real_target_dogfood.py already
proves the full subprocess+transport stack works; this targets the
blocking decision itself.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from mcp import types

from proxy.audit_log import AuditLogWriter
from proxy.client_side import DownstreamClient
from proxy.server_side import build_proxy_server
from scanner.connect import TargetSpec, enumerate_target
from scanner.fingerprint import fingerprint_tools

ORIGINAL_TOY_SERVER = Path(__file__).resolve().parent / "fixtures" / "toy_server.py"

NEW_TOOL_SOURCE = '''

@mcp.tool()
def delete_all_notes() -> str:
    """Delete every saved note. Newly added after the baseline."""
    return "all notes deleted"
'''


def _add_new_tool(toy_server_copy: Path) -> None:
    original_text = toy_server_copy.read_text(encoding="utf-8")
    edited_text = original_text.replace(
        'if __name__ == "__main__":', NEW_TOOL_SOURCE + '\n\nif __name__ == "__main__":'
    )
    assert edited_text != original_text
    toy_server_copy.write_text(edited_text, encoding="utf-8")


@pytest.fixture
def toy_server_copy(tmp_path):
    """Same fixture as tests/test_drift.py — duplicated rather than shared
    via a conftest.py, since this repo doesn't have one yet and this is
    the second (not yet common enough to be worth introducing one for)."""
    dest = tmp_path / "toy_server.py"
    dest.write_text(ORIGINAL_TOY_SERVER.read_text(encoding="utf-8"), encoding="utf-8")
    return dest


async def _baseline_against_original(slug: str):
    target = TargetSpec(command="python", args=[str(ORIGINAL_TOY_SERVER)])
    result = await enumerate_target(target)
    assert result.ok, f"Failed to connect: {result.error}"
    return fingerprint_tools(result.tools, slug)


async def _list_tools(server, ctx=None):
    handler = server.get_request_handler("tools/list").handler
    return await handler(ctx, None)


async def _call_tool(server, name: str, arguments: dict | None = None, ctx=None):
    handler = server.get_request_handler("tools/call").handler
    params = types.CallToolRequestParams(name=name, arguments=arguments or {})
    return await handler(ctx, params)


async def test_monitor_mode_still_forwards_a_drifted_tool_call_by_default(toy_server_copy, tmp_path):
    """Regression guard: block_on_drift defaults to False, so a newly
    added tool must still be callable exactly as before this feature
    existed — the README's long-standing "the proxy only monitors" claim,
    now conditional on an explicit opt-in rather than absolute."""
    baseline = await _baseline_against_original("toy-block-test")
    _add_new_tool(toy_server_copy)

    audit_log = AuditLogWriter(tmp_path, "toy-block-test")
    target = TargetSpec(command="python", args=[str(toy_server_copy)])
    async with DownstreamClient(target) as downstream:
        with audit_log:
            server = build_proxy_server(downstream, baseline, audit_log)
            await _list_tools(server)
            result = await _call_tool(server, "delete_all_notes")

    assert getattr(result, "is_error", None) is not True
    text = "".join(b.text for b in result.content if getattr(b, "type", None) == "text")
    assert "all notes deleted" in text


async def test_block_on_drift_refuses_a_newly_added_tool(toy_server_copy, tmp_path):
    baseline = await _baseline_against_original("toy-block-test")
    _add_new_tool(toy_server_copy)

    audit_log = AuditLogWriter(tmp_path, "toy-block-test")
    target = TargetSpec(command="python", args=[str(toy_server_copy)])
    async with DownstreamClient(target) as downstream:
        with audit_log:
            server = build_proxy_server(downstream, baseline, audit_log, block_on_drift=True)
            await _list_tools(server)  # populates drifted_tool_names with delete_all_notes
            result = await _call_tool(server, "delete_all_notes")

    assert result.is_error is True
    text = "".join(b.text for b in result.content if getattr(b, "type", None) == "text")
    assert "drifted" in text.lower()
    assert "delete_all_notes" in text

    log_files = list(tmp_path.glob("toy-block-test-*.jsonl"))
    assert len(log_files) == 1
    import json

    records = [json.loads(line) for line in log_files[0].read_text(encoding="utf-8").splitlines()]
    blocked = [r for r in records if r["record_type"] == "blocked_call"]
    assert len(blocked) == 1
    assert blocked[0]["tool_name"] == "delete_all_notes"
    # The refusal must never have reached the downstream server as a real
    # tool_call — only the blocked_call record exists for this tool.
    forwarded = [r for r in records if r["record_type"] == "tool_call" and r.get("tool_name") == "delete_all_notes"]
    assert forwarded == []


async def test_block_on_drift_still_allows_an_unchanged_tool(toy_server_copy, tmp_path):
    """Blocking is scoped to what actually drifted — an existing,
    unchanged tool must remain callable even with --block-on-drift on,
    proving this isn't a blanket lockdown once any drift is seen."""
    baseline = await _baseline_against_original("toy-block-test")
    _add_new_tool(toy_server_copy)

    audit_log = AuditLogWriter(tmp_path, "toy-block-test")
    target = TargetSpec(command="python", args=[str(toy_server_copy)])
    async with DownstreamClient(target) as downstream:
        with audit_log:
            server = build_proxy_server(downstream, baseline, audit_log, block_on_drift=True)
            await _list_tools(server)
            result = await _call_tool(server, "get_weather", {"city": "Boston"})

    assert getattr(result, "is_error", None) is not True
    text = "".join(b.text for b in result.content if getattr(b, "type", None) == "text")
    assert "Boston" in text


async def test_block_on_drift_fails_open_before_any_tools_list_call(toy_server_copy, tmp_path):
    """A tool call made before this proxy has ever listed tools has no
    drift information to act on yet — documented fail-open behavior, not
    a silent gap: see build_proxy_server's docstring."""
    baseline = await _baseline_against_original("toy-block-test")
    _add_new_tool(toy_server_copy)

    audit_log = AuditLogWriter(tmp_path, "toy-block-test")
    target = TargetSpec(command="python", args=[str(toy_server_copy)])
    async with DownstreamClient(target) as downstream:
        with audit_log:
            server = build_proxy_server(downstream, baseline, audit_log, block_on_drift=True)
            # No _list_tools(server) call here — drifted_tool_names is still empty.
            result = await _call_tool(server, "delete_all_notes")

    assert getattr(result, "is_error", None) is not True
    text = "".join(b.text for b in result.content if getattr(b, "type", None) == "text")
    assert "all notes deleted" in text
