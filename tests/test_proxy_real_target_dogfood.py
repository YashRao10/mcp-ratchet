"""Proves the runtime proxy (Phase 2) end-to-end against a real, running
MCP server — not the toy fixture. tests/test_forward.py already proves
transparency against the toy server; this proves the whole stack (proxy
subprocess, stdio transport, drift check against a real baseline, audit
log writing, hash-chain verification) survives contact with a server this
repo doesn't control the internals of.

Skipped everywhere except the machine this was authored on: the target is
a real personal MCP server at a fixed local path, not something CI can
run. That's a deliberate, named trade-off (same spirit as the README's own
"one target per run, by design" callouts) — a dogfood test that only ever
runs on one machine is still worth more than zero real-target proof, and
forcing it to run in CI would mean faking the target, which defeats the
point.
"""

from __future__ import annotations

import platform
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
REAL_TARGET_SERVER = (
    Path.home() / "Desktop" / "finance-projects" / "financial-analysis-mcp" / "server.py"
)

pytestmark = pytest.mark.skipif(
    not REAL_TARGET_SERVER.exists() or platform.system() != "Windows",
    reason="Real personal-financial-analysis MCP server not present on this machine — "
    "this test only runs where the actual target exists, see module docstring.",
)


async def test_proxy_end_to_end_against_real_target():
    """Drives the proxy exactly as Claude Code/Cursor would: spawn
    `python -m proxy.run_proxy ...` and talk MCP to its stdio. Proves the
    full subprocess+transport stack, not just the internal Python objects.
    """
    from scanner.connect import TargetSpec, open_session

    proxy_target = TargetSpec.from_argv(
        [
            sys.executable,
            "-m",
            "proxy.run_proxy",
            "--target",
            "personal-financial-analysis",
            "--",
            sys.executable,
            str(REAL_TARGET_SERVER),
        ],
        cwd=str(REPO_ROOT),
    )

    async with open_session(proxy_target) as session:
        tools_result = await session.list_tools()
        tool_names = {t.name for t in tools_result.tools}
        assert "query_warehouse" in tool_names

        call_result = await session.call_tool("query_warehouse", {"sql": "SELECT 1 AS x"})
        assert getattr(call_result, "isError", None) is not True
        text = "".join(b.text for b in call_result.content if getattr(b, "type", None) == "text")
        assert '"ok": true' in text


async def test_proxy_real_dogfood_produces_a_verifiable_audit_log(tmp_path):
    """Exercises the exact same forward/drift/audit_log wiring
    proxy/server_side.py uses (rather than a second stdio subprocess hop,
    already proven above) against the real target, writing into an
    isolated tmp_path instead of the repo's shared logs/ dir — so this
    test doesn't leave a new timestamped log file behind on every run.
    """
    import json
    import time

    from proxy import forward
    from proxy.audit_log import AuditLogWriter, verify_chain
    from proxy.client_side import DownstreamClient
    from proxy.drift import diff_against_baseline
    from scanner.connect import TargetSpec
    from scanner.fingerprint import ServerFingerprint

    real_target = TargetSpec(command=sys.executable, args=[str(REAL_TARGET_SERVER)])

    baseline_path = REPO_ROOT / "baselines" / "personal-financial-analysis.json"
    assert baseline_path.exists(), "Run scanner.run_scan for this target first to produce a baseline."
    baseline = ServerFingerprint.from_dict(json.loads(baseline_path.read_text(encoding="utf-8")))

    audit_log = AuditLogWriter(tmp_path, "personal-financial-analysis-dogfood-test")
    async with DownstreamClient(real_target) as downstream:
        with audit_log:
            list_result = await forward.forward_list_tools(downstream)
            live_fp, drift_events = diff_against_baseline(list_result.tools, baseline)
            audit_log.tools_list_snapshot(
                tool_count=live_fp.tool_count,
                whole_server_hash=live_fp.whole_server_hash,
                per_tool_hashes=live_fp.per_tool_hashes,
            )
            assert drift_events == [], "Real target drifted from its own just-recorded baseline mid-test."

            start = time.monotonic()
            call_result = await forward.forward_call_tool(downstream, "query_warehouse", {"sql": "SELECT 1 AS x"})
            audit_log.tool_call(
                tool_name="query_warehouse",
                arguments={"sql": "SELECT 1 AS x"},
                result_status="error" if getattr(call_result, "is_error", False) else "success",
                result_shape=call_result,
                duration_ms=(time.monotonic() - start) * 1000,
                anomaly_flags=[],
            )

    log_files = list(tmp_path.glob("personal-financial-analysis-dogfood-test-*.jsonl"))
    assert len(log_files) == 1
    result = verify_chain(log_files[0])
    assert result.ok, f"Real dogfood audit log failed chain verification: {result}"
