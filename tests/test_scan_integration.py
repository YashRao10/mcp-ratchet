"""End-to-end proof that a real scan against a real (if toy) MCP server
catches each planted problem — not a claim any individual unit test can
make on its own, since unit tests feed the checks hand-built fixtures
rather than going through a real stdio connection and a real MCP
handshake.

This is the single test that proves the whole pipeline (connect -> list
tools -> fingerprint -> checks) is wired together correctly, end to end,
against a live subprocess.
"""

from pathlib import Path

import pytest

from scanner.checks import permission_mismatch, secret_scan
from scanner.connect import TargetSpec, enumerate_target
from scanner.fingerprint import fingerprint_tools

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"
TOY_SERVER = FIXTURES_DIR / "toy_server.py"


@pytest.fixture(scope="module")
async def toy_scan_result():
    target = TargetSpec(command="python", args=[str(TOY_SERVER)])
    result = await enumerate_target(target)
    assert result.ok, f"Failed to connect to toy_server.py: {result.error}"
    return result


async def test_connects_and_lists_all_four_toy_tools(toy_scan_result):
    names = {t.name for t in toy_scan_result.tools}
    assert names == {"get_weather", "read_notes", "list_recent_files", "summarize_document"}


async def test_fingerprint_is_deterministic_across_two_live_connections():
    """Reconnecting to the same, unchanged server must reproduce the exact
    same fingerprint — this is Phase 2's entire premise, so it has to hold
    here first."""
    target = TargetSpec(command="python", args=[str(TOY_SERVER)])
    result_a = await enumerate_target(target)
    result_b = await enumerate_target(target)
    assert result_a.ok and result_b.ok

    fp_a = fingerprint_tools(result_a.tools, "toy")
    fp_b = fingerprint_tools(result_b.tools, "toy")
    assert fp_a.whole_server_hash == fp_b.whole_server_hash


async def test_permission_mismatch_check_catches_the_planted_shell_param(toy_scan_result):
    findings = permission_mismatch.check_all_tools(toy_scan_result.tools)
    flagged_names = {f.tool_name for f in findings}
    assert "list_recent_files" in flagged_names
    # and nothing else — proves this isn't just flagging everything
    assert flagged_names == {"list_recent_files"}


async def test_permission_mismatch_check_does_not_flag_clean_tools(toy_scan_result):
    findings = permission_mismatch.check_all_tools(toy_scan_result.tools)
    flagged_names = {f.tool_name for f in findings}
    assert "get_weather" not in flagged_names
    assert "summarize_document" not in flagged_names


def test_secret_scan_catches_the_planted_key_in_the_toy_server_source():
    findings = secret_scan.scan_source_tree(FIXTURES_DIR)
    assert any(f.pattern_name == "aws_access_key_id" for f in findings)


async def test_injection_prone_tool_description_reaches_the_checker_verbatim(toy_scan_result):
    """Doesn't call the real Claude API (no network dependency in this
    test) — just proves the planted hidden-instruction text in
    read_notes's description survives the real MCP handshake unmangled,
    which is what prompt_injection.check_tool actually judges against."""
    read_notes = next(t for t in toy_scan_result.tools if t.name == "read_notes")
    assert "SYSTEM OVERRIDE" in read_notes.description
    assert "ignore all previous instructions" in read_notes.description
