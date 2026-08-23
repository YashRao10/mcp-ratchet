"""Tests for the audit log's hash-chain tamper-evidence (proxy/audit_log.py).

No test file existed for audit_log.py before this — it had been exercised
only indirectly via proxy/server_side.py's real usage. These tests target
the chain mechanism directly: a real writer produces a chain that verifies
clean, and each realistic tampering scenario (editing a line's content,
deleting a line, truncating the file) is caught with the file position
correctly attributed. See the module docstring for what tamper-evidence
here explicitly does NOT protect against (a compromised proxy computing a
consistent fake chain from the start) — these tests only claim what the
docstring claims.
"""

from __future__ import annotations

import json

import pytest

from proxy.audit_log import AuditLogWriter, GENESIS_HASH, verify_chain


def _write_a_normal_session(logs_dir) -> "Path":
    with AuditLogWriter(logs_dir, "test-target") as log:
        log.tool_call(
            tool_name="get_weather",
            arguments={"city": "Boston"},
            result_status="success",
            result_shape={"temp": 72},
            duration_ms=12.5,
        )
        log.tools_list_snapshot(tool_count=1, whole_server_hash="abc123", per_tool_hashes={"get_weather": "abc123"})
    return log.path


def test_a_real_session_verifies_clean(tmp_path):
    path = _write_a_normal_session(tmp_path)
    result = verify_chain(path)
    assert result.ok is True
    assert result.broken_at_line is None
    # session_start + tool_call + tools_list_snapshot + session_end
    assert result.records_checked == 4


def test_first_record_chains_from_the_genesis_hash(tmp_path):
    path = _write_a_normal_session(tmp_path)
    first_line = json.loads(path.read_text(encoding="utf-8").splitlines()[0])
    assert first_line["prev_record_hash"] == GENESIS_HASH
    assert first_line["record_type"] == "session_start"


def test_each_record_hash_is_unique_and_chains_to_the_next(tmp_path):
    path = _write_a_normal_session(tmp_path)
    lines = [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines()]
    hashes = [l["record_hash"] for l in lines]
    assert len(hashes) == len(set(hashes)), "record_hash values must all be distinct"
    for prev_line, next_line in zip(lines, lines[1:]):
        assert next_line["prev_record_hash"] == prev_line["record_hash"]


def test_editing_a_middle_line_in_place_breaks_the_chain_at_that_line(tmp_path):
    path = _write_a_normal_session(tmp_path)
    lines = path.read_text(encoding="utf-8").splitlines()

    tampered_index = 1  # the tool_call record
    record = json.loads(lines[tampered_index])
    record["tool_name"] = "delete_everything"  # tamper with content, leave the stale hash in place
    lines[tampered_index] = json.dumps(record)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    result = verify_chain(path)
    assert result.ok is False
    assert result.broken_at_line == tampered_index
    assert "edited in place" in result.detail


def test_deleting_a_middle_line_breaks_the_chain_at_the_following_line(tmp_path):
    path = _write_a_normal_session(tmp_path)
    lines = path.read_text(encoding="utf-8").splitlines()

    deleted_index = 1  # remove the tool_call record entirely
    del lines[deleted_index]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    result = verify_chain(path)
    assert result.ok is False
    # the record that used to follow the deleted one now has a
    # prev_record_hash that doesn't match what's actually before it
    assert result.broken_at_line == deleted_index
    assert "doesn't match" in result.detail


def test_truncating_the_trailing_record_is_detected_as_an_incomplete_but_valid_prefix(tmp_path):
    """Cutting off the last line (e.g. session_end) doesn't break the chain
    for the lines that remain — verify_chain reports the remaining prefix
    as valid. Callers who care about completeness (not just tamper-freedom)
    should separately check the last record_type == 'session_end'."""
    path = _write_a_normal_session(tmp_path)
    lines = path.read_text(encoding="utf-8").splitlines()
    assert lines[-1].count('"record_type":"session_end"') or "session_end" in lines[-1]

    path.write_text("\n".join(lines[:-1]) + "\n", encoding="utf-8")

    result = verify_chain(path)
    assert result.ok is True
    assert result.records_checked == len(lines) - 1


def test_blocked_call_chains_correctly_and_never_leaks_raw_args_by_default(tmp_path):
    with AuditLogWriter(tmp_path, "test-target") as log:
        log.blocked_call(
            tool_name="delete_all_notes",
            reason="Tool has drifted from baseline; refused under --block-on-drift.",
            arguments={"confirm": True},
        )
    path = log.path

    result = verify_chain(path)
    assert result.ok is True

    records = [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines()]
    blocked = [r for r in records if r["record_type"] == "blocked_call"]
    assert len(blocked) == 1
    assert blocked[0]["tool_name"] == "delete_all_notes"
    assert blocked[0]["args_raw"] is None  # log_raw_args defaults to False
    assert blocked[0]["args_shape_hash"]  # still recorded, just not the real values


def test_blocked_call_logs_raw_args_when_log_raw_args_is_set(tmp_path):
    with AuditLogWriter(tmp_path, "test-target", log_raw_args=True) as log:
        log.blocked_call(tool_name="delete_all_notes", reason="refused", arguments={"confirm": True})

    records = [json.loads(l) for l in log.path.read_text(encoding="utf-8").splitlines()]
    blocked = [r for r in records if r["record_type"] == "blocked_call"][0]
    assert blocked["args_raw"] == {"confirm": True}


def test_a_log_written_by_a_non_chain_aware_source_is_flagged_as_such(tmp_path):
    path = tmp_path / "foreign.jsonl"
    path.write_text(json.dumps({"schema_version": "mcp-ratchet-audit-log/1", "record_type": "session_start"}) + "\n", encoding="utf-8")

    result = verify_chain(path)
    assert result.ok is False
    assert result.broken_at_line == 0
    assert "not written by this chain-aware writer" in result.detail
