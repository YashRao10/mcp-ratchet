"""Tests for policy.py's hash-chained approval log — the piece that closes
the gap the README used to flag: approval decisions are now tamper-evident
the same way audit_log.py's session logs already were, via the shared
primitives in proxy/hash_chain.py.
"""

from __future__ import annotations

import json

import pytest

from proxy.policy import (
    ApprovedDrift,
    PolicyStore,
    append_approval_record,
    approval_log_path,
    load_policy,
    policy_path,
    rebuild_snapshot_from_chain,
    verify_policy_chain,
)


def _entry(tool_name="delete_all_notes", current_hash="hash-a", note=None) -> ApprovedDrift:
    return ApprovedDrift(
        tool_name=tool_name,
        drift_type="tool_added",
        baseline_hash=None,
        current_hash=current_hash,
        approved_at="2026-08-24T00:00:00+00:00",
        approved_by="yash",
        note=note,
    )


def test_first_append_chains_from_genesis(tmp_path):
    append_approval_record(tmp_path, "toy", _entry())
    log_path = approval_log_path(tmp_path, "toy")
    record = json.loads(log_path.read_text(encoding="utf-8").strip())
    assert record["prev_record_hash"] == "0" * 64
    assert record["tool_name"] == "delete_all_notes"
    assert record["record_type"] == "approval"


def test_verify_policy_chain_ok_on_untouched_log(tmp_path):
    append_approval_record(tmp_path, "toy", _entry(current_hash="hash-a"))
    append_approval_record(tmp_path, "toy", _entry(current_hash="hash-b", note="second review"))

    log_path = approval_log_path(tmp_path, "toy")
    result = verify_policy_chain(log_path)
    assert result.ok
    assert result.records_checked == 2


def test_verify_policy_chain_detects_edited_line(tmp_path):
    append_approval_record(tmp_path, "toy", _entry(current_hash="hash-a"))
    append_approval_record(tmp_path, "toy", _entry(current_hash="hash-b"))

    log_path = approval_log_path(tmp_path, "toy")
    lines = log_path.read_text(encoding="utf-8").splitlines()
    tampered = json.loads(lines[0])
    tampered["note"] = "an attacker snuck this approval note in after the fact"
    lines[0] = json.dumps(tampered, sort_keys=True, separators=(",", ":"))
    log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    result = verify_policy_chain(log_path)
    assert not result.ok
    assert result.broken_at_line == 0


def test_verify_policy_chain_detects_reordered_lines(tmp_path):
    append_approval_record(tmp_path, "toy", _entry(current_hash="hash-a"))
    append_approval_record(tmp_path, "toy", _entry(current_hash="hash-b"))

    log_path = approval_log_path(tmp_path, "toy")
    lines = log_path.read_text(encoding="utf-8").splitlines()
    log_path.write_text("\n".join(reversed(lines)) + "\n", encoding="utf-8")

    result = verify_policy_chain(log_path)
    assert not result.ok
    assert result.broken_at_line == 0


def test_re_approving_same_transition_appends_a_new_record_not_replaces(tmp_path):
    """Unlike the .json snapshot (PolicyStore.approve_event replaces an
    existing entry for the same key), the durable log keeps every approval
    decision — re-approving the same tool_name+hash pair with a new note
    is a second, real event, not a correction of the first."""
    append_approval_record(tmp_path, "toy", _entry(note="first pass"))
    append_approval_record(tmp_path, "toy", _entry(note="re-confirmed after a second reviewer looked"))

    log_path = approval_log_path(tmp_path, "toy")
    lines = [line for line in log_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert len(lines) == 2
    assert json.loads(lines[0])["note"] == "first pass"
    assert json.loads(lines[1])["note"] == "re-confirmed after a second reviewer looked"

    result = verify_policy_chain(log_path)
    assert result.ok


def test_rebuild_snapshot_from_chain_matches_a_healthy_json_snapshot(tmp_path):
    store = PolicyStore(target_slug="toy")
    store.approved.append(_entry(tool_name="tool_a", current_hash="hash-a"))
    store.approved.append(_entry(tool_name="tool_b", current_hash="hash-b"))
    store.save(policy_path(tmp_path, "toy"))

    append_approval_record(tmp_path, "toy", _entry(tool_name="tool_a", current_hash="hash-a"))
    append_approval_record(tmp_path, "toy", _entry(tool_name="tool_b", current_hash="hash-b"))

    rebuilt = rebuild_snapshot_from_chain(tmp_path, "toy")
    on_disk = load_policy(tmp_path, "toy")
    assert rebuilt.to_dict()["approved_drift"] == on_disk.to_dict()["approved_drift"]


def test_rebuild_snapshot_from_chain_exposes_a_hand_edited_snapshot():
    """If someone hand-edits policy/<slug>.json to add an approval that was
    never actually logged, rebuilding from the chain (the source of truth)
    won't reproduce that entry — this is how a human would notice the
    snapshot disagrees with the audit trail."""
    import tempfile
    from pathlib import Path

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        append_approval_record(tmp_path, "toy", _entry(tool_name="tool_a", current_hash="hash-a"))
        store = load_policy(tmp_path, "toy")
        store.approved.append(_entry(tool_name="tool_a", current_hash="hash-a"))
        store.save(policy_path(tmp_path, "toy"))

        # Simulate hand-tampering: add a second, never-logged approval
        # straight into the .json snapshot.
        store = load_policy(tmp_path, "toy")
        store.approved.append(_entry(tool_name="tool_b", current_hash="hash-b"))
        store.save(policy_path(tmp_path, "toy"))

        rebuilt = rebuild_snapshot_from_chain(tmp_path, "toy")
        on_disk = load_policy(tmp_path, "toy")
        assert len(rebuilt.approved) == 1
        assert len(on_disk.approved) == 2
        assert rebuilt.to_dict()["approved_drift"] != on_disk.to_dict()["approved_drift"]


def test_verify_policy_log_cli_reports_ok(tmp_path, capsys):
    from proxy.verify_policy_log import main as verify_main

    append_approval_record(tmp_path, "toy", _entry())
    log_path = approval_log_path(tmp_path, "toy")

    exit_code = verify_main([str(log_path)])
    assert exit_code == 0
    assert "chain intact" in capsys.readouterr().out


def test_verify_policy_log_cli_reports_failure_on_tampered_file(tmp_path, capsys):
    from proxy.verify_policy_log import main as verify_main

    append_approval_record(tmp_path, "toy", _entry())
    log_path = approval_log_path(tmp_path, "toy")
    record = json.loads(log_path.read_text(encoding="utf-8").strip())
    record["note"] = "tampered"
    log_path.write_text(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")

    exit_code = verify_main([str(log_path)])
    assert exit_code == 1
    captured = capsys.readouterr()
    assert "First problem at line 0" in captured.err


def test_verify_policy_log_cli_missing_file(tmp_path, capsys):
    from proxy.verify_policy_log import main as verify_main

    exit_code = verify_main([str(tmp_path / "nope.jsonl")])
    assert exit_code == 1
    assert "No such file" in capsys.readouterr().err
