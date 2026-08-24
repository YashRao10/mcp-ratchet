"""Tests for the proxy.approve_drift CLI entrypoint — the actual way a
human would approve a reviewed drift event, reading real drift_event
records back out of a real audit log written by AuditLogWriter. Same
pattern as tests/test_verify_log_cli.py for proxy.verify_log: exercise the
log-reading/plumbing concern directly against records a real AuditLogWriter
produced, rather than a hand-built dict.
"""

from __future__ import annotations

from proxy.approve_drift import main
from proxy.audit_log import AuditLogWriter
from proxy.drift import DRIFT_DESCRIPTION_CHANGED, DRIFT_TOOL_ADDED, DriftEvent
from proxy.policy import approval_log_path, load_policy, verify_policy_chain


def _write_log_with_one_drift_event(logs_dir, target="toy") -> "Path":
    with AuditLogWriter(logs_dir, target) as log:
        log.drift_event(
            DriftEvent(
                drift_type=DRIFT_TOOL_ADDED,
                tool_name="delete_all_notes",
                baseline_hash=None,
                current_hash="hash-a",
                detail="Tool 'delete_all_notes' was not present in the baseline and now is.",
            )
        )
    return log.path


def test_approve_writes_a_policy_file_and_prints_confirmation(tmp_path, monkeypatch, capsys):
    logs_dir = tmp_path / "logs"
    _write_log_with_one_drift_event(logs_dir)

    monkeypatch.setattr("proxy.approve_drift.REPO_ROOT", tmp_path)
    exit_code = main(["toy", "delete_all_notes"])
    assert exit_code == 0

    out = capsys.readouterr().out
    assert "Approved 1 drift transition" in out
    assert "delete_all_notes" in out

    store = load_policy(tmp_path, "toy")
    assert len(store.approved) == 1
    assert store.approved[0].tool_name == "delete_all_notes"
    assert store.approved[0].current_hash == "hash-a"

    # The CLI must also durably log this approval, not just update the
    # overwritable .json snapshot — that's the whole point of pairing
    # store.save() with append_approval_record() in approve_drift.main().
    log_path = approval_log_path(tmp_path, "toy")
    assert log_path.exists()
    result = verify_policy_chain(log_path)
    assert result.ok
    assert result.records_checked == 1


def test_two_separate_approve_invocations_chain_together(tmp_path, monkeypatch):
    """Approving two different tools across two separate CLI invocations
    (two separate processes, in reality) must still produce one valid
    chain — the second call has to read the first call's trailing hash off
    disk, not assume it's starting from genesis."""
    logs_dir = tmp_path / "logs"
    with AuditLogWriter(logs_dir, "toy") as log:
        log.drift_event(
            DriftEvent(
                drift_type=DRIFT_TOOL_ADDED, tool_name="tool_a",
                baseline_hash=None, current_hash="hash-a", detail="added",
            )
        )
        log.drift_event(
            DriftEvent(
                drift_type=DRIFT_TOOL_ADDED, tool_name="tool_b",
                baseline_hash=None, current_hash="hash-b", detail="added",
            )
        )

    monkeypatch.setattr("proxy.approve_drift.REPO_ROOT", tmp_path)
    assert main(["toy", "tool_a"]) == 0
    assert main(["toy", "tool_b"]) == 0

    log_path = approval_log_path(tmp_path, "toy")
    lines = [line for line in log_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert len(lines) == 2

    result = verify_policy_chain(log_path)
    assert result.ok
    assert result.records_checked == 2


def test_approve_records_approved_by_and_note(tmp_path, monkeypatch):
    logs_dir = tmp_path / "logs"
    _write_log_with_one_drift_event(logs_dir)

    monkeypatch.setattr("proxy.approve_drift.REPO_ROOT", tmp_path)
    exit_code = main(["toy", "delete_all_notes", "--approved-by", "yash", "--note", "reviewed, read-only"])
    assert exit_code == 0

    store = load_policy(tmp_path, "toy")
    assert store.approved[0].approved_by == "yash"
    assert store.approved[0].note == "reviewed, read-only"


def test_approve_fails_when_no_log_exists_for_target(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr("proxy.approve_drift.REPO_ROOT", tmp_path)
    exit_code = main(["toy", "delete_all_notes"])
    assert exit_code == 1
    assert "No audit log found" in capsys.readouterr().err


def test_approve_fails_when_tool_has_no_drift_events_in_log(tmp_path, monkeypatch, capsys):
    logs_dir = tmp_path / "logs"
    _write_log_with_one_drift_event(logs_dir)

    monkeypatch.setattr("proxy.approve_drift.REPO_ROOT", tmp_path)
    exit_code = main(["toy", "some_other_tool"])
    assert exit_code == 1
    assert "No drift_event records" in capsys.readouterr().err


def test_approve_only_covers_the_most_recent_transition(tmp_path, monkeypatch):
    """A tool that drifted twice (two different tools/list diffs, two
    different current_hash values) should only have its latest transition
    approved — approving the CLI's default target shouldn't reach back and
    approve a stale, superseded hash."""
    logs_dir = tmp_path / "logs"
    with AuditLogWriter(logs_dir, "toy") as log:
        log.drift_event(
            DriftEvent(
                drift_type=DRIFT_TOOL_ADDED,
                tool_name="delete_all_notes",
                baseline_hash=None,
                current_hash="hash-a",
                detail="added",
            )
        )
        log.drift_event(
            DriftEvent(
                drift_type=DRIFT_DESCRIPTION_CHANGED,
                tool_name="delete_all_notes",
                baseline_hash="hash-a",
                current_hash="hash-b",
                detail="changed again",
            )
        )

    monkeypatch.setattr("proxy.approve_drift.REPO_ROOT", tmp_path)
    exit_code = main(["toy", "delete_all_notes"])
    assert exit_code == 0

    store = load_policy(tmp_path, "toy")
    assert len(store.approved) == 1
    assert store.approved[0].current_hash == "hash-b"
    assert store.approved[0].baseline_hash == "hash-a"
