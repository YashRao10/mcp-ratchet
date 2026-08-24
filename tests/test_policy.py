"""Tests for proxy/policy.py's persistent drift-approval store: save/load
round-tripping, exact-transition matching, and the fail-safe-closed default
when no policy file exists yet. Direct unit-style tests, same pattern as
tests/test_audit_log.py for the other local-JSON-file concern in this
project — the live-subprocess proof that approval actually changes
--block-on-drift's behavior lives in tests/test_policy_block_on_drift.py.
"""

from __future__ import annotations

from proxy.drift import DRIFT_DESCRIPTION_CHANGED, DRIFT_TOOL_ADDED, DriftEvent
from proxy.policy import PolicyStore, load_policy, policy_path


def _added_event(current_hash="hash-a") -> DriftEvent:
    return DriftEvent(
        drift_type=DRIFT_TOOL_ADDED,
        tool_name="delete_all_notes",
        baseline_hash=None,
        current_hash=current_hash,
        detail="Tool 'delete_all_notes' was not present in the baseline and now is.",
    )


def test_unapproved_event_is_not_approved():
    store = PolicyStore(target_slug="toy")
    assert store.is_approved(_added_event()) is False


def test_approving_an_event_makes_is_approved_true_for_the_exact_transition():
    store = PolicyStore(target_slug="toy")
    event = _added_event()
    store.approve_event(event, approved_by="yash", note="reviewed, harmless")
    assert store.is_approved(event) is True


def test_a_further_drift_on_an_approved_tool_is_not_approved():
    """The core guarantee: approving one specific hash transition must NOT
    approve whatever that tool becomes next — a second, different edit
    produces a new current_hash and must block again."""
    store = PolicyStore(target_slug="toy")
    first = _added_event(current_hash="hash-a")
    store.approve_event(first)
    assert store.is_approved(first) is True

    second = DriftEvent(
        drift_type=DRIFT_DESCRIPTION_CHANGED,
        tool_name="delete_all_notes",
        baseline_hash="hash-a",
        current_hash="hash-b",
        detail="Field 'description' changed from ... to ...",
    )
    assert store.is_approved(second) is False


def test_re_approving_the_same_transition_is_idempotent_not_duplicating():
    store = PolicyStore(target_slug="toy")
    event = _added_event()
    store.approve_event(event, note="first pass")
    store.approve_event(event, note="re-reviewed")
    assert len(store.approved) == 1
    assert store.approved[0].note == "re-reviewed"


def test_save_and_load_round_trips(tmp_path):
    store = PolicyStore(target_slug="toy")
    store.approve_event(_added_event(), approved_by="yash", note="reviewed")
    path = policy_path(tmp_path, "toy")
    store.save(path)

    reloaded = load_policy(tmp_path, "toy")
    assert reloaded.target_slug == "toy"
    assert len(reloaded.approved) == 1
    assert reloaded.is_approved(_added_event()) is True
    assert reloaded.approved[0].approved_by == "yash"
    assert reloaded.approved[0].note == "reviewed"


def test_load_policy_with_no_file_yet_returns_empty_store_not_an_error(tmp_path):
    store = load_policy(tmp_path, "some-target-with-no-policy-file")
    assert store.approved == []
    # Fail-safe-closed: nothing approved means nothing is approved.
    assert store.is_approved(_added_event()) is False
