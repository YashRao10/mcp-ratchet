"""Per-classification drift cases the live-subprocess tests in
tests/test_drift.py do not cover: a removed tool (TOR-4), and the three
modified-tool shapes (TOR-5) — input-schema change, annotations change,
and several fields changing at once.

Exercises diff_against_baseline directly with constructed tool dicts —
fingerprint_tools accepts plain dicts (see tests/test_fingerprint.py), so
this is requirements-based testing of the classifier itself without a
subprocess hop. tests/test_drift.py already proves the full live path.
"""

from __future__ import annotations

from proxy.drift import (
    DRIFT_ANNOTATIONS_CHANGED,
    DRIFT_DESCRIPTION_CHANGED,
    DRIFT_SCHEMA_CHANGED,
    DRIFT_TOOL_REMOVED,
    diff_against_baseline,
)
from scanner.fingerprint import fingerprint_tools

SLUG = "toy-classify"


def _tool(name, description="does a thing", input_schema=None, annotations=None):
    t = {"name": name, "description": description}
    t["input_schema"] = input_schema or {"type": "object", "properties": {}}
    if annotations is not None:
        t["annotations"] = annotations
    return t


def _baseline(tools):
    return fingerprint_tools(tools, SLUG)


def test_removed_tool_is_flagged_as_tool_removed():
    baseline = _baseline([_tool("alpha"), _tool("beta")])
    _, events = diff_against_baseline([_tool("alpha")], baseline)

    assert len(events) == 1
    assert events[0].drift_type == DRIFT_TOOL_REMOVED
    assert events[0].tool_name == "beta"
    assert events[0].current_hash is None
    assert events[0].whitespace_only_change is False


def test_input_schema_change_is_flagged_as_schema_changed():
    before = _tool("alpha", input_schema={"type": "object", "properties": {"city": {"type": "string"}}})
    after = _tool("alpha", input_schema={"type": "object", "properties": {
        "city": {"type": "string"}, "cmd": {"type": "string"}}})
    baseline = _baseline([before])
    _, events = diff_against_baseline([after], baseline)

    schema_events = [e for e in events if e.drift_type == DRIFT_SCHEMA_CHANGED]
    assert len(schema_events) == 1
    assert schema_events[0].tool_name == "alpha"
    assert "input_schema" in schema_events[0].detail


def test_annotations_change_is_flagged_as_annotations_changed():
    before = _tool("alpha", annotations={"readOnlyHint": True})
    after = _tool("alpha", annotations={"readOnlyHint": False})
    baseline = _baseline([before])
    _, events = diff_against_baseline([after], baseline)

    ann_events = [e for e in events if e.drift_type == DRIFT_ANNOTATIONS_CHANGED]
    assert len(ann_events) == 1
    assert ann_events[0].tool_name == "alpha"


def test_multiple_fields_changing_at_once_each_reported():
    before = _tool("alpha", description="read-only lookup",
                   input_schema={"type": "object", "properties": {"q": {"type": "string"}}},
                   annotations={"readOnlyHint": True})
    after = _tool("alpha", description="now also writes",
                  input_schema={"type": "object", "properties": {
                      "q": {"type": "string"}, "force": {"type": "boolean"}}},
                  annotations={"readOnlyHint": False})
    baseline = _baseline([before])
    _, events = diff_against_baseline([after], baseline)

    kinds = sorted(e.drift_type for e in events)
    # Exactly one event per changed field — no more, no fewer.
    assert kinds == sorted([
        DRIFT_DESCRIPTION_CHANGED, DRIFT_SCHEMA_CHANGED, DRIFT_ANNOTATIONS_CHANGED
    ])
    # Every event names the tool and carries both baseline and current hash.
    for e in events:
        assert e.tool_name == "alpha"
        assert e.baseline_hash and e.current_hash
        assert e.baseline_hash != e.current_hash


def test_unchanged_surface_produces_no_events():
    tools = [_tool("alpha"), _tool("beta", annotations={"readOnlyHint": True})]
    baseline = _baseline(tools)
    # Re-fingerprint an equal-but-reordered list — order must not matter (TOR-7).
    _, events = diff_against_baseline(list(reversed(tools)), baseline)
    assert events == []
