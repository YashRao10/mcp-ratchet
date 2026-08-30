"""The single most important test in this project. Everything else can be
correct and this project still wouldn't have proven its actual premise —
that a real, post-baseline change to a live server's tool surface gets
detected — without this test passing.

Does not edit tests/fixtures/toy_server.py in place (that would be a
mutating, order-dependent test touching shared repo state). Instead
copies it to a temp dir per test and edits the copy, so this stays a real
live-subprocess test without side effects on any other test.
"""

from pathlib import Path

import pytest

from proxy.drift import (
    DRIFT_DESCRIPTION_CHANGED,
    DRIFT_TOOL_ADDED,
    diff_against_baseline,
)
from scanner.connect import TargetSpec, enumerate_target
from scanner.fingerprint import fingerprint_tools

ORIGINAL_TOY_SERVER = Path(__file__).resolve().parent / "fixtures" / "toy_server.py"


async def _connect_and_fingerprint(server_path: Path, slug: str):
    target = TargetSpec(command="python", args=[str(server_path)])
    result = await enumerate_target(target)
    assert result.ok, f"Failed to connect: {result.error}"
    return fingerprint_tools(result.tools, slug), result.tools


@pytest.fixture
def toy_server_copy(tmp_path):
    dest = tmp_path / "toy_server.py"
    dest.write_text(ORIGINAL_TOY_SERVER.read_text(encoding="utf-8"), encoding="utf-8")
    return dest


async def test_unchanged_server_produces_zero_drift_events(toy_server_copy):
    baseline_fp, _ = await _connect_and_fingerprint(toy_server_copy, "toy-drift-test")
    _, live_tools = await _connect_and_fingerprint(toy_server_copy, "toy-drift-test")

    _, events = diff_against_baseline(live_tools, baseline_fp)
    assert events == []


async def test_description_change_between_two_runs_is_flagged_as_drift(toy_server_copy):
    """The core proof: baseline against the original toy server, then a
    real edit to a real live server's tool description, then a second
    real connection — and the resulting drift must be caught, correctly
    attributed to the right tool, and correctly classified.
    """
    baseline_fp, _ = await _connect_and_fingerprint(toy_server_copy, "toy-drift-test")

    original_text = toy_server_copy.read_text(encoding="utf-8")
    edited_text = original_text.replace(
        '"""Get the current weather for a city. Read-only, no side effects."""',
        '"""Get the current weather for a city. Now also logs your location history."""',
    )
    assert edited_text != original_text, "The replace() didn't match — fixture text may have changed."
    toy_server_copy.write_text(edited_text, encoding="utf-8")

    _, live_tools_after_edit = await _connect_and_fingerprint(toy_server_copy, "toy-drift-test")

    _, events = diff_against_baseline(live_tools_after_edit, baseline_fp)

    weather_events = [e for e in events if e.tool_name == "get_weather"]
    assert len(weather_events) == 1, f"Expected exactly one drift event for get_weather, got: {events}"
    assert weather_events[0].drift_type == DRIFT_DESCRIPTION_CHANGED
    assert "location history" in weather_events[0].detail
    # Real content changed, not just whitespace — must not be mislabeled.
    assert weather_events[0].whitespace_only_change is False

    # And nothing else should have drifted — proves this isn't just
    # flagging every tool indiscriminately.
    other_events = [e for e in events if e.tool_name != "get_weather"]
    assert other_events == []


async def test_new_tool_added_between_two_runs_is_flagged_as_tool_added(toy_server_copy):
    baseline_fp, _ = await _connect_and_fingerprint(toy_server_copy, "toy-drift-test")

    original_text = toy_server_copy.read_text(encoding="utf-8")
    new_tool = '''

@mcp.tool()
def delete_all_notes() -> str:
    """Delete every saved note. Newly added after the baseline."""
    return "all notes deleted"
'''
    edited_text = original_text.replace('if __name__ == "__main__":', new_tool + '\n\nif __name__ == "__main__":')
    assert edited_text != original_text
    toy_server_copy.write_text(edited_text, encoding="utf-8")

    _, live_tools_after_edit = await _connect_and_fingerprint(toy_server_copy, "toy-drift-test")
    _, events = diff_against_baseline(live_tools_after_edit, baseline_fp)

    added = [e for e in events if e.drift_type == DRIFT_TOOL_ADDED]
    assert len(added) == 1
    assert added[0].tool_name == "delete_all_notes"
    # Not a field-level change (a whole new tool) — the flag never applies.
    assert added[0].whitespace_only_change is False
    # Nothing else drifted — the one added tool is the ONLY event of any kind.
    assert len(events) == 1


async def test_whitespace_only_edit_still_drifts_but_is_labeled_as_such(toy_server_copy):
    """The exact-hash ratchet must still fire on a purely cosmetic edit —
    that guarantee is non-negotiable (see README) — but the event should
    now additionally be labeled whitespace_only_change=True so a human (or
    the dashboard) can tell it apart from a real content change at a
    glance, without the underlying detection ever being weakened.
    """
    baseline_fp, _ = await _connect_and_fingerprint(toy_server_copy, "toy-drift-test")

    original_text = toy_server_copy.read_text(encoding="utf-8")
    edited_text = original_text.replace(
        '"""Get the current weather for a city. Read-only, no side effects."""',
        '"""Get   the current  weather for a city.  Read-only, no side effects.  """',
    )
    assert edited_text != original_text, "The replace() didn't match — fixture text may have changed."
    toy_server_copy.write_text(edited_text, encoding="utf-8")

    _, live_tools_after_edit = await _connect_and_fingerprint(toy_server_copy, "toy-drift-test")
    _, events = diff_against_baseline(live_tools_after_edit, baseline_fp)

    weather_events = [e for e in events if e.tool_name == "get_weather"]
    assert len(weather_events) == 1, f"Expected exactly one drift event for get_weather, got: {events}"
    # Still a real drift event — the hash still changed, the ratchet still fired.
    assert weather_events[0].drift_type == DRIFT_DESCRIPTION_CHANGED
    # But correctly labeled as whitespace-only, unlike the real-content-change test above.
    assert weather_events[0].whitespace_only_change is True
