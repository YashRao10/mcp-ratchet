"""Regression test for a real bug found dogfooding the scanner against a
real local MCP server (not the toy fixture) on Windows: a launch command
whose path contains a space silently broke.

Both run_scan.py and run_proxy.py used to build the downstream launch
command by joining argparse's already-correctly-tokenized argv list back
into a single string with `" ".join(...)`, then reparsing that string with
shlex in TargetSpec.from_command_string. That round trip only works when no
individual argument contains whitespace — which most real Windows paths do,
e.g. `python "C:\\Users\\Yash Rao\\...\\server.py"`. The rejoin+reparse
silently produced ['python', 'C:\\Users\\Yash', 'Rao\\...\\server.py'],
so the subprocess launch failed with a file-not-found error that had
nothing to do with the actual target server.

The fix is TargetSpec.from_argv, which builds the target directly from the
already-tokenized argv list and never reparses a string. This test proves
that path specifically: a fixture launched from a directory whose name
contains a space connects successfully.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from scanner.connect import TargetSpec, enumerate_target

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"
TOY_SERVER = FIXTURES_DIR / "toy_server.py"


@pytest.fixture
def toy_server_at_spaced_path(tmp_path: Path) -> Path:
    """Copy the toy fixture into a directory whose name has a space in it —
    reproduces the real-world path shape that broke (e.g. 'Yash Rao')."""
    spaced_dir = tmp_path / "a directory with spaces"
    spaced_dir.mkdir()
    dest = spaced_dir / "toy_server.py"
    shutil.copy(TOY_SERVER, dest)
    return dest


def test_from_argv_preserves_a_path_containing_a_space():
    """The core regression, isolated from any subprocess/asyncio machinery:
    from_argv must NOT split 'C:\\a path\\with spaces\\server.py' into two
    args just because it contains whitespace — it's already one argv
    element, exactly as the OS/shell delivered it."""
    spaced_path = r"C:\a path\with spaces\server.py"
    target = TargetSpec.from_argv(["python", spaced_path])
    assert target.command == "python"
    assert target.args == [spaced_path]


def test_from_command_string_is_the_unsafe_round_trip_by_contrast():
    """Documents *why* from_argv exists: the string round trip this test
    exercises is exactly the bug — shown here as a known limitation of
    from_command_string, not exercised by any real call site anymore."""
    spaced_path = r"C:\a path\with spaces\server.py"
    command_string = " ".join(["python", spaced_path])
    target = TargetSpec.from_command_string(command_string)
    assert target.args != [spaced_path], (
        "if this ever starts passing, from_command_string stopped being "
        "the unsafe primitive this test documents — from_argv should "
        "still be preferred at every real call site regardless"
    )


async def test_real_connection_to_a_target_launched_from_a_spaced_path(
    toy_server_at_spaced_path: Path,
):
    """End-to-end: the exact scenario that broke — a real stdio connection
    to a server whose launch path contains a space, built the same way
    run_scan.py and run_proxy.py build it (argv list straight into
    TargetSpec, no string round trip)."""
    target = TargetSpec.from_argv(["python", str(toy_server_at_spaced_path)])
    result = await enumerate_target(target)
    assert result.ok, f"Failed to connect to a target at a spaced path: {result.error}"
    names = {t.name for t in result.tools}
    assert names == {"get_weather", "read_notes", "list_recent_files", "summarize_document"}
