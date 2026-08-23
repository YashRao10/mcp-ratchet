"""Thin CLI-parsing tests for proxy/run_proxy.py — no prior test file
touched parse_args directly. Added alongside the --block-on-drift flag so
its default (off) and opt-in behavior are checked at the argparse layer,
separate from tests/test_server_side.py's behavioral proof of what the
flag actually does once wired to build_proxy_server.
"""

from __future__ import annotations

from proxy.run_proxy import parse_args


def test_block_on_drift_defaults_to_false():
    args = parse_args(["--target", "toy", "--", "python", "server.py"])
    assert args.block_on_drift is False


def test_block_on_drift_flag_sets_true():
    args = parse_args(["--target", "toy", "--block-on-drift", "--", "python", "server.py"])
    assert args.block_on_drift is True
