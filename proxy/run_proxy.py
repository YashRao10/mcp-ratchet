"""CLI entrypoint for the runtime proxy — point Claude Code/Cursor's MCP
config at this instead of a real server directly.

Usage (local downstream target):
    python -m proxy.run_proxy --target toy -- python tests/fixtures/toy_server.py

Usage (remote downstream target):
    export PACT_STAGE_TOKEN=...
    python -m proxy.run_proxy --target pact-stage \
        --url https://stage.acs-pact.com/mcp --bearer-token-env PACT_STAGE_TOKEN

Requires a baseline already written by scanner/run_scan.py for --target's
slug (baselines/<slug>.json) — run a static scan first. The proxy will
still run without one, but drift detection is skipped and every
tools/list call logs an explicit "no_baseline" error record rather than
silently reporting no drift.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from mcp.server.stdio import stdio_server

from proxy.audit_log import AuditLogWriter
from proxy.client_side import DownstreamClient
from proxy.server_side import build_proxy_server
from scanner.connect import HttpTargetSpec, TargetSpec
from scanner.fingerprint import ServerFingerprint


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--target", required=True, help="Target slug — matches baselines/<slug>.json.")
    parser.add_argument("--cwd", default=None, help="Working directory to launch a local downstream target from.")
    parser.add_argument("--url", default=None, help="Remote downstream MCP server URL, instead of a local launch command.")
    parser.add_argument("--bearer-token-env", default=None, help="Env var holding the Bearer token for --url.")
    parser.add_argument(
        "--log-raw-args",
        action="store_true",
        help="Log real tool-call argument values, not just their shape hash. Off by default for privacy.",
    )
    parser.add_argument("command", nargs=argparse.REMAINDER, help="Local downstream launch command, after a literal --.")
    args = parser.parse_args(argv)

    if args.command and args.command[0] == "--":
        args.command = args.command[1:]
    if not args.url and not args.command:
        parser.error("Give either --url <remote downstream MCP endpoint> or a local launch command after a literal '--'.")
    return args


def load_baseline(target_slug: str) -> ServerFingerprint | None:
    baseline_path = REPO_ROOT / "baselines" / f"{target_slug}.json"
    if not baseline_path.exists():
        return None
    data = json.loads(baseline_path.read_text(encoding="utf-8"))
    return ServerFingerprint.from_dict(data)


async def run(args: argparse.Namespace) -> None:
    bearer_token = None
    if args.bearer_token_env:
        bearer_token = os.environ.get(args.bearer_token_env)
        if not bearer_token:
            print(f"Environment variable '{args.bearer_token_env}' is not set or empty.", file=sys.stderr)
            raise SystemExit(1)

    downstream_target = (
        HttpTargetSpec(url=args.url, bearer_token=bearer_token)
        if args.url
        # args.command is already a correctly-tokenized argv list — build
        # directly from it rather than joining+reparsing, which drops
        # whitespace inside any single argument (see scanner/connect.py).
        else TargetSpec.from_argv(args.command, cwd=args.cwd)
    )

    baseline = load_baseline(args.target)
    if baseline is None:
        print(
            f"WARNING: no baseline found at baselines/{args.target}.json — "
            "run scanner.run_scan first for real drift detection. Proxying "
            "without it; every tools/list call will log a no_baseline error record.",
            file=sys.stderr,
        )

    logs_dir = REPO_ROOT / "logs"
    audit_log = AuditLogWriter(logs_dir, args.target, log_raw_args=args.log_raw_args)

    async with DownstreamClient(downstream_target) as downstream:
        with audit_log:
            server = build_proxy_server(downstream, baseline, audit_log)
            init_options = server.create_initialization_options()
            async with stdio_server() as (read_stream, write_stream):
                await server.run(read_stream, write_stream, init_options)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv if argv is not None else sys.argv[1:])
    asyncio.run(run(args))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
