"""CLI entrypoint for a single static scan of one MCP server.

Usage (local, stdio target):
    python -m scanner.run_scan --slug toy -- python tests/fixtures/toy_server.py

Usage (remote, HTTP target):
    export PACT_STAGE_TOKEN=...
    python -m scanner.run_scan --slug pact-stage \
        --url https://stage.acs-pact.com/mcp --bearer-token-env PACT_STAGE_TOKEN

Everything after a literal "--" is the local launch command for the target
server (so its own flags aren't confused with this CLI's flags). Use
--url instead for a remote target; --bearer-token-env names an environment
variable to read the token from — never pass a token value directly on
the command line, where it could end up in shell history.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scanner.checks import dependency_cve, permission_mismatch, prompt_injection, secret_scan
from scanner.connect import HttpTargetSpec, TargetSpec, enumerate_target
from scanner.fingerprint import fingerprint_tools
from scanner.report import ScanResult, REPORT_SCHEMA_VERSION, now_iso, write_html, write_json


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--slug", required=True, help="Short identifier for this target, e.g. 'pact-stage'.")
    parser.add_argument("--cwd", default=None, help="Working directory to launch a local target from.")
    parser.add_argument("--url", default=None, help="Remote MCP server URL (streamable HTTP), instead of a local launch command.")
    parser.add_argument(
        "--bearer-token-env",
        default=None,
        help="Name of an environment variable holding the Bearer token for --url (never pass the token value directly).",
    )
    parser.add_argument(
        "--skip-injection-check",
        action="store_true",
        help="Skip the Claude API prompt-injection check (useful without ANTHROPIC_API_KEY).",
    )
    parser.add_argument("command", nargs=argparse.REMAINDER, help="Local launch command, after a literal --.")
    args = parser.parse_args(argv)

    if args.command and args.command[0] == "--":
        args.command = args.command[1:]
    if not args.url and not args.command:
        parser.error("Give either --url <remote MCP endpoint> or a local launch command after a literal '--'.")
    return args


async def run_scan(
    slug: str,
    command: list[str] | None,
    cwd: str | None,
    run_injection_check: bool,
    url: str | None = None,
    bearer_token: str | None = None,
) -> ScanResult:
    if url:
        command_string = url
        target = HttpTargetSpec(url=url, bearer_token=bearer_token)
    else:
        # command is already a correctly-tokenized argv list (from argparse's
        # REMAINDER) — build the target straight from it rather than joining
        # to a string and reparsing, which drops whitespace inside any single
        # argument (e.g. a Windows path containing a space). command_string
        # here is display-only (ScanResult.target_command), never reparsed.
        command_string = " ".join(command)
        target = TargetSpec.from_argv(command, cwd=cwd)
    connect_result = await enumerate_target(target)

    if not connect_result.ok:
        return ScanResult(
            report_schema_version=REPORT_SCHEMA_VERSION,
            target_slug=slug,
            target_command=command_string,
            generated_at=now_iso(),
            connect_ok=False,
            connect_error=connect_result.error,
            server_name=None,
            server_version=None,
            fingerprint=None,
        )

    tools = connect_result.tools
    fingerprint = fingerprint_tools(tools, slug)

    injection_verdicts = (
        prompt_injection.check_all_tools(tools) if run_injection_check else []
    )
    mismatch_findings = permission_mismatch.check_all_tools(tools)

    # Source-tree checks (secrets, dependency manifests) only make sense
    # for a local target we actually have a filesystem path for — a remote
    # HTTP target's source isn't ours to read.
    if url:
        secret_findings = []
        dependency_findings = []
    else:
        source_root = Path(cwd) if cwd else Path(command[-1]).resolve().parent
        secret_findings = secret_scan.scan_source_tree(source_root)
        dependency_findings = dependency_cve.check_manifest_dir(source_root)

    return ScanResult(
        report_schema_version=REPORT_SCHEMA_VERSION,
        target_slug=slug,
        target_command=command_string,
        generated_at=now_iso(),
        connect_ok=True,
        connect_error=None,
        server_name=connect_result.server_name,
        server_version=connect_result.server_version,
        fingerprint=fingerprint,
        injection_verdicts=injection_verdicts,
        mismatch_findings=mismatch_findings,
        secret_findings=secret_findings,
        dependency_findings=dependency_findings,
    )


def write_scan_outputs(result: ScanResult, slug: str) -> tuple[Path, Path, Path]:
    """Write a scan's JSON report, HTML report, and (if connect_ok) baseline
    fingerprint to their standard locations under REPO_ROOT. Shared between
    this CLI and scanner/scan_batch.py so both write reports identically.
    Returns (json_path, html_path, baseline_path) — baseline_path may not
    exist on disk if the scan failed to connect (still returned for the
    caller's convenience/logging).
    """
    json_path = REPO_ROOT / "reports" / f"{slug}-scan-{result.generated_at.replace(':', '-')}.json"
    html_path = json_path.with_suffix(".html")
    write_json(result, json_path)
    write_html(result, html_path)

    baseline_path = REPO_ROOT / "baselines" / f"{slug}.json"
    if result.connect_ok and result.fingerprint is not None:
        baseline_path.parent.mkdir(parents=True, exist_ok=True)
        baseline_path.write_text(
            __import__("json").dumps(result.fingerprint.to_dict(), indent=2), encoding="utf-8"
        )
    return json_path, html_path, baseline_path


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv if argv is not None else sys.argv[1:])

    bearer_token = None
    if args.bearer_token_env:
        bearer_token = os.environ.get(args.bearer_token_env)
        if not bearer_token:
            print(f"Environment variable '{args.bearer_token_env}' is not set or empty.", file=sys.stderr)
            return 1

    result = asyncio.run(
        run_scan(
            slug=args.slug,
            command=args.command or None,
            cwd=args.cwd,
            run_injection_check=not args.skip_injection_check,
            url=args.url,
            bearer_token=bearer_token,
        )
    )

    if not result.connect_ok:
        print(f"FAILED to connect to target '{args.slug}': {result.connect_error}", file=sys.stderr)
        return 1

    json_path, html_path, baseline_path = write_scan_outputs(result, args.slug)

    print(f"Scanned '{args.slug}' — {result.server_name or '(unnamed server)'}")
    print(f"  Tools found: {result.fingerprint.tool_count}")
    print(f"  Suspicious (prompt-injection): {result.suspicious_tool_count}")
    print(f"  Needs review: {result.needs_review_count}")
    print(f"  Permission mismatches: {len(result.mismatch_findings)}")
    print(f"  Secrets found: {len(result.secret_findings)}")
    print(f"  Dependency findings: {len(result.dependency_findings)}")
    print(f"  Status: {'CLEAN' if result.is_clean else 'FINDINGS PRESENT'}")
    print(f"  Report: {json_path}")
    print(f"  Baseline written: {baseline_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
