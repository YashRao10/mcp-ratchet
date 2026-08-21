"""CLI entrypoint for scanning multiple MCP server targets in one run.

Additive to run_scan.py's one-target-per-run design, not a replacement for
it — a single scan is still the right tool for "check this one server
before I approve it." This is for the other real question: "of everything
I have configured right now, is anything already bad?" There's still no
registry-wide crawl (no code here ever reaches out to find *more* targets
than the ones you list) — this is a batch of your own already-known
targets, not registry discovery.

Usage:
    python -m scanner.scan_batch --config targets.json

Config file shape (JSON):
    {
      "targets": [
        {"slug": "toy", "command": ["python", "tests/fixtures/toy_server.py"]},
        {"slug": "my-remote", "url": "https://example.com/mcp", "bearer_token_env": "MY_TOKEN"}
      ]
    }

Each target accepts the same options as run_scan.py's CLI: slug (required),
either command (a list, already tokenized — no shell re-parsing, see
scanner/connect.py's TargetSpec.from_argv) or url+bearer_token_env, plus
optional cwd and skip_injection_check.

One failing target (bad launch command, connection refused, missing env
var) does not abort the batch — every target gets attempted, and the
per-target failure is recorded in that target's own report exactly as
run_scan.py would record it standalone. The aggregate summary at the end
makes it obvious how many of N targets actually connected.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scanner.report import ScanResult, REPORT_SCHEMA_VERSION, now_iso
from scanner.run_scan import run_scan, write_scan_outputs


@dataclass
class TargetConfig:
    slug: str
    command: list[str] | None = None
    cwd: str | None = None
    url: str | None = None
    bearer_token_env: str | None = None
    skip_injection_check: bool = False


def load_targets(config_path: Path) -> list[TargetConfig]:
    data = json.loads(config_path.read_text(encoding="utf-8"))
    raw_targets = data.get("targets")
    if not raw_targets:
        raise ValueError(f"{config_path} has no non-empty 'targets' list.")

    targets: list[TargetConfig] = []
    seen_slugs: set[str] = set()
    for i, raw in enumerate(raw_targets):
        if "slug" not in raw:
            raise ValueError(f"targets[{i}] is missing required field 'slug'.")
        slug = raw["slug"]
        if slug in seen_slugs:
            raise ValueError(f"Duplicate slug '{slug}' in {config_path} — each target needs a unique slug.")
        seen_slugs.add(slug)

        has_command = "command" in raw
        has_url = "url" in raw
        if has_command == has_url:  # neither or both
            raise ValueError(f"targets[{i}] ('{slug}') must have exactly one of 'command' or 'url'.")

        targets.append(
            TargetConfig(
                slug=slug,
                command=raw.get("command"),
                cwd=raw.get("cwd"),
                url=raw.get("url"),
                bearer_token_env=raw.get("bearer_token_env"),
                skip_injection_check=raw.get("skip_injection_check", False),
            )
        )
    return targets


async def _scan_one(target: TargetConfig) -> ScanResult:
    bearer_token = None
    if target.bearer_token_env:
        bearer_token = os.environ.get(target.bearer_token_env)
        if not bearer_token:
            # Same convention as a connect failure elsewhere in this repo:
            # never raise a raw exception out of a single target's scan —
            # report it as a failed connection so the rest of the batch
            # still runs.
            return ScanResult(
                report_schema_version=REPORT_SCHEMA_VERSION,
                target_slug=target.slug,
                target_command=target.url or "",
                generated_at=now_iso(),
                connect_ok=False,
                connect_error=f"Environment variable '{target.bearer_token_env}' is not set or empty.",
                server_name=None,
                server_version=None,
                fingerprint=None,
            )

    try:
        return await run_scan(
            slug=target.slug,
            command=target.command,
            cwd=target.cwd,
            run_injection_check=not target.skip_injection_check,
            url=target.url,
            bearer_token=bearer_token,
        )
    except Exception as exc:  # noqa: BLE001 — deliberate: one bad target must not abort the batch
        return ScanResult(
            report_schema_version=REPORT_SCHEMA_VERSION,
            target_slug=target.slug,
            target_command=" ".join(target.command) if target.command else (target.url or ""),
            generated_at=now_iso(),
            connect_ok=False,
            connect_error=f"{type(exc).__name__}: {exc}",
            server_name=None,
            server_version=None,
            fingerprint=None,
        )


async def scan_all(targets: list[TargetConfig]) -> list[ScanResult]:
    """Scan every target in sequence (not concurrently — a local stdio
    target spawns a real subprocess, and running many at once has no clear
    benefit here while making failures harder to attribute)."""
    results = []
    for target in targets:
        results.append(await _scan_one(target))
    return results


def write_batch_summary(results: list[ScanResult], out_path: Path) -> None:
    connected = [r for r in results if r.connect_ok]
    summary = {
        "batch_schema_version": 1,
        "generated_at": now_iso(),
        "target_count": len(results),
        "connected_count": len(connected),
        "clean_count": sum(1 for r in connected if r.is_clean),
        "targets": [
            {
                "slug": r.target_slug,
                "connect_ok": r.connect_ok,
                "connect_error": r.connect_error,
                "is_clean": r.is_clean if r.connect_ok else None,
                "tool_count": r.fingerprint.tool_count if r.fingerprint else None,
                "suspicious_tool_count": r.suspicious_tool_count,
                "mismatch_count": len(r.mismatch_findings),
                "secret_count": len(r.secret_findings),
                "dependency_finding_count": len(r.dependency_findings),
            }
            for r in results
        ],
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--config", required=True, help="Path to a JSON file listing targets (see module docstring).")
    args = parser.parse_args(argv if argv is not None else sys.argv[1:])

    config_path = Path(args.config)
    if not config_path.exists():
        print(f"No such config file: {config_path}", file=sys.stderr)
        return 1

    try:
        targets = load_targets(config_path)
    except ValueError as exc:
        print(f"Invalid config: {exc}", file=sys.stderr)
        return 1

    results = asyncio.run(scan_all(targets))

    exit_code = 0
    for result in results:
        if not result.connect_ok:
            print(f"FAILED '{result.target_slug}': {result.connect_error}", file=sys.stderr)
            exit_code = 1
            continue
        json_path, html_path, baseline_path = write_scan_outputs(result, result.target_slug)
        status = "CLEAN" if result.is_clean else "FINDINGS PRESENT"
        print(f"Scanned '{result.target_slug}' — {result.fingerprint.tool_count} tool(s) — {status} — {json_path}")
        if not result.is_clean:
            exit_code = 1

    summary_path = REPO_ROOT / "reports" / f"batch-{results[0].generated_at.replace(':', '-')}.json" if results else None
    if summary_path:
        write_batch_summary(results, summary_path)
        connected = sum(1 for r in results if r.connect_ok)
        print(f"\nBatch summary: {connected}/{len(results)} target(s) connected — {summary_path}")

    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
