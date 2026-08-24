"""CLI entrypoint to durably approve a reviewed drift event, so
--block-on-drift stops re-blocking it in every future proxy session. See
proxy/policy.py's module docstring for exactly what an approval does and
does not cover (in particular: it's scoped to the exact tool_name +
baseline_hash + current_hash transition, so a further drift on the same
tool blocks again).

Usage:
    python -m proxy.approve_drift <target> <tool_name>
    python -m proxy.approve_drift toy delete_all_notes --log logs/toy-20260821T221732Z.jsonl
    python -m proxy.approve_drift toy delete_all_notes --approved-by yash --note "reviewed, read-only"

Reads drift_event records straight out of a real proxy session's audit log
(logs/<target>-*.jsonl by default, the newest one by filename timestamp)
rather than taking a hash on the command line — a human should be approving
a specific, already-observed drift they looked at, not typing a hash in by
hand. Exits non-zero if no matching drift_event record exists in the log:
approving something that was never actually observed by this proxy would
defeat the point of this being a review step, not a blanket bypass.

Only the most recent observed transition for <tool_name> in the log is
approved (its baseline_hash/current_hash pair) — if that tool drifted more
than once across the log's history, older transitions are not retroactively
approved, since --block-on-drift only ever cares about the current one
anyway (see proxy/server_side.py's build_proxy_server docstring on
"currently believes").
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from proxy.drift import DriftEvent
from proxy.policy import append_approval_record, load_policy, policy_path


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("target", help="Target slug — matches baselines/<slug>.json and policy/<slug>.json.")
    parser.add_argument("tool_name", help="Name of the drifted tool to approve.")
    parser.add_argument(
        "--log",
        default=None,
        help="Specific audit log .jsonl to read drift events from. Defaults to the newest logs/<target>-*.jsonl.",
    )
    parser.add_argument("--approved-by", default=None, help="Optional reviewer name/identifier to record with the approval.")
    parser.add_argument("--note", default=None, help="Optional free-text note to record with the approval.")
    return parser.parse_args(argv)


def _latest_log_for_target(logs_dir: Path, target: str) -> Path | None:
    # Session timestamps in the filename (see AuditLogWriter) are
    # zero-padded and zulu, so lexical sort == chronological sort.
    candidates = sorted(logs_dir.glob(f"{target}-*.jsonl"))
    return candidates[-1] if candidates else None


def _drift_records_for_tool(log_path: Path, tool_name: str) -> list[dict]:
    records = []
    for line in log_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        record = json.loads(line)
        if record.get("record_type") == "drift_event" and record.get("tool_name") == tool_name:
            records.append(record)
    return records


def _most_recent_transition(records: list[dict]) -> list[dict]:
    """Multiple field-level drift_event records can describe one and the
    same tools/list transition (e.g. both description and schema changed in
    the same diff) — they share one baseline_hash/current_hash pair. Find
    the latest such record by `sequence` and return every record sharing
    its exact pair, so approving covers the whole transition, not just one
    field of it."""
    latest = max(records, key=lambda r: r.get("sequence", -1))
    target_pair = (latest.get("baseline_hash"), latest.get("current_hash"))
    return [r for r in records if (r.get("baseline_hash"), r.get("current_hash")) == target_pair]


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv if argv is not None else sys.argv[1:])

    logs_dir = REPO_ROOT / "logs"
    log_path = Path(args.log) if args.log else _latest_log_for_target(logs_dir, args.target)
    if log_path is None or not log_path.exists():
        print(
            f"No audit log found for target '{args.target}' — pass --log explicitly, "
            "or run the proxy against this target first.",
            file=sys.stderr,
        )
        return 1

    records = _drift_records_for_tool(log_path, args.tool_name)
    if not records:
        print(f"No drift_event records for tool '{args.tool_name}' found in {log_path}.", file=sys.stderr)
        return 1

    to_approve = _most_recent_transition(records)

    store = load_policy(REPO_ROOT, args.target)
    approved_entries = [
        store.approve_event(
            DriftEvent(
                drift_type=record["drift_type"],
                tool_name=record["tool_name"],
                baseline_hash=record.get("baseline_hash"),
                current_hash=record.get("current_hash"),
                detail=record.get("detail", ""),
                whitespace_only_change=record.get("whitespace_only_change", False),
            ),
            approved_by=args.approved_by,
            note=args.note,
        )
        for record in to_approve
    ]
    out_path = policy_path(REPO_ROOT, args.target)
    store.save(out_path)
    for entry in approved_entries:
        append_approval_record(REPO_ROOT, args.target, entry)

    print(f"Approved {len(approved_entries)} drift transition(s) for '{args.tool_name}' -> {out_path}")
    for entry in approved_entries:
        print(f"  {entry.drift_type}: baseline_hash={entry.baseline_hash} current_hash={entry.current_hash}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
