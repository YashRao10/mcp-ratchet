"""Aggregates real scanner reports (reports/*.json) and real proxy audit
logs (logs/*.jsonl) into the summary data reporting/dashboard.py renders.

Pure data-shaping — this module makes no judgment calls of its own, it
just counts and groups what scanner/ and proxy/ already decided.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class TargetSummary:
    slug: str
    latest_scan: dict | None = None
    call_count: int = 0
    drift_event_count: int = 0
    anomaly_call_count: int = 0
    recent_drift_events: list[dict] = field(default_factory=list)
    session_count: int = 0

    @property
    def is_clean(self) -> bool:
        if self.latest_scan is None:
            return False
        return bool(self.latest_scan.get("summary", {}).get("is_clean"))

    @property
    def has_live_drift(self) -> bool:
        return self.drift_event_count > 0


def load_latest_scans(reports_dir: Path) -> dict[str, dict]:
    """One JSON scan report per target_slug — the most recent by
    generated_at wins if a slug has multiple reports on disk."""
    latest: dict[str, dict] = {}
    for path in sorted(reports_dir.glob("*-scan-*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        slug = data.get("target_slug")
        if not slug:
            continue
        existing = latest.get(slug)
        if existing is None or data.get("generated_at", "") > existing.get("generated_at", ""):
            latest[slug] = data
    return latest


def load_audit_logs(logs_dir: Path) -> dict[str, list[dict]]:
    """target_slug -> list of every JSONL record across every session log
    for that slug, in file-then-line order."""
    by_slug: dict[str, list[dict]] = {}
    if not logs_dir.exists():
        return by_slug
    for path in sorted(logs_dir.glob("*.jsonl")):
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except ValueError:
                continue
            slug = record.get("target_slug")
            if not slug:
                continue
            by_slug.setdefault(slug, []).append(record)
    return by_slug


def build_summaries(reports_dir: Path, logs_dir: Path) -> list[TargetSummary]:
    latest_scans = load_latest_scans(reports_dir)
    logs_by_slug = load_audit_logs(logs_dir)

    all_slugs = sorted(set(latest_scans.keys()) | set(logs_by_slug.keys()))
    summaries = []

    for slug in all_slugs:
        records = logs_by_slug.get(slug, [])
        call_records = [r for r in records if r.get("record_type") == "tool_call"]
        drift_records = [r for r in records if r.get("record_type") == "drift_event"]
        anomaly_calls = [r for r in call_records if r.get("anomaly_flags")]
        session_ids = {r.get("session_id") for r in records if r.get("session_id")}

        summaries.append(
            TargetSummary(
                slug=slug,
                latest_scan=latest_scans.get(slug),
                call_count=len(call_records),
                drift_event_count=len(drift_records),
                anomaly_call_count=len(anomaly_calls),
                recent_drift_events=drift_records[-10:],
                session_count=len(session_ids),
            )
        )

    return summaries
