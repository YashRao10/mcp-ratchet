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
    all_drift_events: list[dict] = field(default_factory=list)
    session_count: int = 0
    blocked_call_count: int = 0
    recent_blocked_calls: list[dict] = field(default_factory=list)
    all_blocked_calls: list[dict] = field(default_factory=list)
    # Drift-evaluation state (TOR-8/TOR-9). drift_status is one of:
    #   "evaluated"         — the most recent proxy session diffed the live
    #                         surface against a real baseline
    #   "baseline_error"    — most recent session had a baseline file that
    #                         was unreadable/unparseable/unsupported (TOR-9)
    #   "no_baseline"       — most recent session ran with no baseline file (TOR-8)
    #   "no_proxy_activity" — the proxy has never listed tools for this target
    # An unusable or missing baseline in the latest session means drift was
    # NOT evaluated — absence of drift events must not be read as "no drift".
    drift_status: str = "no_proxy_activity"
    no_baseline_session_count: int = 0
    baseline_error_session_count: int = 0
    recent_baseline_issues: list[dict] = field(default_factory=list)

    @property
    def is_clean(self) -> bool:
        if self.latest_scan is None:
            return False
        if self.drift_not_evaluated:
            return False
        return bool(self.latest_scan.get("summary", {}).get("is_clean"))

    @property
    def has_live_drift(self) -> bool:
        return self.drift_event_count > 0

    @property
    def has_blocked_calls(self) -> bool:
        return self.blocked_call_count > 0

    @property
    def drift_not_evaluated(self) -> bool:
        """True when the latest proxy session could not evaluate drift —
        the point TOR-8/TOR-9 make: this state must never render as clean."""
        return self.drift_status in ("baseline_error", "no_baseline")

    @property
    def drift_evaluation(self) -> str:
        """Machine-readable marker for drift-summary.json — "performed"
        only when the latest session actually diffed against a baseline."""
        return "performed" if self.drift_status == "evaluated" else "not_performed"

    def to_dict(self) -> dict:
        return {
            "slug": self.slug,
            "drift_evaluation": self.drift_evaluation,
            "drift_status": self.drift_status,
            "drift_event_count": self.drift_event_count,
            "blocked_call_count": self.blocked_call_count,
            "no_baseline_session_count": self.no_baseline_session_count,
            "baseline_error_session_count": self.baseline_error_session_count,
            "call_count": self.call_count,
            "session_count": self.session_count,
            "scan_is_clean": bool((self.latest_scan or {}).get("summary", {}).get("is_clean"))
            if self.latest_scan
            else None,
        }


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
        blocked_records = [r for r in records if r.get("record_type") == "blocked_call"]
        anomaly_calls = [r for r in call_records if r.get("anomaly_flags")]
        session_ids = {r.get("session_id") for r in records if r.get("session_id")}

        drift_status, no_baseline_count, baseline_error_count, baseline_issues = _drift_evaluation_state(records)

        summaries.append(
            TargetSummary(
                slug=slug,
                latest_scan=latest_scans.get(slug),
                call_count=len(call_records),
                drift_event_count=len(drift_records),
                anomaly_call_count=len(anomaly_calls),
                recent_drift_events=drift_records[-10:],
                all_drift_events=drift_records,
                session_count=len(session_ids),
                blocked_call_count=len(blocked_records),
                recent_blocked_calls=blocked_records[-10:],
                all_blocked_calls=blocked_records,
                drift_status=drift_status,
                no_baseline_session_count=no_baseline_count,
                baseline_error_session_count=baseline_error_count,
                recent_baseline_issues=baseline_issues[-10:],
            )
        )

    return summaries


def _drift_evaluation_state(records: list[dict]) -> tuple[str, int, int, list[dict]]:
    """Work out whether the latest proxy session actually evaluated drift.

    Records arrive in file-then-line (chronological) order, so grouping by
    session_id preserves session order. The last session that produced any
    tools/list outcome — a snapshot, a no_baseline error, or a
    baseline_error error — determines the current drift_status. Counts and
    the issue list span every session, for context on the detail page.
    """
    sessions: dict[str, list[dict]] = {}
    for r in records:
        sid = r.get("session_id")
        if sid:
            sessions.setdefault(sid, []).append(r)

    drift_status = "no_proxy_activity"
    no_baseline_count = 0
    baseline_error_count = 0
    issues: list[dict] = []

    for recs in sessions.values():
        errors = [r for r in recs if r.get("record_type") == "error"]
        had_baseline_error = any(r.get("error_type") == "baseline_error" for r in errors)
        had_no_baseline = any(r.get("error_type") == "no_baseline" for r in errors)
        had_snapshot = any(r.get("record_type") == "tools_list_snapshot" for r in recs)

        if had_baseline_error:
            baseline_error_count += 1
            issues += [r for r in errors if r.get("error_type") == "baseline_error"]
            drift_status = "baseline_error"
        elif had_no_baseline:
            no_baseline_count += 1
            issues += [r for r in errors if r.get("error_type") == "no_baseline"]
            drift_status = "no_baseline"
        elif had_snapshot:
            drift_status = "evaluated"
        # A session with none of these leaves drift_status unchanged.

    return drift_status, no_baseline_count, baseline_error_count, issues
