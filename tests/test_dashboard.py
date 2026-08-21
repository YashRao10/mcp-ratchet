import json

from reporting.audit_summary import build_summaries
from reporting.dashboard import render_dashboard


def _write_scan(reports_dir, slug, is_clean=True, generated_at="2026-08-21T00:00:00+00:00"):
    reports_dir.mkdir(parents=True, exist_ok=True)
    data = {
        "target_slug": slug,
        "generated_at": generated_at,
        "server_name": f"{slug}-server",
        "fingerprint": {"tool_count": 3},
        "summary": {
            "is_clean": is_clean,
            "suspicious_tool_count": 0 if is_clean else 1,
            "needs_review_count": 0,
            "mismatch_count": 0,
            "secret_count": 0,
            "dependency_finding_count": 0,
        },
    }
    (reports_dir / f"{slug}-scan-{generated_at.replace(':', '-')}.json").write_text(json.dumps(data))
    return data


def _write_log_line(logs_dir, slug, record_type, session_id="s1", **extra):
    logs_dir.mkdir(parents=True, exist_ok=True)
    path = logs_dir / f"{slug}-test.jsonl"
    record = {
        "schema_version": "mcp-ratchet-audit-log/1",
        "record_type": record_type,
        "session_id": session_id,
        "target_slug": slug,
        "sequence": 0,
        **extra,
    }
    with path.open("a") as f:
        f.write(json.dumps(record) + "\n")


def test_build_summaries_picks_latest_scan_per_slug(tmp_path):
    reports_dir = tmp_path / "reports"
    _write_scan(reports_dir, "toy", is_clean=True, generated_at="2026-08-20T00:00:00+00:00")
    _write_scan(reports_dir, "toy", is_clean=False, generated_at="2026-08-21T00:00:00+00:00")

    summaries = build_summaries(reports_dir, tmp_path / "logs")
    assert len(summaries) == 1
    assert summaries[0].latest_scan["generated_at"] == "2026-08-21T00:00:00+00:00"
    assert summaries[0].is_clean is False


def test_build_summaries_counts_calls_and_drift(tmp_path):
    reports_dir = tmp_path / "reports"
    logs_dir = tmp_path / "logs"
    _write_scan(reports_dir, "toy", is_clean=True)
    _write_log_line(logs_dir, "toy", "tool_call")
    _write_log_line(logs_dir, "toy", "tool_call")
    _write_log_line(logs_dir, "toy", "drift_event", drift_type="description_changed", tool_name="x", detail="d")

    summaries = build_summaries(reports_dir, logs_dir)
    summary = summaries[0]
    assert summary.call_count == 2
    assert summary.drift_event_count == 1
    assert summary.has_live_drift is True
    assert summary.is_clean is True  # scan itself is clean; drift is a separate signal


def test_build_summaries_handles_target_with_no_scan_yet(tmp_path):
    logs_dir = tmp_path / "logs"
    _write_log_line(logs_dir, "unscanned-target", "tool_call")

    summaries = build_summaries(tmp_path / "reports", logs_dir)
    assert len(summaries) == 1
    assert summaries[0].latest_scan is None
    assert summaries[0].is_clean is False


def test_render_dashboard_produces_real_numbers_not_placeholders(tmp_path):
    reports_dir = tmp_path / "reports"
    _write_scan(reports_dir, "clean-target", is_clean=True)
    _write_scan(reports_dir, "flagged-target", is_clean=False)

    summaries = build_summaries(reports_dir, tmp_path / "logs")
    html = render_dashboard(summaries)

    assert "clean-target" in html
    assert "flagged-target" in html
    assert ">2<" in html  # targets tracked count appears somewhere as real markup
    assert "{" not in html.split("<style>")[0]  # no unformatted f-string braces leaked into the head


def test_render_dashboard_empty_state_does_not_crash():
    html = render_dashboard([])
    assert "No targets scanned yet" in html
