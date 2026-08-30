"""TOR-8 and TOR-11 report markers.

TOR-8 — a target whose drift was not evaluated (no baseline, or an
unusable baseline) must not render as clean: the dashboard, the detail
page, and the machine-readable drift-summary.json all say so explicitly.

TOR-11 — the prompt-injection check carries a visible "not a qualified
result" marker everywhere it appears, and the scan JSON marks it
not_qualified.
"""

from __future__ import annotations

import json

from reporting.audit_summary import build_summaries
from reporting.dashboard import build_and_write, render_dashboard
from reporting.target_detail import render_target_detail
from scanner.checks.prompt_injection import InjectionVerdict
from scanner.report import ScanResult, now_iso, render_html


def _write_scan(reports_dir, slug, is_clean=True, generated_at="2026-08-29T00:00:00+00:00"):
    reports_dir.mkdir(parents=True, exist_ok=True)
    data = {
        "target_slug": slug,
        "generated_at": generated_at,
        "server_name": f"{slug}-server",
        "fingerprint": {"tool_count": 3},
        "summary": {
            "is_clean": is_clean,
            "suspicious_tool_count": 0,
            "needs_review_count": 0,
            "mismatch_count": 0,
            "secret_count": 0,
            "dependency_finding_count": 0,
        },
    }
    (reports_dir / f"{slug}-scan-{generated_at.replace(':', '-')}.json").write_text(json.dumps(data))


def _write_records(logs_dir, slug, records, fname="log-test.jsonl"):
    logs_dir.mkdir(parents=True, exist_ok=True)
    path = logs_dir / f"{slug}-{fname}"
    with path.open("w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps({"target_slug": slug, **r}) + "\n")


# ---- TOR-8 -----------------------------------------------------------------


def test_no_baseline_session_is_not_clean(tmp_path):
    reports_dir, logs_dir = tmp_path / "reports", tmp_path / "logs"
    _write_scan(reports_dir, "toy", is_clean=True)
    _write_records(logs_dir, "toy", [
        {"record_type": "session_start", "session_id": "s1"},
        {"record_type": "error", "error_type": "no_baseline", "error_message": "no baseline", "session_id": "s1"},
        {"record_type": "tool_call", "session_id": "s1"},
    ])
    summary = build_summaries(reports_dir, logs_dir)[0]
    assert summary.drift_status == "no_baseline"
    assert summary.drift_evaluation == "not_performed"
    assert summary.drift_not_evaluated is True
    assert summary.is_clean is False  # scan is clean, but drift was never checked


def test_baseline_error_session_is_not_clean(tmp_path):
    reports_dir, logs_dir = tmp_path / "reports", tmp_path / "logs"
    _write_scan(reports_dir, "toy", is_clean=True)
    _write_records(logs_dir, "toy", [
        {"record_type": "error", "error_type": "baseline_error",
         "error_message": "unparseable: boom", "session_id": "s1"},
    ])
    summary = build_summaries(reports_dir, logs_dir)[0]
    assert summary.drift_status == "baseline_error"
    assert summary.drift_evaluation == "not_performed"
    assert summary.is_clean is False


def test_latest_session_wins_over_an_earlier_no_baseline_gap(tmp_path):
    reports_dir, logs_dir = tmp_path / "reports", tmp_path / "logs"
    _write_scan(reports_dir, "toy", is_clean=True)
    # s1: ran with no baseline. s2 (later file): baseline present, diff ran clean.
    _write_records(logs_dir, "toy", [
        {"record_type": "error", "error_type": "no_baseline", "error_message": "x", "session_id": "s1"},
    ], fname="a.jsonl")
    _write_records(logs_dir, "toy", [
        {"record_type": "tools_list_snapshot", "session_id": "s2", "tool_count": 3},
    ], fname="b.jsonl")
    summary = build_summaries(reports_dir, logs_dir)[0]
    assert summary.drift_status == "evaluated"
    assert summary.no_baseline_session_count == 1  # history still counted
    assert summary.is_clean is True


def test_dashboard_and_machine_readable_flag_not_evaluated(tmp_path):
    reports_dir, logs_dir = tmp_path / "reports", tmp_path / "logs"
    _write_scan(reports_dir, "toy", is_clean=True)
    _write_records(logs_dir, "toy", [
        {"record_type": "error", "error_type": "no_baseline", "error_message": "x", "session_id": "s1"},
    ])
    out = build_and_write(reports_dir, logs_dir, tmp_path / "site" / "index.html")

    html = out.read_text(encoding="utf-8")
    assert "DRIFT NOT EVALUATED" in html
    assert "drift not evaluated" in html  # the status pill

    drift_summary = json.loads((out.parent / "drift-summary.json").read_text(encoding="utf-8"))
    target = drift_summary["targets"][0]
    assert target["slug"] == "toy"
    assert target["drift_evaluation"] == "not_performed"
    assert target["drift_status"] == "no_baseline"


def test_evaluated_target_reports_performed(tmp_path):
    reports_dir, logs_dir = tmp_path / "reports", tmp_path / "logs"
    _write_scan(reports_dir, "toy", is_clean=True)
    _write_records(logs_dir, "toy", [
        {"record_type": "tools_list_snapshot", "session_id": "s1", "tool_count": 3},
    ])
    out = build_and_write(reports_dir, logs_dir, tmp_path / "site" / "index.html")
    drift_summary = json.loads((out.parent / "drift-summary.json").read_text(encoding="utf-8"))
    assert drift_summary["targets"][0]["drift_evaluation"] == "performed"
    assert "DRIFT NOT EVALUATED" not in out.read_text(encoding="utf-8")


# ---- TOR-11 ---------------------------------------------------------------


def test_scan_report_marks_injection_check_not_qualified():
    result = ScanResult(
        report_schema_version=1,
        target_slug="toy",
        target_command="python toy.py",
        generated_at=now_iso(),
        connect_ok=True,
        connect_error=None,
        server_name="toy",
        server_version="1.0",
        fingerprint=None,
        injection_verdicts=[
            InjectionVerdict(tool_name="get_weather", suspicious=False, needs_review=False,
                             confidence="high", reasoning="benign"),
        ],
    )
    d = result.to_dict()
    assert d["injection_check"]["qualification_status"] == "not_qualified"

    html = render_html(result)
    assert "not a qualified result" in html.lower()
    assert "no compliance credit" in html.lower()


def test_dashboard_and_detail_carry_not_qualified_marker(tmp_path):
    reports_dir, logs_dir = tmp_path / "reports", tmp_path / "logs"
    _write_scan(reports_dir, "toy", is_clean=True)
    summaries = build_summaries(reports_dir, logs_dir)

    assert "NOT A QUALIFIED RESULT" in render_dashboard(summaries)
    assert "not a qualified result" in render_target_detail(summaries[0]).lower()
