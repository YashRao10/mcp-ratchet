import json

from reporting.audit_summary import build_summaries
from reporting.target_detail import build_and_write_all, render_target_detail


def _write_scan(reports_dir, slug, generated_at="2026-08-21T00:00:00+00:00", mismatch=None, secret=None, injection_verdicts=None):
    reports_dir.mkdir(parents=True, exist_ok=True)
    data = {
        "target_slug": slug,
        "target_command": f"python {slug}.py",
        "generated_at": generated_at,
        "server_name": f"{slug}-server",
        "fingerprint": {
            "tool_count": 2,
            "whole_server_hash": "abc123def456",
            "per_tool_hashes": {"read_thing": "aaaa1111", "write_thing": "bbbb2222"},
            "per_tool_canonical": {
                "read_thing": {"description": "Reads a thing."},
                "write_thing": {"description": "Writes a thing, deliberately."},
            },
        },
        "mismatch_findings": [mismatch] if mismatch else [],
        "secret_findings": [secret] if secret else [],
        "dependency_findings": [],
        "injection_verdicts": injection_verdicts or [],
        "summary": {
            "is_clean": not (mismatch or secret),
            "suspicious_tool_count": 0,
            "needs_review_count": 0,
            "mismatch_count": 1 if mismatch else 0,
            "secret_count": 1 if secret else 0,
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


def test_render_target_detail_lists_real_tools_and_hashes(tmp_path):
    reports_dir = tmp_path / "reports"
    _write_scan(reports_dir, "toy")
    summary = build_summaries(reports_dir, tmp_path / "logs")[0]

    html = render_target_detail(summary)

    assert "read_thing" in html
    assert "write_thing" in html
    assert "Reads a thing." in html
    assert "aaaa1111" in html
    assert "abc123def456" in html  # whole-server hash


def test_render_target_detail_shows_real_finding_fields_not_just_a_count(tmp_path):
    reports_dir = tmp_path / "reports"
    _write_scan(
        reports_dir,
        "flagged",
        mismatch={"tool_name": "get_status", "reason": "accepts a delete parameter despite read-like name"},
    )
    summary = build_summaries(reports_dir, tmp_path / "logs")[0]

    html = render_target_detail(summary)

    assert "get_status" in html
    assert "accepts a delete parameter despite read-like name" in html


def test_render_target_detail_shows_why_a_tool_needs_review_not_just_the_count(tmp_path):
    """Regression: the dashboard card shows a 'needs review' count, but
    until this test the detail page never rendered *why* — a viewer had
    to open the raw JSON report to learn a tool was needs_review because
    ANTHROPIC_API_KEY wasn't set, not because it was actually judged
    suspicious. Found 2026-08-26 while adding the reference-git/fetch/
    filesystem targets with no key configured."""
    reports_dir = tmp_path / "reports"
    _write_scan(
        reports_dir,
        "no-key",
        injection_verdicts=[
            {
                "tool_name": "git_status",
                "suspicious": None,
                "needs_review": True,
                "reasoning": "ANTHROPIC_API_KEY not set; prompt-injection check was not run.",
                "raw_error": "no_api_key",
            }
        ],
    )
    summary = build_summaries(reports_dir, tmp_path / "logs")[0]

    html = render_target_detail(summary)

    assert "git_status" in html
    assert "ANTHROPIC_API_KEY not set" in html


def test_render_target_detail_hides_clean_injection_verdicts(tmp_path):
    """A tool that was actually judged and came back clean shouldn't
    clutter this list — only suspicious or needs_review verdicts belong
    here, same convention as the other three finding lists."""
    reports_dir = tmp_path / "reports"
    _write_scan(
        reports_dir,
        "checked-clean",
        injection_verdicts=[
            {
                "tool_name": "git_status",
                "suspicious": False,
                "needs_review": False,
                "reasoning": "Tool description is a plain, literal statement of its function.",
            }
        ],
    )
    summary = build_summaries(reports_dir, tmp_path / "logs")[0]

    html = render_target_detail(summary)

    assert "No tools flagged." in html
    assert "plain, literal statement" not in html


def test_render_target_detail_empty_states_do_not_crash():
    from reporting.audit_summary import TargetSummary

    html = render_target_detail(TargetSummary(slug="unscanned"))

    assert "unscanned" in html
    assert "No permission mismatches." in html
    assert "No drift events logged for this target." in html


def test_render_target_detail_back_link_matches_the_deployed_filename():
    """Regression test: the deploy workflow copies reports/dashboard.html
    to _site/index.html (see .github/workflows/deploy.yml), so a target
    detail page's "back to dashboard" link pointing at "dashboard.html"
    404s on the live site even though it resolves fine locally, since
    that file never exists in _site/ under its dev-time name. Caught live
    2026-08-26 by the user clicking the link on the deployed dashboard —
    no test had asserted this href before."""
    from reporting.audit_summary import TargetSummary

    html = render_target_detail(TargetSummary(slug="unscanned"))

    assert 'href="index.html"' in html
    assert 'href="dashboard.html"' not in html


def test_render_target_detail_shows_full_drift_history_not_just_recent_ten(tmp_path):
    reports_dir = tmp_path / "reports"
    logs_dir = tmp_path / "logs"
    _write_scan(reports_dir, "toy")
    for i in range(12):
        _write_log_line(
            logs_dir,
            "toy",
            "drift_event",
            drift_type="description_changed",
            tool_name=f"tool_{i}",
            detail=f"change #{i}",
            timestamp=f"2026-08-2{i % 9}T00:00:00Z",
        )

    summary = build_summaries(reports_dir, logs_dir)[0]
    assert len(summary.recent_drift_events) == 10  # unchanged existing behavior for the card
    assert len(summary.all_drift_events) == 12  # new: detail page gets everything

    html = render_target_detail(summary)
    assert "tool_0" in html  # would be missing if this page only used the last-10 slice
    assert "tool_11" in html


def test_render_target_detail_shows_full_blocked_call_history_not_just_recent_ten(tmp_path):
    reports_dir = tmp_path / "reports"
    logs_dir = tmp_path / "logs"
    _write_scan(reports_dir, "toy")
    for i in range(12):
        _write_log_line(
            logs_dir,
            "toy",
            "blocked_call",
            tool_name=f"tool_{i}",
            detail=f"refused #{i}",
            timestamp=f"2026-08-2{i % 9}T00:00:00Z",
        )

    summary = build_summaries(reports_dir, logs_dir)[0]
    assert len(summary.recent_blocked_calls) == 10  # card summary stays capped
    assert len(summary.all_blocked_calls) == 12  # detail page gets everything

    html = render_target_detail(summary)
    assert "tool_0" in html  # would be missing if this page only used the last-10 slice
    assert "tool_11" in html


def test_render_target_detail_no_blocked_calls_state_does_not_crash():
    from reporting.audit_summary import TargetSummary

    html = render_target_detail(TargetSummary(slug="unscanned"))
    assert "No calls blocked for this target" in html


def test_build_and_write_all_writes_one_file_per_target(tmp_path):
    reports_dir = tmp_path / "reports"
    _write_scan(reports_dir, "alpha")
    _write_scan(reports_dir, "beta")
    out_dir = tmp_path / "out"

    paths = build_and_write_all(reports_dir, tmp_path / "logs", out_dir)

    names = {p.name for p in paths}
    assert names == {"target-alpha.html", "target-beta.html"}
    for p in paths:
        assert p.exists()
        assert "mcp-ratchet" in p.read_text(encoding="utf-8")
