"""TOR-9 — a baseline file that exists but is unreadable, unparseable,
missing a required field, or declares an unsupported
fingerprint_schema_version must not crash the proxy and must never be
read as "no drift".

Covers proxy.run_proxy.load_baseline's classification and
proxy.server_side.build_proxy_server's fail-safe handling of the
resulting BaselineError.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from proxy.audit_log import AuditLogWriter
from proxy.client_side import DownstreamClient
from proxy import run_proxy
from proxy.server_side import build_proxy_server
from scanner.connect import TargetSpec, enumerate_target
from scanner.fingerprint import (
    FINGERPRINT_SCHEMA_VERSION,
    BaselineError,
    ServerFingerprint,
    fingerprint_tools,
)

ORIGINAL_TOY_SERVER = Path(__file__).resolve().parent / "fixtures" / "toy_server.py"


def _write_baseline(tmp_path: Path, slug: str, text: str, monkeypatch) -> Path:
    """Point load_baseline's REPO_ROOT at tmp_path and drop a baselines/<slug>.json there."""
    baselines_dir = tmp_path / "baselines"
    baselines_dir.mkdir(parents=True, exist_ok=True)
    path = baselines_dir / f"{slug}.json"
    path.write_text(text, encoding="utf-8")
    monkeypatch.setattr(run_proxy, "REPO_ROOT", tmp_path)
    return path


def _valid_baseline_dict() -> dict:
    return {
        "fingerprint_schema_version": FINGERPRINT_SCHEMA_VERSION,
        "target_slug": "toy",
        "generated_at": "2026-08-29T00:00:00+00:00",
        "tool_count": 0,
        "whole_server_hash": "0" * 64,
        "per_tool_hashes": {},
        "per_tool_canonical": {},
    }


def test_missing_file_returns_none(tmp_path, monkeypatch):
    monkeypatch.setattr(run_proxy, "REPO_ROOT", tmp_path)
    assert run_proxy.load_baseline("never-scanned") is None


def test_valid_file_returns_fingerprint(tmp_path, monkeypatch):
    _write_baseline(tmp_path, "toy", json.dumps(_valid_baseline_dict()), monkeypatch)
    result = run_proxy.load_baseline("toy")
    assert isinstance(result, ServerFingerprint)


def test_unparseable_json_returns_baseline_error(tmp_path, monkeypatch):
    _write_baseline(tmp_path, "toy", "{not valid json", monkeypatch)
    result = run_proxy.load_baseline("toy")
    assert isinstance(result, BaselineError)
    assert result.reason == "unparseable"


def test_non_object_json_returns_baseline_error(tmp_path, monkeypatch):
    _write_baseline(tmp_path, "toy", "[1, 2, 3]", monkeypatch)
    result = run_proxy.load_baseline("toy")
    assert isinstance(result, BaselineError)
    assert result.reason == "unparseable"


def test_missing_required_field_returns_baseline_error(tmp_path, monkeypatch):
    data = _valid_baseline_dict()
    del data["whole_server_hash"]
    _write_baseline(tmp_path, "toy", json.dumps(data), monkeypatch)
    result = run_proxy.load_baseline("toy")
    assert isinstance(result, BaselineError)
    assert result.reason == "missing_field"


def test_missing_schema_version_returns_baseline_error(tmp_path, monkeypatch):
    data = _valid_baseline_dict()
    del data["fingerprint_schema_version"]
    _write_baseline(tmp_path, "toy", json.dumps(data), monkeypatch)
    result = run_proxy.load_baseline("toy")
    assert isinstance(result, BaselineError)
    assert result.reason == "missing_field"


def test_unsupported_schema_version_returns_baseline_error(tmp_path, monkeypatch):
    data = _valid_baseline_dict()
    data["fingerprint_schema_version"] = FINGERPRINT_SCHEMA_VERSION + 99
    _write_baseline(tmp_path, "toy", json.dumps(data), monkeypatch)
    result = run_proxy.load_baseline("toy")
    assert isinstance(result, BaselineError)
    assert result.reason == "schema_version_mismatch"


async def test_proxy_logs_baseline_error_and_never_claims_no_drift(tmp_path, monkeypatch):
    """A BaselineError baseline: on_list_tools must log a baseline_error
    record (not no_baseline, not a clean tools_list_snapshot with zero
    drift), forward the real result unmodified, and still forward tool
    calls (monitor mode) since nothing is known to have drifted."""
    audit_log = AuditLogWriter(tmp_path, "toy-baseline-err")
    baseline = BaselineError("unparseable", "boom", str(tmp_path / "baselines" / "toy.json"))
    target = TargetSpec(command="python", args=[str(ORIGINAL_TOY_SERVER)])

    async with DownstreamClient(target) as downstream:
        with audit_log:
            server = build_proxy_server(downstream, baseline, audit_log)
            list_handler = server.get_request_handler("tools/list").handler
            result = await list_handler(None, None)
            assert result.tools  # real surface forwarded unmodified

            call_handler = server.get_request_handler("tools/call").handler
            from mcp import types

            call_result = await call_handler(
                None, types.CallToolRequestParams(name="get_weather", arguments={"city": "Boston"})
            )
    assert getattr(call_result, "is_error", None) is not True

    log_file = next(tmp_path.glob("toy-baseline-err-*.jsonl"))
    records = [json.loads(line) for line in log_file.read_text(encoding="utf-8").splitlines()]

    errors = [r for r in records if r["record_type"] == "error"]
    assert any(r["error_type"] == "baseline_error" for r in errors)
    assert not any(r["error_type"] == "no_baseline" for r in errors)
    # Drift was never evaluated, so no drift_event and no tools_list_snapshot
    # claiming a clean diff should have been written.
    assert not [r for r in records if r["record_type"] == "drift_event"]
    assert not [r for r in records if r["record_type"] == "tools_list_snapshot"]
