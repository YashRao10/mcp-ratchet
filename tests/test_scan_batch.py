"""Tests for scanner/scan_batch.py — real, multi-target scans in one run.

Follows the same real-connection convention as test_scan_integration.py:
this proves the batch path against actual live stdio connections to the
toy fixture, not hand-built ScanResult objects.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from scanner.scan_batch import TargetConfig, load_targets, scan_all, write_batch_summary

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"
TOY_SERVER = FIXTURES_DIR / "toy_server.py"


def _write_config(tmp_path: Path, targets: list[dict]) -> Path:
    config_path = tmp_path / "targets.json"
    config_path.write_text(json.dumps({"targets": targets}), encoding="utf-8")
    return config_path


def test_load_targets_parses_a_valid_config(tmp_path):
    config_path = _write_config(
        tmp_path,
        [
            {"slug": "a", "command": ["python", str(TOY_SERVER)]},
            {"slug": "b", "url": "https://example.com/mcp", "bearer_token_env": "SOME_TOKEN"},
        ],
    )
    targets = load_targets(config_path)
    assert len(targets) == 2
    assert targets[0] == TargetConfig(slug="a", command=["python", str(TOY_SERVER)])
    assert targets[1].url == "https://example.com/mcp"
    assert targets[1].bearer_token_env == "SOME_TOKEN"


def test_load_targets_rejects_empty_targets_list(tmp_path):
    config_path = _write_config(tmp_path, [])
    with pytest.raises(ValueError, match="no non-empty"):
        load_targets(config_path)


def test_load_targets_rejects_missing_slug(tmp_path):
    config_path = _write_config(tmp_path, [{"command": ["python", "x.py"]}])
    with pytest.raises(ValueError, match="missing required field 'slug'"):
        load_targets(config_path)


def test_load_targets_rejects_duplicate_slugs(tmp_path):
    config_path = _write_config(
        tmp_path,
        [
            {"slug": "dup", "command": ["python", "x.py"]},
            {"slug": "dup", "command": ["python", "y.py"]},
        ],
    )
    with pytest.raises(ValueError, match="Duplicate slug 'dup'"):
        load_targets(config_path)


def test_load_targets_rejects_neither_command_nor_url(tmp_path):
    config_path = _write_config(tmp_path, [{"slug": "bad"}])
    with pytest.raises(ValueError, match="exactly one of 'command' or 'url'"):
        load_targets(config_path)


def test_load_targets_rejects_both_command_and_url(tmp_path):
    config_path = _write_config(
        tmp_path, [{"slug": "bad", "command": ["python", "x.py"], "url": "https://example.com"}]
    )
    with pytest.raises(ValueError, match="exactly one of 'command' or 'url'"):
        load_targets(config_path)


async def test_scan_all_connects_to_two_real_toy_targets():
    targets = [
        TargetConfig(slug="toy-batch-a", command=["python", str(TOY_SERVER)], skip_injection_check=True),
        TargetConfig(slug="toy-batch-b", command=["python", str(TOY_SERVER)], skip_injection_check=True),
    ]
    results = await scan_all(targets)
    assert [r.target_slug for r in results] == ["toy-batch-a", "toy-batch-b"]
    assert all(r.connect_ok for r in results)
    assert all(r.fingerprint.tool_count == 4 for r in results)


async def test_scan_all_continues_past_a_broken_target():
    """The core claim of batch scanning: one bad target's launch command
    failing must not prevent the rest of the batch from running."""
    targets = [
        TargetConfig(slug="broken", command=["python", "no_such_file_anywhere.py"], skip_injection_check=True),
        TargetConfig(slug="toy-still-works", command=["python", str(TOY_SERVER)], skip_injection_check=True),
    ]
    results = await scan_all(targets)
    assert len(results) == 2

    broken_result = next(r for r in results if r.target_slug == "broken")
    assert broken_result.connect_ok is False
    assert broken_result.connect_error is not None

    working_result = next(r for r in results if r.target_slug == "toy-still-works")
    assert working_result.connect_ok is True
    assert working_result.fingerprint.tool_count == 4


async def test_scan_all_reports_a_missing_bearer_token_env_without_raising():
    targets = [
        TargetConfig(slug="needs-token", url="https://example.com/mcp", bearer_token_env="DEFINITELY_NOT_SET_ENV_VAR"),
    ]
    results = await scan_all(targets)
    assert len(results) == 1
    assert results[0].connect_ok is False
    assert "DEFINITELY_NOT_SET_ENV_VAR" in results[0].connect_error


def test_write_batch_summary_aggregates_correctly(tmp_path):
    from scanner.report import ScanResult, REPORT_SCHEMA_VERSION
    from scanner.fingerprint import ServerFingerprint

    clean_fp = ServerFingerprint(
        fingerprint_schema_version=1, target_slug="clean-one", generated_at="2026-01-01T00:00:00Z",
        tool_count=2, whole_server_hash="abc",
    )
    results = [
        ScanResult(
            report_schema_version=REPORT_SCHEMA_VERSION, target_slug="clean-one", target_command="python x.py",
            generated_at="2026-01-01T00:00:00Z", connect_ok=True, connect_error=None,
            server_name="clean-one", server_version="1.0", fingerprint=clean_fp,
        ),
        ScanResult(
            report_schema_version=REPORT_SCHEMA_VERSION, target_slug="broken-one", target_command="python y.py",
            generated_at="2026-01-01T00:00:00Z", connect_ok=False, connect_error="boom",
            server_name=None, server_version=None, fingerprint=None,
        ),
    ]
    out_path = tmp_path / "batch-summary.json"
    write_batch_summary(results, out_path)

    summary = json.loads(out_path.read_text(encoding="utf-8"))
    assert summary["target_count"] == 2
    assert summary["connected_count"] == 1
    assert summary["clean_count"] == 1
    slugs = {t["slug"]: t for t in summary["targets"]}
    assert slugs["clean-one"]["is_clean"] is True
    assert slugs["broken-one"]["connect_ok"] is False
    assert slugs["broken-one"]["is_clean"] is None
