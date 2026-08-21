"""Tests for the proxy.verify_log CLI entrypoint — the actual way a human
would use audit_log.verify_chain, not just the library function directly.
"""

from __future__ import annotations

import json

from proxy.audit_log import AuditLogWriter
from proxy.verify_log import main


def test_cli_exits_zero_on_a_clean_log(tmp_path, capsys):
    with AuditLogWriter(tmp_path, "cli-test") as log:
        log.tool_call("get_weather", {"city": "Boston"}, "success", {"temp": 72}, 12.5)

    exit_code = main([str(log.path)])
    assert exit_code == 0
    out = capsys.readouterr().out
    assert "verified" in out
    assert "chain intact" in out


def test_cli_exits_nonzero_on_a_tampered_log(tmp_path, capsys):
    with AuditLogWriter(tmp_path, "cli-test") as log:
        log.tool_call("get_weather", {"city": "Boston"}, "success", {"temp": 72}, 12.5)

    lines = log.path.read_text(encoding="utf-8").splitlines()
    record = json.loads(lines[0])
    record["record_type"] = "TAMPERED"
    lines[0] = json.dumps(record)
    log.path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    exit_code = main([str(log.path)])
    assert exit_code == 1
    captured = capsys.readouterr()
    assert "First problem at line 0" in captured.err


def test_cli_exits_nonzero_on_a_missing_file(tmp_path, capsys):
    missing = tmp_path / "does-not-exist.jsonl"
    exit_code = main([str(missing)])
    assert exit_code == 1
    assert "No such file" in capsys.readouterr().err
