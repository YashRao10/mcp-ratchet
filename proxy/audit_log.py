"""Writer for the mcp-ratchet-audit-log/1 JSONL format (see
schemas/audit_log_v1.schema.json — the schema file is the source of truth
for field shape; this module just knows how to produce conforming
records).

One AuditLogWriter per proxy session, appending to
logs/<target_slug>-<session_id>.jsonl. args are hashed, not stored raw, by
default — the point of args_shape_hash is that a real incident review can
still see "this tool was called with an argument shaped like X" without
this log itself becoming a second copy of every credential/payload that
ever flowed through the proxy.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "mcp-ratchet-audit-log/1"


def _stable_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str)


def hash_shape(value: Any) -> str:
    """Hash of a value's *shape* (keys + value types for a dict, else the
    type name), not its actual content — this is deliberately lossy."""
    if isinstance(value, dict):
        shape = {k: type(v).__name__ for k, v in sorted(value.items())}
    else:
        shape = {"_type": type(value).__name__}
    return hashlib.sha256(_stable_json(shape).encode("utf-8")).hexdigest()


class AuditLogWriter:
    def __init__(self, logs_dir: Path, target_slug: str, log_raw_args: bool = False):
        self.session_id = str(uuid.uuid4())
        self.target_slug = target_slug
        self.log_raw_args = log_raw_args
        self._sequence = 0

        logs_dir.mkdir(parents=True, exist_ok=True)
        session_ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        self.path = logs_dir / f"{target_slug}-{session_ts}.jsonl"
        self._fh = self.path.open("a", encoding="utf-8")

    def _write(self, record: dict) -> None:
        record = {
            "schema_version": SCHEMA_VERSION,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "session_id": self.session_id,
            "target_slug": self.target_slug,
            "sequence": self._sequence,
            **record,
        }
        self._sequence += 1
        self._fh.write(_stable_json(record) + "\n")
        self._fh.flush()

    def session_start(self) -> None:
        self._write({"record_type": "session_start"})

    def session_end(self) -> None:
        self._write({"record_type": "session_end"})

    def tool_call(
        self,
        tool_name: str,
        arguments: dict | None,
        result_status: str,
        result_shape: Any,
        duration_ms: float,
        anomaly_flags: list[str] | None = None,
    ) -> None:
        self._write(
            {
                "record_type": "tool_call",
                "tool_name": tool_name,
                "args_shape_hash": hash_shape(arguments or {}),
                "args_raw": arguments if self.log_raw_args else None,
                "result_status": result_status,
                "result_shape_hash": hash_shape(result_shape),
                "duration_ms": duration_ms,
                "anomaly_flags": anomaly_flags or [],
            }
        )

    def tools_list_snapshot(self, tool_count: int, whole_server_hash: str, per_tool_hashes: dict) -> None:
        self._write(
            {
                "record_type": "tools_list_snapshot",
                "tool_count": tool_count,
                "whole_server_hash": whole_server_hash,
                "per_tool_hashes": per_tool_hashes,
            }
        )

    def drift_event(self, event) -> None:
        """`event` is a proxy.drift.DriftEvent."""
        self._write({"record_type": "drift_event", **{k: v for k, v in event.to_dict().items() if k != "record_type"}})

    def error(self, error_type: str, error_message: str) -> None:
        self._write({"record_type": "error", "error_type": error_type, "error_message": error_message})

    def close(self) -> None:
        self._fh.close()

    def __enter__(self) -> "AuditLogWriter":
        self.session_start()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        if exc_type is not None:
            self.error(error_type=exc_type.__name__, error_message=str(exc))
        self.session_end()
        self.close()
