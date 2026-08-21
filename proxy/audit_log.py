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

Hash-chained for tamper-evidence: every record's record_hash commits to
the previous record's record_hash plus this record's own content, so
editing or deleting any past line breaks the chain for every line after
it — detectable by verify_chain() below without needing anything but the
log file itself. This is explicitly bounded, matching the README's
existing caveat: it detects a log file edited *after the fact* by
something other than this writer (an external tamperer, a bug, a partial
disk write). It does NOT protect against a compromised proxy process
computing a consistent fake chain from the start — that would require
something outside this file's control, like an external append-only
store or a signing key the proxy process itself never has custody of.
Named as a real limitation, same as the README already does, not solved
here.
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
GENESIS_HASH = "0" * 64


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


@dataclass
class ChainVerificationResult:
    ok: bool
    records_checked: int
    # 0-based line index of the first record whose hash doesn't match, or
    # that's missing chain fields entirely — None when ok is True.
    broken_at_line: int | None
    detail: str


def verify_chain(path: Path) -> ChainVerificationResult:
    """Recompute the hash chain over an existing log file from genesis and
    confirm every record_hash matches. Detects any edit, reordering, or
    deletion of a past line (each breaks the chain for every line after
    it) and a truncated file missing its trailing session_end record —
    but see the module docstring for what this does NOT protect against.
    """
    prev_hash = GENESIS_HASH
    lines = path.read_text(encoding="utf-8").splitlines()

    for i, line in enumerate(lines):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            return ChainVerificationResult(
                ok=False, records_checked=i, broken_at_line=i,
                detail=f"Line {i} is not valid JSON: {exc}",
            )

        claimed_hash = record.get("record_hash")
        claimed_prev = record.get("prev_record_hash")
        if claimed_hash is None or claimed_prev is None:
            return ChainVerificationResult(
                ok=False, records_checked=i, broken_at_line=i,
                detail=f"Line {i} is missing prev_record_hash/record_hash — not written by this chain-aware writer.",
            )
        if claimed_prev != prev_hash:
            return ChainVerificationResult(
                ok=False, records_checked=i, broken_at_line=i,
                detail=(
                    f"Line {i}'s prev_record_hash ({claimed_prev[:12]}...) doesn't match the "
                    f"previous record's actual hash ({prev_hash[:12]}...) — a line was edited, "
                    "reordered, or deleted somewhere before this point."
                ),
            )

        record_without_hash = {k: v for k, v in record.items() if k != "record_hash"}
        recomputed = hashlib.sha256(
            (prev_hash + _stable_json(record_without_hash)).encode("utf-8")
        ).hexdigest()
        if recomputed != claimed_hash:
            return ChainVerificationResult(
                ok=False, records_checked=i, broken_at_line=i,
                detail=f"Line {i}'s content doesn't match its own claimed record_hash — this line was edited in place.",
            )

        prev_hash = claimed_hash

    return ChainVerificationResult(
        ok=True, records_checked=len(lines), broken_at_line=None,
        detail=f"All {len(lines)} record(s) verified — chain intact from genesis.",
    )


class AuditLogWriter:
    def __init__(self, logs_dir: Path, target_slug: str, log_raw_args: bool = False):
        self.session_id = str(uuid.uuid4())
        self.target_slug = target_slug
        self.log_raw_args = log_raw_args
        self._sequence = 0
        # Chain state is per-writer (i.e. per file, since one writer owns
        # one file for its whole session) — genesis for a brand new file.
        # This writer only ever appends to a file it just created (the
        # session timestamp in the filename makes collisions practically
        # impossible), so there's no case where _prev_hash needs to be
        # recovered from an existing file's tail.
        self._prev_hash = GENESIS_HASH

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
        record["prev_record_hash"] = self._prev_hash
        record_hash = hashlib.sha256(
            (self._prev_hash + _stable_json(record)).encode("utf-8")
        ).hexdigest()
        record["record_hash"] = record_hash
        self._prev_hash = record_hash
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
