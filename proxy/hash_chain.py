"""Shared hash-chain primitives, factored out of audit_log.py so a second
append-only log (proxy/policy.py's approval log) can get the exact same
tamper-evidence guarantee without duplicating the hashing logic.

Same bounded guarantee everywhere this is used: detects a file edited,
reordered, or truncated *after the fact* by anything other than the writer
that produced it. Does NOT protect against a compromised writer computing a
consistent fake chain from the start — that needs something outside the
file's own control (an external append-only store, a signing key the
writer process never has custody of). Named here once so every caller's
docstring can point back to this instead of re-deriving the caveat.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any

GENESIS_HASH = "0" * 64


def stable_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str)


def chain_hash(prev_hash: str, record_without_hash: dict) -> str:
    """The hash a record's own record_hash field must equal: a commitment
    to both this record's content and everything before it via prev_hash."""
    return hashlib.sha256((prev_hash + stable_json(record_without_hash)).encode("utf-8")).hexdigest()


@dataclass
class ChainVerificationResult:
    ok: bool
    records_checked: int
    # 0-based line index of the first record whose hash doesn't match, or
    # that's missing chain fields entirely — None when ok is True.
    broken_at_line: int | None
    detail: str


def verify_chain_lines(lines: list[str]) -> ChainVerificationResult:
    """Recompute a hash chain over a sequence of JSONL lines from genesis
    and confirm every record_hash matches. Format-agnostic: works for any
    JSONL log whose writer follows the prev_record_hash/record_hash
    convention (currently: proxy/audit_log.py's session logs and
    proxy/policy.py's approval logs) — the caller supplies the lines and
    owns what "a record" means for its own log.
    """
    prev_hash = GENESIS_HASH
    checked = 0

    for i, line in enumerate(lines):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            return ChainVerificationResult(
                ok=False, records_checked=checked, broken_at_line=i,
                detail=f"Line {i} is not valid JSON: {exc}",
            )

        claimed_hash = record.get("record_hash")
        claimed_prev = record.get("prev_record_hash")
        if claimed_hash is None or claimed_prev is None:
            return ChainVerificationResult(
                ok=False, records_checked=checked, broken_at_line=i,
                detail=f"Line {i} is missing prev_record_hash/record_hash — not written by a chain-aware writer.",
            )
        if claimed_prev != prev_hash:
            return ChainVerificationResult(
                ok=False, records_checked=checked, broken_at_line=i,
                detail=(
                    f"Line {i}'s prev_record_hash ({claimed_prev[:12]}...) doesn't match the "
                    f"previous record's actual hash ({prev_hash[:12]}...) — a line was edited, "
                    "reordered, or deleted somewhere before this point."
                ),
            )

        record_without_hash = {k: v for k, v in record.items() if k != "record_hash"}
        recomputed = chain_hash(prev_hash, record_without_hash)
        if recomputed != claimed_hash:
            return ChainVerificationResult(
                ok=False, records_checked=checked, broken_at_line=i,
                detail=f"Line {i}'s content doesn't match its own claimed record_hash — this line was edited in place.",
            )

        prev_hash = claimed_hash
        checked += 1

    return ChainVerificationResult(
        ok=True, records_checked=checked, broken_at_line=None,
        detail=f"All {checked} record(s) verified — chain intact from genesis.",
    )
