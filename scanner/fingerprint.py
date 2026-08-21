"""Canonical fingerprinting of an MCP server's tool surface.

This is the one module Phase 2's drift detection depends on being correct —
a baseline written here has to hash identically to a live re-fingerprint of
the same unchanged server later, across process restarts, dict-ordering
differences, and whitespace noise a human wouldn't consider a real change.
Get the canonicalization right once, here, rather than half-reimplementing
it in proxy/drift.py later.

Deliberately naive about what counts as "changed": this hashes the tool's
declared shape (name, title, description, schemas, annotations, icons,
meta), not its runtime behavior. A purely cosmetic whitespace-only edit to
a description still changes the hash — that's a documented, accepted
trade-off (see README's "read this before trusting a report" section), not
an oversight.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

FINGERPRINT_SCHEMA_VERSION = 1

# Fields pulled off each mcp.Tool that participate in the hash. Deliberately
# excludes anything session/runtime-specific (there isn't any on Tool as of
# SDK 2.0.0 — every field is static metadata) so the whole object is in
# scope except None-valued optional fields, which are dropped rather than
# hashed as null vs. omitted (a server that starts declaring an empty
# optional field shouldn't register as a false-positive change).
_TOOL_FIELDS = (
    "name",
    "title",
    "description",
    "input_schema",
    "output_schema",
    "annotations",
    "icons",
    "meta",
)


def _canonicalize(value: Any) -> Any:
    """Recursively normalize a value for stable, order-independent hashing.

    dict keys get sorted; this is applied before json.dumps rather than
    relying on sort_keys=True alone, since sort_keys only sorts one level's
    worth of dict output ordering — nested dicts still need this to be
    fully order-independent in a way that's easy to reason about.
    """
    if isinstance(value, dict):
        return {k: _canonicalize(value[k]) for k in sorted(value.keys())}
    if isinstance(value, (list, tuple)):
        return [_canonicalize(v) for v in value]
    return value


def _tool_to_canonical_dict(tool: Any) -> dict:
    """Pull the hash-relevant fields off an mcp.Tool into a plain dict.

    Works against both the real mcp.Tool pydantic model (via
    model_dump(by_alias=False)) and a plain dict (used by tests/fixtures
    that don't want a full mcp.Tool instance) so fingerprint.py has exactly
    one code path regardless of caller.
    """
    if hasattr(tool, "model_dump"):
        raw = tool.model_dump(mode="json", exclude_none=True)
    elif isinstance(tool, dict):
        raw = {k: v for k, v in tool.items() if v is not None}
    else:
        raise TypeError(f"Cannot fingerprint tool of type {type(tool)!r}")

    picked = {field: raw[field] for field in _TOOL_FIELDS if field in raw}
    return _canonicalize(picked)


def _stable_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def normalize_whitespace(value: Any) -> Any:
    """Recursively collapse whitespace runs and strip string values, for
    comparison purposes only — never used to compute the actual fingerprint
    hash. A whitespace-only edit to a tool's description still changes
    whole_server_hash and still trips drift detection; that's a deliberate
    trade-off (see module docstring). This helper exists so drift.py can
    additionally label a hash-changing edit as whitespace-only, giving a
    human (or the dashboard) a way to deprioritize a purely cosmetic diff
    without the underlying ratchet ever missing it.
    """
    if isinstance(value, str):
        return " ".join(value.split())
    if isinstance(value, dict):
        return {k: normalize_whitespace(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [normalize_whitespace(v) for v in value]
    return value


def hash_tool(tool: Any) -> str:
    """SHA-256 of one tool's canonical shape, as a hex digest."""
    canonical = _tool_to_canonical_dict(tool)
    return hashlib.sha256(_stable_json(canonical).encode("utf-8")).hexdigest()


@dataclass
class ServerFingerprint:
    fingerprint_schema_version: int
    target_slug: str
    generated_at: str
    tool_count: int
    whole_server_hash: str
    per_tool_hashes: dict[str, str] = field(default_factory=dict)
    # Full canonical shape per tool, kept alongside the hash so drift
    # detection can report *what* changed, not just *that* something did.
    per_tool_canonical: dict[str, dict] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "fingerprint_schema_version": self.fingerprint_schema_version,
            "target_slug": self.target_slug,
            "generated_at": self.generated_at,
            "tool_count": self.tool_count,
            "whole_server_hash": self.whole_server_hash,
            "per_tool_hashes": self.per_tool_hashes,
            "per_tool_canonical": self.per_tool_canonical,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "ServerFingerprint":
        return cls(
            fingerprint_schema_version=data["fingerprint_schema_version"],
            target_slug=data["target_slug"],
            generated_at=data["generated_at"],
            tool_count=data["tool_count"],
            whole_server_hash=data["whole_server_hash"],
            per_tool_hashes=data.get("per_tool_hashes", {}),
            per_tool_canonical=data.get("per_tool_canonical", {}),
        )


def fingerprint_tools(tools: list, target_slug: str) -> ServerFingerprint:
    """Build a ServerFingerprint from a list of mcp.Tool (or dict) objects.

    Whole-server hash is computed over the sorted-by-name list of per-tool
    canonical dicts, NOT over the per-tool hashes themselves — hashing the
    hashes would make the whole-server hash undebuggable (you'd have no way
    to recover which tool's change caused it without also storing the
    per-tool hashes, which we do anyway, so hash the real content).
    """
    per_tool_hashes: dict[str, str] = {}
    per_tool_canonical: dict[str, dict] = {}

    for tool in tools:
        canonical = _tool_to_canonical_dict(tool)
        name = canonical.get("name")
        if not name:
            raise ValueError("Tool has no 'name' field — cannot fingerprint")
        per_tool_hashes[name] = hashlib.sha256(
            _stable_json(canonical).encode("utf-8")
        ).hexdigest()
        per_tool_canonical[name] = canonical

    ordered_canonicals = [per_tool_canonical[name] for name in sorted(per_tool_canonical)]
    whole_server_hash = hashlib.sha256(
        _stable_json(ordered_canonicals).encode("utf-8")
    ).hexdigest()

    return ServerFingerprint(
        fingerprint_schema_version=FINGERPRINT_SCHEMA_VERSION,
        target_slug=target_slug,
        generated_at=datetime.now(timezone.utc).isoformat(),
        tool_count=len(tools),
        whole_server_hash=whole_server_hash,
        per_tool_hashes=per_tool_hashes,
        per_tool_canonical=per_tool_canonical,
    )
