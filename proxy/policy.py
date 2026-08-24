"""Persistent allow-listing for reviewed drift events.

This is the piece `--block-on-drift` was missing at launch: every new proxy
session recomputes "currently believed drifted" from scratch against the
Phase 1 baseline (see proxy/server_side.py's build_proxy_server docstring),
with no memory of a prior human decision — so a change a human already
reviewed and accepted got re-blocked forever, every session, with no way to
say "I looked at this one, let it through."

An approval is scoped to the *exact* transition a human reviewed, not the
tool name: (tool_name, baseline_hash, current_hash). scanner/fingerprint.py's
hash is a whole-tool-shape hash, so any further edit to an already-approved
tool produces a new current_hash that doesn't match the approved entry — the
tool blocks again, on the next drift, exactly as this project's design
intends. Approving one specific diff is not a standing license for whatever
that tool's description says next; see proxy/drift.py's DriftEvent for why
baseline_hash/current_hash are the right identity, not the tool name alone.

Storage is a plain local JSON file at policy/<slug>.json, mirroring the
existing baselines/<slug>.json convention. Explicitly NOT hash-chained or
tamper-evident the way proxy/audit_log.py's log is: this file records a local
human trust decision made on this machine, not an append-only record of
proxy activity, and editing it by hand (or an attacker with local file
access editing it) leaves no trace. Extending audit_log.py's hash chain to
also cover approvals was considered and deliberately left out of scope here
— see README's "what this does NOT do" section for the explicit call-out.
Approving a drift event does not remove or alter the original drift_event
record already written to the audit log by AuditLogWriter.drift_event() —
that record is permanent; this store only changes whether a future call to
the affected tool is refused under --block-on-drift.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from proxy.drift import DriftEvent

POLICY_SCHEMA_VERSION = 1


@dataclass
class ApprovedDrift:
    tool_name: str
    drift_type: str
    baseline_hash: str | None
    current_hash: str | None
    approved_at: str
    approved_by: str | None = None
    note: str | None = None

    def key(self) -> tuple[str, str | None, str | None]:
        return (self.tool_name, self.baseline_hash, self.current_hash)

    def to_dict(self) -> dict:
        return {
            "tool_name": self.tool_name,
            "drift_type": self.drift_type,
            "baseline_hash": self.baseline_hash,
            "current_hash": self.current_hash,
            "approved_at": self.approved_at,
            "approved_by": self.approved_by,
            "note": self.note,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "ApprovedDrift":
        return cls(
            tool_name=data["tool_name"],
            drift_type=data["drift_type"],
            baseline_hash=data.get("baseline_hash"),
            current_hash=data.get("current_hash"),
            approved_at=data["approved_at"],
            approved_by=data.get("approved_by"),
            note=data.get("note"),
        )


def _event_key(event: DriftEvent) -> tuple[str, str | None, str | None]:
    return (event.tool_name, event.baseline_hash, event.current_hash)


@dataclass
class PolicyStore:
    target_slug: str
    approved: list[ApprovedDrift] = field(default_factory=list)

    def is_approved(self, event: DriftEvent) -> bool:
        """True only if this *exact* tool_name+baseline_hash+current_hash
        transition has been approved before. A further drift on top of an
        already-approved tool has a different current_hash and is therefore
        NOT approved by this check — see module docstring for why that's
        the deliberate behavior, not a gap."""
        target_key = _event_key(event)
        return any(entry.key() == target_key for entry in self.approved)

    def approve_event(
        self, event: DriftEvent, approved_by: str | None = None, note: str | None = None
    ) -> ApprovedDrift:
        """Record approval of one specific drift transition. Idempotent:
        re-approving the same exact transition replaces the earlier entry
        (refreshing approved_at/approved_by/note) rather than accumulating
        duplicates."""
        entry = ApprovedDrift(
            tool_name=event.tool_name,
            drift_type=event.drift_type,
            baseline_hash=event.baseline_hash,
            current_hash=event.current_hash,
            approved_at=datetime.now(timezone.utc).isoformat(),
            approved_by=approved_by,
            note=note,
        )
        self.approved = [a for a in self.approved if a.key() != entry.key()] + [entry]
        return entry

    def to_dict(self) -> dict:
        return {
            "policy_schema_version": POLICY_SCHEMA_VERSION,
            "target_slug": self.target_slug,
            "approved_drift": [a.to_dict() for a in self.approved],
        }

    @classmethod
    def from_dict(cls, data: dict) -> "PolicyStore":
        return cls(
            target_slug=data["target_slug"],
            approved=[ApprovedDrift.from_dict(a) for a in data.get("approved_drift", [])],
        )

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")


def policy_path(repo_root: Path, target_slug: str) -> Path:
    return repo_root / "policy" / f"{target_slug}.json"


def load_policy(repo_root: Path, target_slug: str) -> PolicyStore:
    """Load policy/<slug>.json, or return an empty, unsaved PolicyStore if
    it doesn't exist yet. No approvals on disk means every drift event still
    blocks under --block-on-drift — the same fail-safe-closed posture as
    before this feature existed; a missing policy file is never treated as
    "everything's approved.\""""
    path = policy_path(repo_root, target_slug)
    if not path.exists():
        return PolicyStore(target_slug=target_slug)
    data = json.loads(path.read_text(encoding="utf-8"))
    return PolicyStore.from_dict(data)
