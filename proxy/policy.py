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
existing baselines/<slug>.json convention — is_approved() reads this
snapshot, and it's what --block-on-drift actually checks against at proxy
startup. Approving a drift event does not remove or alter the original
drift_event record already written to the audit log by
AuditLogWriter.drift_event() — that record is permanent; this store only
changes whether a future call to the affected tool is refused under
--block-on-drift.

Alongside that snapshot, every approval is also appended to
policy/<slug>.jsonl — a hash-chained, append-only record of approval
decisions, using the same prev_record_hash/record_hash convention as
proxy/audit_log.py (see proxy/hash_chain.py, factored out of that module so
both logs share one hashing implementation instead of two). This closes the
gap the README used to call out here: editing, reordering, or truncating a
past line in that file now breaks the chain for every line after it,
detectable via verify_policy_chain()/`python -m proxy.verify_policy_log`
with no input but the file itself. Same bounded guarantee as the audit
log, not a stronger one: it catches a policy/<slug>.jsonl edited *after
the fact* by something other than this module's own append path. It does
NOT prove the *.json snapshot itself hasn't been hand-edited to disagree
with the chain — the snapshot is still a plain overwritten JSON file for
fast lookups, not a chain. A human auditing this target's trust decisions
should treat policy/<slug>.jsonl (verified) as the source of truth and the
.json snapshot as a cache of it; rebuild_snapshot_from_chain() below exists
for exactly that reconciliation.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from proxy.drift import DriftEvent
from proxy.hash_chain import ChainVerificationResult, GENESIS_HASH, chain_hash, verify_chain_lines

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


def approval_log_path(repo_root: Path, target_slug: str) -> Path:
    return repo_root / "policy" / f"{target_slug}.jsonl"


def _last_record_hash(path: Path) -> str:
    """The prev_record_hash the next appended record must chain from:
    GENESIS_HASH for a file that doesn't exist yet or is empty, otherwise
    the record_hash of the last non-blank line. Reads the whole file —
    fine here since an approval log grows by one line per human review
    decision, nothing like audit_log.py's per-tool-call volume."""
    if not path.exists():
        return GENESIS_HASH
    lines = [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    if not lines:
        return GENESIS_HASH
    return json.loads(lines[-1])["record_hash"]


def append_approval_record(repo_root: Path, target_slug: str, entry: ApprovedDrift) -> Path:
    """Append one hash-chained record of this approval decision to
    policy/<slug>.jsonl, chaining from whatever record_hash currently ends
    that file (or GENESIS_HASH for the first record). Call this alongside
    PolicyStore.save() — this function only appends the durable log entry,
    it does not touch the .json snapshot; the two are meant to be updated
    together (see approve_drift.py's CLI for the paired call site).

    Unlike the .json snapshot (one entry per tool_name+baseline+current
    triple, later approvals of the same key replacing earlier ones), this
    log is genuinely append-only: re-approving the same transition again
    (e.g. with a different --note) still writes a second record here,
    because the point of this file is "what did a human actually decide,
    and when" — a full history, not just current state.
    """
    path = approval_log_path(repo_root, target_slug)
    path.parent.mkdir(parents=True, exist_ok=True)
    prev_hash = _last_record_hash(path)

    record = {
        "schema_version": "mcp-ratchet-policy-log/1",
        "timestamp": entry.approved_at,
        "target_slug": target_slug,
        "record_type": "approval",
        **entry.to_dict(),
    }
    record["prev_record_hash"] = prev_hash
    record["record_hash"] = chain_hash(prev_hash, record)

    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str) + "\n")
    return path


def verify_policy_chain(path: Path) -> ChainVerificationResult:
    """Verify policy/<slug>.jsonl's hash chain from genesis — same bounded
    guarantee as proxy/audit_log.py's verify_chain (see proxy/hash_chain.py
    module docstring): catches this file being edited, reordered, or
    truncated after the fact, not a compromised writer faking a consistent
    chain from the start."""
    lines = path.read_text(encoding="utf-8").splitlines()
    return verify_chain_lines(lines)


def rebuild_snapshot_from_chain(repo_root: Path, target_slug: str) -> PolicyStore:
    """Reconstruct a PolicyStore purely from policy/<slug>.jsonl's verified
    history, ignoring whatever policy/<slug>.json currently says. Use this
    to check the .json snapshot hasn't drifted from (or been hand-edited
    against) the chain it's supposed to summarize — compare this result's
    to_dict() against load_policy()'s. Does NOT call verify_policy_chain()
    itself; callers that care whether the chain is intact (not just what
    it currently implies) should verify first and treat an unverified
    chain's rebuild as untrustworthy.
    """
    store = PolicyStore(target_slug=target_slug)
    path = approval_log_path(repo_root, target_slug)
    if not path.exists():
        return store
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        record = json.loads(line)
        entry = ApprovedDrift.from_dict(record)
        store.approved = [a for a in store.approved if a.key() != entry.key()] + [entry]
    return store
