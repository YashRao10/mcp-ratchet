"""Diff a live tools/list response against a stored Phase 1 baseline and
classify what changed.

This is the single most load-bearing file for the project's actual claim
— every other check in this repo answers "is this server safe right now,"
this one answers "is this still the same server I approved." Reuses
scanner/fingerprint.py's exact canonicalization so a baseline written by
the static scanner and a live fingerprint computed here are guaranteed to
hash identically for an unchanged server (see tests/test_fingerprint.py's
determinism tests — this module's correctness depends on those holding).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from scanner.fingerprint import ServerFingerprint, fingerprint_tools, normalize_whitespace

DRIFT_TOOL_ADDED = "tool_added"
DRIFT_TOOL_REMOVED = "tool_removed"
DRIFT_DESCRIPTION_CHANGED = "description_changed"
DRIFT_SCHEMA_CHANGED = "schema_changed"
DRIFT_ANNOTATIONS_CHANGED = "annotations_changed"
DRIFT_OTHER_CHANGED = "other_changed"


@dataclass
class DriftEvent:
    drift_type: str
    tool_name: str
    baseline_hash: str | None
    current_hash: str | None
    detail: str
    # True only for a field-level change whose baseline and live values are
    # identical after whitespace normalization (see
    # scanner.fingerprint.normalize_whitespace) — e.g. a description that
    # only gained a trailing space. Always False for tool_added/tool_removed
    # and for any change where normalization doesn't erase the difference.
    # Purely informational: this flag never suppresses the event or changes
    # whether it fires — the exact-hash ratchet still catches it regardless.
    whitespace_only_change: bool = False

    def to_dict(self) -> dict:
        return {
            "record_type": "drift_event",
            "drift_type": self.drift_type,
            "tool_name": self.tool_name,
            "baseline_hash": self.baseline_hash,
            "current_hash": self.current_hash,
            "detail": self.detail,
            "whitespace_only_change": self.whitespace_only_change,
        }


def _classify_field_change(field_name: str) -> str:
    if field_name == "description" or field_name == "title":
        return DRIFT_DESCRIPTION_CHANGED
    if field_name in ("input_schema", "output_schema"):
        return DRIFT_SCHEMA_CHANGED
    if field_name == "annotations":
        return DRIFT_ANNOTATIONS_CHANGED
    return DRIFT_OTHER_CHANGED


def diff_against_baseline(
    live_tools: list, baseline: ServerFingerprint
) -> tuple[ServerFingerprint, list[DriftEvent]]:
    """Fingerprint `live_tools` fresh, diff against `baseline`, and return
    (live_fingerprint, drift_events). An empty drift_events list means the
    server's declared tool surface matches the baseline exactly.
    """
    live_fp = fingerprint_tools(live_tools, baseline.target_slug)
    events: list[DriftEvent] = []

    baseline_names = set(baseline.per_tool_hashes.keys())
    live_names = set(live_fp.per_tool_hashes.keys())

    for added_name in sorted(live_names - baseline_names):
        events.append(
            DriftEvent(
                drift_type=DRIFT_TOOL_ADDED,
                tool_name=added_name,
                baseline_hash=None,
                current_hash=live_fp.per_tool_hashes[added_name],
                detail=f"Tool '{added_name}' was not present in the baseline and now is.",
            )
        )

    for removed_name in sorted(baseline_names - live_names):
        events.append(
            DriftEvent(
                drift_type=DRIFT_TOOL_REMOVED,
                tool_name=removed_name,
                baseline_hash=baseline.per_tool_hashes[removed_name],
                current_hash=None,
                detail=f"Tool '{removed_name}' was in the baseline and is no longer present.",
            )
        )

    for shared_name in sorted(baseline_names & live_names):
        baseline_hash = baseline.per_tool_hashes[shared_name]
        current_hash = live_fp.per_tool_hashes[shared_name]
        if baseline_hash == current_hash:
            continue

        baseline_canonical = baseline.per_tool_canonical.get(shared_name, {})
        live_canonical = live_fp.per_tool_canonical.get(shared_name, {})
        changed_fields = sorted(
            {
                key
                for key in set(baseline_canonical.keys()) | set(live_canonical.keys())
                if baseline_canonical.get(key) != live_canonical.get(key)
            }
        )

        if not changed_fields:
            # Hash differs but no field-level diff found — shouldn't
            # happen given identical canonicalization, but report it as a
            # generic change rather than silently dropping a real drift
            # event if it ever does.
            events.append(
                DriftEvent(
                    drift_type=DRIFT_OTHER_CHANGED,
                    tool_name=shared_name,
                    baseline_hash=baseline_hash,
                    current_hash=current_hash,
                    detail="Hash changed but no field-level difference was detected.",
                )
            )
            continue

        for field_name in changed_fields:
            baseline_value = baseline_canonical.get(field_name)
            live_value = live_canonical.get(field_name)
            whitespace_only = normalize_whitespace(baseline_value) == normalize_whitespace(live_value)
            events.append(
                DriftEvent(
                    drift_type=_classify_field_change(field_name),
                    tool_name=shared_name,
                    baseline_hash=baseline_hash,
                    current_hash=current_hash,
                    detail=(
                        f"Field '{field_name}' changed from "
                        f"{baseline_value!r} to {live_value!r}."
                        + (" (whitespace-only)" if whitespace_only else "")
                    ),
                    whitespace_only_change=whitespace_only,
                )
            )

    return live_fp, events
