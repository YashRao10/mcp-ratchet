"""Scripted (non-LLM) check: does a tool's declared name/description imply
narrower scope than its input schema actually allows?

Deliberately NOT an LLM call — this is cheap, deterministic, and the rule
table is small enough to reason about directly. The prompt-injection check
handles the "is this text manipulative" question; this one handles a
different, complementary question: "does this schema let the tool do more
than its own name and description claim."
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# Verb prefixes in a tool's own name that imply a narrow, read-only or
# listing-only scope. Extendable, not exhaustive.
_NARROW_SCOPE_VERBS = ("get_", "list_", "read_", "fetch_", "find_", "search_", "view_")

# Schema property names that suggest the tool can do more than read —
# execute arbitrary commands, write/delete, or reach an arbitrary
# filesystem/network location beyond what a "read"-scoped tool needs.
_ESCALATING_PROPERTY_PATTERNS = (
    re.compile(r"^command$", re.IGNORECASE),
    re.compile(r"^cmd$", re.IGNORECASE),
    re.compile(r"^shell", re.IGNORECASE),
    re.compile(r"exec", re.IGNORECASE),
    re.compile(r"^script$", re.IGNORECASE),
    re.compile(r"delete", re.IGNORECASE),
    re.compile(r"^overwrite$", re.IGNORECASE),
)


@dataclass
class MismatchFinding:
    tool_name: str
    matched_verb_prefix: str
    escalating_properties: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "tool_name": self.tool_name,
            "matched_verb_prefix": self.matched_verb_prefix,
            "escalating_properties": self.escalating_properties,
        }


def _get_name(tool) -> str:
    return getattr(tool, "name", None) or (tool.get("name") if isinstance(tool, dict) else "") or ""


def _get_input_schema(tool) -> dict:
    schema = getattr(tool, "input_schema", None)
    if schema is None and isinstance(tool, dict):
        schema = tool.get("input_schema") or tool.get("inputSchema")
    return schema or {}


def check_tool(tool) -> MismatchFinding | None:
    """Return a MismatchFinding if this tool's name implies narrower scope
    than its input schema's properties suggest, else None.
    """
    name = _get_name(tool)
    lower_name = name.lower()

    matched_prefix = next((p for p in _NARROW_SCOPE_VERBS if lower_name.startswith(p)), None)
    if matched_prefix is None:
        return None

    schema = _get_input_schema(tool)
    properties = schema.get("properties", {}) if isinstance(schema, dict) else {}
    if not isinstance(properties, dict):
        return None

    escalating = [
        prop_name
        for prop_name in properties
        if any(pattern.search(prop_name) for pattern in _ESCALATING_PROPERTY_PATTERNS)
    ]

    if not escalating:
        return None

    return MismatchFinding(
        tool_name=name,
        matched_verb_prefix=matched_prefix,
        escalating_properties=escalating,
    )


def check_all_tools(tools: list) -> list[MismatchFinding]:
    """Run the mismatch check against every tool; only tools with a real
    finding appear in the result (unlike the injection check, there is no
    "needs review" state here — this check is fully deterministic).
    """
    findings = []
    for tool in tools:
        finding = check_tool(tool)
        if finding is not None:
            findings.append(finding)
    return findings
