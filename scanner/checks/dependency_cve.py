"""Basic dependency CVE lookup via OSV.dev, when a target's manifest
(requirements.txt or package.json) is discoverable on disk.

Explicitly the lowest-priority, least-differentiated check in this project
— Cisco's MCP scanner already does this more thoroughly (pip-audit plus
VirusTotal plus sandboxed behavior). This exists so mcp-ratchet's report
isn't silent on a commodity-obvious risk class, not as a claim of
comprehensive SBOM/CVE coverage. See README's "what this does NOT do"
section.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

import httpx

OSV_QUERY_URL = "https://api.osv.dev/v1/query"
_REQUEST_TIMEOUT_SECONDS = 10


@dataclass
class DependencyFinding:
    package_name: str
    version: str | None
    ecosystem: str
    vulnerability_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "package_name": self.package_name,
            "version": self.version,
            "ecosystem": self.ecosystem,
            "vulnerability_ids": self.vulnerability_ids,
        }


_REQUIREMENTS_LINE = re.compile(r"^\s*([A-Za-z0-9_.\-]+)\s*==\s*([A-Za-z0-9_.\-]+)\s*$")


def parse_requirements_txt(path: Path) -> list[tuple[str, str]]:
    """Only pinned (==) entries are checkable against a specific version —
    unpinned/ranged requirements are skipped rather than guessed at."""
    if not path.exists():
        return []
    pinned = []
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        match = _REQUIREMENTS_LINE.match(line)
        if match:
            pinned.append((match.group(1), match.group(2)))
    return pinned


def parse_package_json(path: Path) -> list[tuple[str, str]]:
    """Pulls exact-pinned dependencies (no ^ / ~ / range prefix) from
    package.json's "dependencies" + "devDependencies"."""
    import json

    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []

    pinned = []
    for section in ("dependencies", "devDependencies"):
        for name, version in (data.get(section) or {}).items():
            if re.match(r"^\d", version):  # no ^, ~, >=, etc. prefix
                pinned.append((name, version))
    return pinned


def find_manifest(root: Path) -> tuple[str, Path] | None:
    """Look one level for a requirements.txt or package.json near a
    target's launch script. Returns (ecosystem, path) or None."""
    for candidate, ecosystem in (
        (root / "requirements.txt", "PyPI"),
        (root / "package.json", "npm"),
    ):
        if candidate.exists():
            return ecosystem, candidate
    return None


def _query_osv(package_name: str, version: str, ecosystem: str, client: httpx.Client) -> list[str]:
    try:
        response = client.post(
            OSV_QUERY_URL,
            json={"package": {"name": package_name, "ecosystem": ecosystem}, "version": version},
            timeout=_REQUEST_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
    except httpx.HTTPError:
        return []

    data = response.json()
    return [vuln["id"] for vuln in data.get("vulns", [])]


def check_manifest_dir(root: Path) -> list[DependencyFinding]:
    """Find + check whatever pinned manifest is discoverable at `root`.

    Any network failure degrades to an empty result for that package
    (fail-open on the network, not fail-open on reporting — a package OSV
    couldn't be reached for simply doesn't appear as a finding, it isn't
    reported as "clean").
    """
    manifest = find_manifest(root)
    if manifest is None:
        return []

    ecosystem, path = manifest
    pinned = parse_requirements_txt(path) if ecosystem == "PyPI" else parse_package_json(path)
    if not pinned:
        return []

    findings: list[DependencyFinding] = []
    with httpx.Client() as client:
        for name, version in pinned:
            vuln_ids = _query_osv(name, version, ecosystem, client)
            if vuln_ids:
                findings.append(
                    DependencyFinding(
                        package_name=name,
                        version=version,
                        ecosystem=ecosystem,
                        vulnerability_ids=vuln_ids,
                    )
                )
    return findings
