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
    unpinned/ranged requirements are skipped rather than guessed at.

    Also handles pip-compile output, which is the same file format but
    with `\\`-continued lines and `--hash=...`/`# via ...` trailer lines —
    the trailing backslash is stripped before matching, and hash/via
    trailer lines simply never match the pin regex, so they're skipped
    the same way a comment-only line already was.
    """
    if not path.exists():
        return []
    pinned = []
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.split("#", 1)[0].strip()
        line = line.removesuffix("\\").strip()
        if not line:
            continue
        match = _REQUIREMENTS_LINE.match(line)
        if match:
            pinned.append((match.group(1), match.group(2)))
    return pinned


def parse_poetry_lock(path: Path) -> list[tuple[str, str]]:
    """Every `[[package]]` table in a poetry.lock is already a single
    resolved version — direct and transitive alike, same guarantee
    package-lock.json gives on the npm side. Malformed/missing files
    degrade to empty, same convention as every other parser here."""
    if not path.exists():
        return []
    import tomllib

    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError):
        return []

    resolved = []
    for package in data.get("package") or []:
        name = package.get("name")
        version = package.get("version")
        if name and version:
            resolved.append((name, version))
    return resolved


def parse_pipfile_lock(path: Path) -> list[tuple[str, str]]:
    """Pipfile.lock is JSON with "default" (runtime) and "develop" (dev-only)
    sections, each package's version pinned as "==X.Y.Z" — includes
    transitive deps, Pipenv resolves the full graph into this file the same
    way poetry.lock and package-lock.json do for their ecosystems."""
    if not path.exists():
        return []
    import json

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []

    resolved: dict[str, str] = {}
    for section in ("default", "develop"):
        for name, entry in (data.get(section) or {}).items():
            if not isinstance(entry, dict):
                continue
            version = entry.get("version")
            if version:
                resolved[name] = version.removeprefix("==")
    return list(resolved.items())


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


def parse_package_lock_json(path: Path) -> list[tuple[str, str]]:
    """Pulls every resolved package (direct AND transitive) out of an npm
    package-lock.json — this is the one lockfile-resolution gap the README
    names explicitly ("no lockfile resolution, no transitive dependencies"),
    closed for the npm ecosystem specifically.

    Supports lockfile v2/v3 ("packages" map, keyed by "node_modules/<name>"
    for top-level and nested paths for transitive deps — the version is
    already fully resolved, unlike package.json's "^"/"~" ranges) and falls
    back to the older v1 "dependencies" tree (which nests transitive deps
    under each direct dependency's own "dependencies" key) for older
    lockfiles. Either way, every entry here has a single concrete version —
    that's what makes a lockfile checkable where a bare manifest isn't.
    """
    if not path.exists():
        return []
    import json

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []

    resolved: dict[str, str] = {}

    packages = data.get("packages")
    if isinstance(packages, dict):
        # v2/v3: keys are "" (the project itself), "node_modules/foo",
        # "node_modules/foo/node_modules/bar" (nested/transitive), etc.
        for key, entry in packages.items():
            if not key or not isinstance(entry, dict):
                continue
            name = key.rsplit("node_modules/", 1)[-1]
            version = entry.get("version")
            if name and version:
                resolved[name] = version
    else:
        # v1 fallback: a recursive "dependencies" tree.
        def _walk(deps: dict) -> None:
            for name, entry in (deps or {}).items():
                if not isinstance(entry, dict):
                    continue
                version = entry.get("version")
                if version:
                    resolved[name] = version
                _walk(entry.get("dependencies") or {})

        _walk(data.get("dependencies") or {})

    return list(resolved.items())


def find_manifest(root: Path) -> tuple[str, Path] | None:
    """Look one level for a lockfile or manifest near a target's launch
    script. Returns (ecosystem, path) or None.

    A lockfile is preferred over its corresponding manifest when both
    exist: package-lock.json gives every transitive dependency a single
    resolved version, where package.json alone only has direct
    dependencies and often a version *range* the CVE check can't act on
    (see check_manifest_dir's ecosystem dispatch below for how the two
    parse differently). poetry.lock and Pipfile.lock get the same
    priority treatment on the Python side, ahead of a bare
    requirements.txt — a project managed by Poetry or Pipenv may not even
    have a requirements.txt, and when it does, it's often only the direct
    deps a human bothered to freeze, not the full resolved graph a
    lockfile guarantees.
    """
    for candidate, ecosystem in (
        (root / "poetry.lock", "poetry-lock"),
        (root / "Pipfile.lock", "pipenv-lock"),
        (root / "requirements.txt", "PyPI"),
        (root / "package-lock.json", "npm-lock"),
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
    if ecosystem == "PyPI":
        pinned = parse_requirements_txt(path)
    elif ecosystem == "poetry-lock":
        pinned = parse_poetry_lock(path)
    elif ecosystem == "pipenv-lock":
        pinned = parse_pipfile_lock(path)
    elif ecosystem == "npm-lock":
        pinned = parse_package_lock_json(path)
    else:
        pinned = parse_package_json(path)
    if not pinned:
        return []

    # "npm-lock"/"poetry-lock"/"pipenv-lock" are this check's own tags for
    # "came from a lockfile, so every version here is fully resolved,
    # including transitive deps" — OSV.dev itself only knows the real
    # ecosystem name (PyPI or npm).
    if ecosystem in ("poetry-lock", "pipenv-lock"):
        osv_ecosystem = "PyPI"
    elif ecosystem == "npm-lock":
        osv_ecosystem = "npm"
    else:
        osv_ecosystem = ecosystem

    findings: list[DependencyFinding] = []
    with httpx.Client() as client:
        for name, version in pinned:
            vuln_ids = _query_osv(name, version, osv_ecosystem, client)
            if vuln_ids:
                findings.append(
                    DependencyFinding(
                        package_name=name,
                        version=version,
                        ecosystem=osv_ecosystem,
                        vulnerability_ids=vuln_ids,
                    )
                )
    return findings
