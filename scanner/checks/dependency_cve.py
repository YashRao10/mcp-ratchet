"""Basic dependency CVE lookup via OSV.dev, when a target's manifest
(requirements.txt, pyproject.toml, or package.json) is discoverable on
disk.

Explicitly the lowest-priority, least-differentiated check in this project
— Cisco's MCP scanner already does this more thoroughly (pip-audit plus
VirusTotal plus sandboxed behavior). This exists so mcp-ratchet's report
isn't silent on a commodity-obvious risk class, not as a claim of
comprehensive SBOM/CVE coverage. See README's "what this does NOT do"
section.

Every finding carries a `resolution` of either "exact" (came from a
lockfile or an exact `==`/pinned version — a real, single, resolvable
version) or "best-effort-transitive" (came from transitive_deps.py's
registry-metadata walk for a bare manifest with no lockfile — an
approximation, not a guarantee; see that module's docstring for exactly
what "best-effort" does and doesn't mean here).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

import httpx

from scanner.checks import transitive_deps

OSV_QUERY_URL = "https://api.osv.dev/v1/query"
_REQUEST_TIMEOUT_SECONDS = 10


@dataclass
class DependencyFinding:
    package_name: str
    version: str | None
    ecosystem: str
    vulnerability_ids: list[str] = field(default_factory=list)
    # "exact": from a lockfile or an exact pin — a real resolved version.
    # "best-effort-transitive": from transitive_deps.py's registry-metadata
    # walk of a bare manifest with no lockfile — an approximation, see
    # that module's docstring for what it can over/under-report.
    resolution: str = "exact"

    def to_dict(self) -> dict:
        return {
            "package_name": self.package_name,
            "version": self.version,
            "ecosystem": self.ecosystem,
            "vulnerability_ids": self.vulnerability_ids,
            "resolution": self.resolution,
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
    directly (see check_manifest_dir's ecosystem dispatch below for how
    the two parse differently, and transitive_deps.py for what happens to
    those ranges now). poetry.lock and Pipfile.lock get the same priority
    treatment on the Python side, ahead of requirements.txt, ahead of
    pyproject.toml — a project managed by Poetry or Pipenv may not even
    have a requirements.txt, and when it does, it's often only the direct
    deps a human bothered to freeze, not the full resolved graph a
    lockfile guarantees. pyproject.toml sits last on the Python side: its
    `[project.dependencies]` array is PEP 621 ranges, never a resolved
    version, so it's only reached when nothing more resolved exists.
    """
    for candidate, ecosystem in (
        (root / "poetry.lock", "poetry-lock"),
        (root / "Pipfile.lock", "pipenv-lock"),
        (root / "requirements.txt", "PyPI"),
        (root / "pyproject.toml", "pyproject"),
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
    """Find + check whatever manifest is discoverable at `root`.

    Two disjoint sets of dependencies can come out of this:
    - `exact` — a lockfile entry or an exact (`==`/pinned) manifest entry.
      A real, resolvable version; checked against OSV.dev directly.
    - `best-effort-transitive` — everything left over from a bare
      manifest with no lockfile (a `^`/`~`/ranged package.json entry, or
      anything from pyproject.toml/requirements.txt-with-ranges), walked
      out through transitive_deps.py's registry-metadata resolver. See
      that module's docstring for exactly what this guarantees and what
      it doesn't — it is never a real dependency solve.

    Any network failure (OSV.dev or the registry walk) degrades to an
    empty result for that package (fail-open on the network, not fail-open
    on reporting — a package that couldn't be reached simply doesn't
    appear as a finding, it isn't reported as "clean").
    """
    manifest = find_manifest(root)
    if manifest is None:
        return []

    ecosystem, path = manifest
    exact_pinned: list[tuple[str, str]] = []
    best_effort_ranges: list[tuple[str, str]] = []

    if ecosystem == "poetry-lock":
        exact_pinned = parse_poetry_lock(path)
        osv_ecosystem = "PyPI"
    elif ecosystem == "pipenv-lock":
        exact_pinned = parse_pipfile_lock(path)
        osv_ecosystem = "PyPI"
    elif ecosystem == "npm-lock":
        exact_pinned = parse_package_lock_json(path)
        osv_ecosystem = "npm"
    elif ecosystem == "PyPI":
        exact_pinned = parse_requirements_txt(path)
        exact_names = {name for name, _ in exact_pinned}
        best_effort_ranges = [
            (name, spec)
            for name, spec in transitive_deps.parse_requirements_txt_ranges(path)
            if name not in exact_names
        ]
        osv_ecosystem = "PyPI"
    elif ecosystem == "pyproject":
        # PEP 621 [project.dependencies] is always a range, never a
        # resolved version — nothing here is ever "exact".
        best_effort_ranges = transitive_deps.parse_pyproject_toml_dependencies(path)
        osv_ecosystem = "PyPI"
    else:  # "npm" — bare package.json, no package-lock.json
        exact_pinned = parse_package_json(path)
        exact_names = {name for name, _ in exact_pinned}
        best_effort_ranges = [
            (name, spec)
            for name, spec in transitive_deps.parse_package_json_dependency_ranges(path)
            if name not in exact_names
        ]
        osv_ecosystem = "npm"

    if not exact_pinned and not best_effort_ranges:
        return []

    findings: list[DependencyFinding] = []
    with httpx.Client() as client:
        for name, version in exact_pinned:
            vuln_ids = _query_osv(name, version, osv_ecosystem, client)
            if vuln_ids:
                findings.append(
                    DependencyFinding(
                        package_name=name,
                        version=version,
                        ecosystem=osv_ecosystem,
                        vulnerability_ids=vuln_ids,
                        resolution="exact",
                    )
                )

        if best_effort_ranges:
            if osv_ecosystem == "npm":
                resolved = transitive_deps.resolve_npm_transitive(best_effort_ranges, client)
            else:
                resolved = transitive_deps.resolve_pypi_transitive(best_effort_ranges, client)
            for name, version in resolved:
                vuln_ids = _query_osv(name, version, osv_ecosystem, client)
                if vuln_ids:
                    findings.append(
                        DependencyFinding(
                            package_name=name,
                            version=version,
                            ecosystem=osv_ecosystem,
                            vulnerability_ids=vuln_ids,
                            resolution="best-effort-transitive",
                        )
                    )

    return findings
