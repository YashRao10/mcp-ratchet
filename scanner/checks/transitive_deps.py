"""Best-effort transitive dependency resolution for the one gap
dependency_cve.py names explicitly: a bare manifest with no lockfile —
npm's package.json with no package-lock.json, or Python's pyproject.toml
(no poetry.lock/Pipfile.lock) / requirements.txt with version ranges
instead of `==` pins. None of those give a single resolved version per
package the way a real lockfile does.

This is NOT a real dependency solver. pip/npm/poetry each own a
multi-year constraint-solving problem (conflict resolution across
sibling requirements, backtracking, platform/extras markers) that isn't
reimplemented here or anywhere close to it. What this does instead: for
each direct dependency, query the real registry (npm's registry.npmjs.org
or PyPI's JSON API) for that package's *latest* published version and
that version's own declared dependencies, and walk outward to a bounded
depth. The result is an approximate transitive set — a reasonable guess
at what a fresh install would likely pull in, not a guarantee of it. It
can both over-report (packages a real resolver would never select because
a sibling constraint ruled them out) and under-report (a real resolver
sometimes picks an older version than "latest" to satisfy a shared
constraint, and that older version can carry a different dependency set
entirely). See README's "what this does NOT do" section — this is named
there, not buried in a comment only developers read.
"""

from __future__ import annotations

import re
from pathlib import Path

import httpx

NPM_REGISTRY_URL = "https://registry.npmjs.org"
PYPI_JSON_URL = "https://pypi.org/pypi"
_REQUEST_TIMEOUT_SECONDS = 10

# How many registry hops out from a direct dependency this will walk.
# Depth 0 is the direct dependencies themselves; each further level is
# one more "dependency of a dependency" hop. Kept small deliberately —
# this is a best-effort approximation, not a full graph walk, and cost
# (one network round-trip per unique package name) grows with depth.
MAX_TRANSITIVE_DEPTH = 2


def parse_package_json_dependency_ranges(path: Path) -> list[tuple[str, str]]:
    """Every entry in "dependencies" + "devDependencies", pinned or not —
    unlike dependency_cve.parse_package_json, which only keeps exact pins.
    Used to find the ranged entries a bare package.json (no
    package-lock.json) leaves this check unable to act on directly."""
    import json

    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []

    entries = []
    for section in ("dependencies", "devDependencies"):
        for name, version in (data.get(section) or {}).items():
            if isinstance(name, str) and isinstance(version, str):
                entries.append((name, version))
    return entries


_REQUIREMENTS_LINE_ANY = re.compile(r"^([A-Za-z0-9][A-Za-z0-9_.\-]*)\s*(?:\[[^\]]*\])?\s*(.*)$")


def parse_requirements_txt_ranges(path: Path) -> list[tuple[str, str]]:
    """Every parseable dependency line, pinned or ranged — unlike
    dependency_cve.parse_requirements_txt, which only keeps exact (==)
    pins. Same comment/continuation/hash-trailer handling as that parser.
    Lines this can't confidently read as "name + spec" (extras-only,
    VCS/URL requirements, `-e`/`-r` directives) are skipped rather than
    guessed at, same convention as the rest of this project."""
    if not path.exists():
        return []
    entries = []
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.split("#", 1)[0].strip()
        line = line.removesuffix("\\").strip()
        if not line or line.startswith("-") or "://" in line:
            continue
        match = _REQUIREMENTS_LINE_ANY.match(line)
        if match:
            entries.append((match.group(1), match.group(2).strip()))
    return entries


def parse_pyproject_toml_dependencies(path: Path) -> list[tuple[str, str]]:
    """PEP 621's `[project.dependencies]` — a plain array of PEP 508
    strings like `"httpx>=0.27,<1.0"` or `"requests[security]==2.31.0"`.
    Regex-based, deliberately not pulled through a full PEP 508 parser
    library (none is already a dependency of this project) — same level
    of parsing rigor as parse_requirements_txt, just applied to a
    different manifest shape. A marker clause (`; python_version < "3.9"`)
    is kept as part of the returned spec string, not stripped or
    evaluated — this never decides whether a marker applies to the
    current environment, it only reads the name out of the line."""
    if not path.exists():
        return []
    import tomllib

    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError):
        return []

    raw_deps = ((data.get("project") or {}).get("dependencies")) or []
    entries = []
    for raw in raw_deps:
        if not isinstance(raw, str):
            continue
        match = _REQUIREMENTS_LINE_ANY.match(raw.strip())
        if match:
            entries.append((match.group(1), match.group(2).strip()))
    return entries


def _query_npm_registry(package_name: str, client: httpx.Client) -> dict | None:
    """The real network boundary for the npm side — tests monkeypatch
    this exactly the way tests/test_dependency_cve.py monkeypatches
    _query_osv. Returns the raw registry document, or None on any
    network failure (fail-open on the network, same convention as
    _query_osv: a package the registry couldn't be reached for simply
    doesn't contribute to the resolved set)."""
    try:
        response = client.get(
            f"{NPM_REGISTRY_URL}/{package_name}", timeout=_REQUEST_TIMEOUT_SECONDS
        )
        response.raise_for_status()
    except httpx.HTTPError:
        return None
    try:
        return response.json()
    except ValueError:
        return None


def _query_pypi_metadata(package_name: str, client: httpx.Client) -> dict | None:
    """The real network boundary for the PyPI side. Same fail-open-on-
    network-failure convention as _query_npm_registry/_query_osv."""
    try:
        response = client.get(
            f"{PYPI_JSON_URL}/{package_name}/json", timeout=_REQUEST_TIMEOUT_SECONDS
        )
        response.raise_for_status()
    except httpx.HTTPError:
        return None
    try:
        return response.json()
    except ValueError:
        return None


def _npm_latest_version_and_deps(metadata: dict) -> tuple[str, list[str]] | None:
    """Picks "dist-tags".latest as the candidate version — the best-effort
    stand-in for what a real installer's constraint solver would pick,
    not a claim that it's what one actually would in every case."""
    dist_tags = metadata.get("dist-tags") or {}
    latest = dist_tags.get("latest")
    if not latest:
        return None
    versions = metadata.get("versions") or {}
    version_entry = versions.get(latest) or {}
    deps = version_entry.get("dependencies") or {}
    return latest, [name for name in deps if isinstance(name, str)]


_REQUIRES_DIST_NAME = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9_.\-]*)")


def _pypi_latest_version_and_deps(metadata: dict) -> tuple[str, list[str]] | None:
    """PyPI's JSON API only exposes "requires_dist" for the *current*
    release (info.version) — there's no per-historical-version dependency
    listing the way npm's registry document has one entry per version.
    Entries carrying an `extra ==` marker (optional extras, e.g. a
    package's own "test" or "docs" extra) are skipped — those are opt-in
    dependency sets a plain install never pulls in."""
    info = metadata.get("info") or {}
    version = info.get("version")
    if not version:
        return None
    requires_dist = info.get("requires_dist") or []
    names = []
    for raw in requires_dist:
        if not isinstance(raw, str) or "extra ==" in raw:
            continue
        match = _REQUIRES_DIST_NAME.match(raw)
        if match:
            names.append(match.group(1))
    return version, names


def resolve_npm_transitive(
    direct: list[tuple[str, str]],
    client: httpx.Client,
    max_depth: int = MAX_TRANSITIVE_DEPTH,
) -> list[tuple[str, str]]:
    """Breadth-first walk outward from `direct` (name, range) pairs to
    `max_depth` registry hops. A visited set (by package name) guards
    against both a circular dependency reference and simply re-querying
    the same package reached two different ways — either would otherwise
    infinite-loop or waste network calls. Returns (name, resolved_version)
    for every package actually reached, direct and transitive alike."""
    resolved: dict[str, str] = {}
    visited: set[str] = set()
    queue: list[tuple[str, int]] = [(name, 0) for name, _ in direct]

    while queue:
        name, depth = queue.pop(0)
        if name in visited:
            continue
        visited.add(name)

        metadata = _query_npm_registry(name, client)
        if metadata is None:
            continue
        result = _npm_latest_version_and_deps(metadata)
        if result is None:
            continue
        version, dep_names = result
        resolved[name] = version

        if depth >= max_depth:
            continue
        for dep_name in dep_names:
            if dep_name not in visited:
                queue.append((dep_name, depth + 1))

    return list(resolved.items())


def resolve_pypi_transitive(
    direct: list[tuple[str, str]],
    client: httpx.Client,
    max_depth: int = MAX_TRANSITIVE_DEPTH,
) -> list[tuple[str, str]]:
    """Same walk as resolve_npm_transitive, against PyPI's JSON API."""
    resolved: dict[str, str] = {}
    visited: set[str] = set()
    queue: list[tuple[str, int]] = [(name, 0) for name, _ in direct]

    while queue:
        name, depth = queue.pop(0)
        if name in visited:
            continue
        visited.add(name)

        metadata = _query_pypi_metadata(name, client)
        if metadata is None:
            continue
        result = _pypi_latest_version_and_deps(metadata)
        if result is None:
            continue
        version, dep_names = result
        resolved[name] = version

        if depth >= max_depth:
            continue
        for dep_name in dep_names:
            if dep_name not in visited:
                queue.append((dep_name, depth + 1))

    return list(resolved.items())
