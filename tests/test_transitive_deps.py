"""scanner/checks/transitive_deps.py: the best-effort registry-metadata
walk for a bare manifest with no lockfile. Parsing logic (pure,
deterministic, no network) is tested directly against real file
fixtures. The npm registry / PyPI JSON API calls are never exercised
here — _query_npm_registry/_query_pypi_metadata are monkeypatched to
canned responses, same pattern as tests/test_dependency_cve.py's
_query_osv, so this suite stays fast and offline.
"""

from __future__ import annotations

from scanner.checks import transitive_deps as td


def test_parse_package_json_dependency_ranges_keeps_pinned_and_ranged(tmp_path):
    pkg = tmp_path / "package.json"
    pkg.write_text(
        """{
        "dependencies": {"left-pad": "1.3.0", "express": "^4.18.0"},
        "devDependencies": {"jest": "29.7.0", "eslint": "~8.0.0"}
        }""",
        encoding="utf-8",
    )
    entries = dict(td.parse_package_json_dependency_ranges(pkg))
    assert entries == {
        "left-pad": "1.3.0",
        "express": "^4.18.0",
        "jest": "29.7.0",
        "eslint": "~8.0.0",
    }


def test_parse_package_json_dependency_ranges_missing_file_returns_empty(tmp_path):
    assert td.parse_package_json_dependency_ranges(tmp_path / "nope.json") == []


def test_parse_requirements_txt_ranges_keeps_pinned_and_ranged(tmp_path):
    reqs = tmp_path / "requirements.txt"
    reqs.write_text(
        "httpx==0.27.0\n"
        "# a comment line\n"
        "\n"
        "requests>=2.0  # ranges are kept here, unlike parse_requirements_txt\n"
        "flask~=3.0\n"
        "-e ./local-pkg\n"
        "git+https://example.com/foo.git\n",
        encoding="utf-8",
    )
    entries = dict(td.parse_requirements_txt_ranges(reqs))
    assert entries["httpx"] == "==0.27.0"
    assert entries["requests"] == ">=2.0"
    assert entries["flask"] == "~=3.0"
    assert "local-pkg" not in entries
    assert len(entries) == 3


def test_parse_pyproject_toml_dependencies_reads_pep621_array(tmp_path):
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        '[project]\n'
        'name = "demo"\n'
        'dependencies = [\n'
        '    "httpx>=0.27,<1.0",\n'
        '    "requests[security]==2.31.0",\n'
        '    "pydantic",\n'
        ']\n',
        encoding="utf-8",
    )
    entries = dict(td.parse_pyproject_toml_dependencies(pyproject))
    assert entries["httpx"] == ">=0.27,<1.0"
    assert entries["requests"] == "==2.31.0"
    assert entries["pydantic"] == ""


def test_parse_pyproject_toml_dependencies_missing_or_malformed_returns_empty(tmp_path):
    assert td.parse_pyproject_toml_dependencies(tmp_path / "nope.toml") == []
    bad = tmp_path / "pyproject.toml"
    bad.write_text("not [ valid toml", encoding="utf-8")
    assert td.parse_pyproject_toml_dependencies(bad) == []


def test_parse_pyproject_toml_dependencies_no_project_table_returns_empty(tmp_path):
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text('[tool.poetry]\nname = "demo"\n', encoding="utf-8")
    assert td.parse_pyproject_toml_dependencies(pyproject) == []


def _npm_doc(latest: str, deps: dict[str, str]) -> dict:
    return {"dist-tags": {"latest": latest}, "versions": {latest: {"dependencies": deps}}}


def test_resolve_npm_transitive_walks_multiple_levels(monkeypatch):
    registry = {
        "left-pad": _npm_doc("1.3.0", {}),
        "express": _npm_doc("4.18.2", {"qs": "^6.11.0"}),
        "qs": _npm_doc("6.11.0", {"side-channel": "^1.0.0"}),
        "side-channel": _npm_doc("1.0.4", {}),
    }

    def fake_query_npm_registry(package_name, client):
        return registry.get(package_name)

    monkeypatch.setattr(td, "_query_npm_registry", fake_query_npm_registry)

    resolved = dict(
        td.resolve_npm_transitive(
            [("left-pad", "1.3.0"), ("express", "^4.18.0")], client=None, max_depth=2
        )
    )
    assert resolved["left-pad"] == "1.3.0"
    assert resolved["express"] == "4.18.2"
    assert resolved["qs"] == "6.11.0"  # depth 1, direct dep of express
    assert resolved["side-channel"] == "1.0.4"  # depth 2, dep of qs


def test_resolve_npm_transitive_respects_depth_cap(monkeypatch):
    """A chain deeper than max_depth: only packages within the cap show
    up in the resolved set — the deepest package's own dependency is
    never queried at all."""
    registry = {
        "a": _npm_doc("1.0.0", {"b": "^1.0.0"}),
        "b": _npm_doc("1.0.0", {"c": "^1.0.0"}),
        "c": _npm_doc("1.0.0", {"d": "^1.0.0"}),
        "d": _npm_doc("1.0.0", {}),
    }
    queried = []

    def fake_query_npm_registry(package_name, client):
        queried.append(package_name)
        return registry.get(package_name)

    monkeypatch.setattr(td, "_query_npm_registry", fake_query_npm_registry)

    resolved = dict(td.resolve_npm_transitive([("a", "^1.0.0")], client=None, max_depth=2))
    # depth 0: a, depth 1: b, depth 2: c -- d (depth 3) is never reached.
    assert set(resolved) == {"a", "b", "c"}
    assert "d" not in queried


def test_resolve_npm_transitive_circular_reference_does_not_infinite_loop(monkeypatch):
    registry = {
        "a": _npm_doc("1.0.0", {"b": "^1.0.0"}),
        "b": _npm_doc("1.0.0", {"a": "^1.0.0"}),  # cycle back to a
    }

    def fake_query_npm_registry(package_name, client):
        return registry.get(package_name)

    monkeypatch.setattr(td, "_query_npm_registry", fake_query_npm_registry)

    # If this doesn't terminate, the test suite hangs -- that's the proof.
    resolved = dict(td.resolve_npm_transitive([("a", "^1.0.0")], client=None, max_depth=5))
    assert resolved == {"a": "1.0.0", "b": "1.0.0"}


def test_resolve_npm_transitive_unreachable_package_is_skipped(monkeypatch):
    def fake_query_npm_registry(package_name, client):
        return None

    monkeypatch.setattr(td, "_query_npm_registry", fake_query_npm_registry)

    resolved = td.resolve_npm_transitive([("ghost-package", "^1.0.0")], client=None)
    assert resolved == []


def _pypi_doc(version: str, requires_dist: list[str]) -> dict:
    return {"info": {"version": version, "requires_dist": requires_dist}}


def test_resolve_pypi_transitive_walks_multiple_levels_and_skips_extras(monkeypatch):
    registry = {
        "httpx": _pypi_doc("0.27.0", ["httpcore>=1.0", "pytest ; extra == \"test\""]),
        "httpcore": _pypi_doc("1.0.5", ["h11>=0.14"]),
        "h11": _pypi_doc("0.14.0", []),
    }

    def fake_query_pypi_metadata(package_name, client):
        return registry.get(package_name)

    monkeypatch.setattr(td, "_query_pypi_metadata", fake_query_pypi_metadata)

    resolved = dict(
        td.resolve_pypi_transitive([("httpx", ">=0.27,<1.0")], client=None, max_depth=2)
    )
    assert resolved["httpx"] == "0.27.0"
    assert resolved["httpcore"] == "1.0.5"
    assert resolved["h11"] == "0.14.0"
    assert "pytest" not in resolved  # optional extra, never a plain-install dep


def test_resolve_pypi_transitive_circular_reference_does_not_infinite_loop(monkeypatch):
    registry = {
        "a": _pypi_doc("1.0.0", ["b"]),
        "b": _pypi_doc("1.0.0", ["a"]),
    }

    def fake_query_pypi_metadata(package_name, client):
        return registry.get(package_name)

    monkeypatch.setattr(td, "_query_pypi_metadata", fake_query_pypi_metadata)

    resolved = dict(td.resolve_pypi_transitive([("a", "")], client=None, max_depth=5))
    assert resolved == {"a": "1.0.0", "b": "1.0.0"}
