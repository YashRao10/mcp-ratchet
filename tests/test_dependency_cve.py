"""scanner/checks/dependency_cve.py had zero test coverage before this —
a real gap found while extending it with lockfile support this round, not
just for the new package-lock.json path. Parsing logic (pure, deterministic,
no network) is tested directly against real file fixtures. The OSV.dev
network call itself is never exercised here — check_manifest_dir's
integration behavior is tested with _query_osv monkeypatched to a canned
response, so this suite stays fast and doesn't depend on a live network
call succeeding.
"""

from __future__ import annotations

from scanner.checks import dependency_cve as dc


def test_parse_requirements_txt_only_keeps_exact_pins(tmp_path):
    reqs = tmp_path / "requirements.txt"
    reqs.write_text(
        "httpx==0.27.0\n"
        "# a comment line\n"
        "\n"
        "requests>=2.0  # ranges are skipped, not guessed at\n"
        "flask~=3.0\n"
        "pydantic==2.9.2  # trailing comment stripped\n",
        encoding="utf-8",
    )
    pinned = dc.parse_requirements_txt(reqs)
    assert set(pinned) == {("httpx", "0.27.0"), ("pydantic", "2.9.2")}


def test_parse_requirements_txt_missing_file_returns_empty(tmp_path):
    assert dc.parse_requirements_txt(tmp_path / "nope.txt") == []


def test_parse_package_json_only_keeps_exact_pins(tmp_path):
    pkg = tmp_path / "package.json"
    pkg.write_text(
        """{
        "dependencies": {"left-pad": "1.3.0", "express": "^4.18.0"},
        "devDependencies": {"jest": "29.7.0", "eslint": "~8.0.0"}
        }""",
        encoding="utf-8",
    )
    pinned = dc.parse_package_json(pkg)
    assert set(pinned) == {("left-pad", "1.3.0"), ("jest", "29.7.0")}


def test_parse_package_lock_json_v3_resolves_transitive_deps(tmp_path):
    """v2/v3 lockfiles list every package — direct and nested/transitive —
    flat in "packages", keyed by its node_modules path. This is the actual
    gap the README named: package.json alone never has this."""
    lock = tmp_path / "package-lock.json"
    lock.write_text(
        """{
        "lockfileVersion": 3,
        "packages": {
            "": {"name": "root-project", "version": "1.0.0"},
            "node_modules/left-pad": {"version": "1.3.0"},
            "node_modules/express": {"version": "4.18.2"},
            "node_modules/express/node_modules/qs": {"version": "6.11.0"}
        }
        }""",
        encoding="utf-8",
    )
    resolved = dict(dc.parse_package_lock_json(lock))
    assert resolved["left-pad"] == "1.3.0"
    assert resolved["express"] == "4.18.2"
    # the transitive dep (nested under express's own node_modules) shows
    # up as a first-class entry too, not just express itself:
    assert resolved["qs"] == "6.11.0"
    assert "root-project" not in resolved  # the "" key is the project itself, not a dependency


def test_parse_package_lock_json_v1_walks_nested_dependencies_tree(tmp_path):
    lock = tmp_path / "package-lock.json"
    lock.write_text(
        """{
        "lockfileVersion": 1,
        "dependencies": {
            "express": {
                "version": "4.18.2",
                "dependencies": {
                    "qs": {"version": "6.11.0"}
                }
            },
            "left-pad": {"version": "1.3.0"}
        }
        }""",
        encoding="utf-8",
    )
    resolved = dict(dc.parse_package_lock_json(lock))
    assert resolved == {"express": "4.18.2", "qs": "6.11.0", "left-pad": "1.3.0"}


def test_parse_package_lock_json_missing_or_malformed_returns_empty(tmp_path):
    assert dc.parse_package_lock_json(tmp_path / "nope.json") == []
    bad = tmp_path / "package-lock.json"
    bad.write_text("{not valid json", encoding="utf-8")
    assert dc.parse_package_lock_json(bad) == []


def test_find_manifest_prefers_lockfile_over_bare_package_json(tmp_path):
    """A lockfile resolves every version exactly; a bare package.json often
    has ^/~ ranges this check can't act on — so when both exist, the
    lockfile wins."""
    (tmp_path / "package.json").write_text('{"dependencies": {}}', encoding="utf-8")
    (tmp_path / "package-lock.json").write_text('{"packages": {}}', encoding="utf-8")
    ecosystem, path = dc.find_manifest(tmp_path)
    assert ecosystem == "npm-lock"
    assert path.name == "package-lock.json"


def test_find_manifest_falls_back_to_package_json_without_a_lockfile(tmp_path):
    (tmp_path / "package.json").write_text('{"dependencies": {}}', encoding="utf-8")
    ecosystem, path = dc.find_manifest(tmp_path)
    assert ecosystem == "npm"
    assert path.name == "package.json"


def test_find_manifest_prefers_requirements_txt_over_npm_files(tmp_path):
    (tmp_path / "requirements.txt").write_text("httpx==0.27.0\n", encoding="utf-8")
    (tmp_path / "package.json").write_text('{"dependencies": {}}', encoding="utf-8")
    ecosystem, path = dc.find_manifest(tmp_path)
    assert ecosystem == "PyPI"
    assert path.name == "requirements.txt"


def test_find_manifest_returns_none_when_nothing_present(tmp_path):
    assert dc.find_manifest(tmp_path) is None


def test_check_manifest_dir_reports_vulnerable_pin_from_lockfile(tmp_path, monkeypatch):
    """Integration of find_manifest -> parse_package_lock_json ->
    check_manifest_dir, with the real OSV.dev network call replaced by a
    canned response so this test is fast and offline. A transitive-only
    dependency (qs, never listed in package.json itself) is the one that
    trips the finding — proving the lockfile path, not just the top-level
    package, actually gets checked."""
    lock = tmp_path / "package-lock.json"
    lock.write_text(
        """{
        "packages": {
            "": {"name": "root"},
            "node_modules/express": {"version": "4.18.2"},
            "node_modules/express/node_modules/qs": {"version": "6.5.2"}
        }
        }""",
        encoding="utf-8",
    )

    def fake_query_osv(package_name, version, ecosystem, client):
        if package_name == "qs" and version == "6.5.2":
            return ["GHSA-hpx4-r86g-5jrg"]
        return []

    monkeypatch.setattr(dc, "_query_osv", fake_query_osv)

    findings = dc.check_manifest_dir(tmp_path)
    assert len(findings) == 1
    assert findings[0].package_name == "qs"
    assert findings[0].version == "6.5.2"
    assert findings[0].ecosystem == "npm"  # osv_ecosystem, not the internal "npm-lock" tag
    assert findings[0].vulnerability_ids == ["GHSA-hpx4-r86g-5jrg"]


def test_check_manifest_dir_returns_empty_when_no_manifest_present(tmp_path):
    assert dc.check_manifest_dir(tmp_path) == []
