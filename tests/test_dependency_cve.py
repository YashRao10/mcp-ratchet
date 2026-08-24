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
from scanner.checks import transitive_deps as td


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


def test_parse_package_lock_json_keeps_both_versions_of_a_diamond_dependency(tmp_path):
    """A real diamond dependency: two different specifiers resolve the
    same package name ("qs") to two different versions, nested under two
    different parents. Both must survive — collapsing to a name-keyed dict
    would silently drop one version's CVEs."""
    lock = tmp_path / "package-lock.json"
    lock.write_text(
        """{
        "packages": {
            "": {"name": "root-project", "version": "1.0.0"},
            "node_modules/qs": {"version": "6.5.2"},
            "node_modules/express/node_modules/qs": {"version": "6.11.0"}
        }
        }""",
        encoding="utf-8",
    )
    resolved = dc.parse_package_lock_json(lock)
    assert set(resolved) == {("qs", "6.5.2"), ("qs", "6.11.0")}


def test_parse_package_lock_json_dedupes_identical_name_version_pairs(tmp_path):
    """The same package resolving to the same version at two different
    nested paths is the common case, not a diamond -- it should collapse
    to one entry, not one OSV query per occurrence."""
    lock = tmp_path / "package-lock.json"
    lock.write_text(
        """{
        "packages": {
            "node_modules/qs": {"version": "6.5.2"},
            "node_modules/express/node_modules/qs": {"version": "6.5.2"}
        }
        }""",
        encoding="utf-8",
    )
    resolved = dc.parse_package_lock_json(lock)
    assert resolved == [("qs", "6.5.2")]


def test_parse_package_lock_json_missing_or_malformed_returns_empty(tmp_path):
    assert dc.parse_package_lock_json(tmp_path / "nope.json") == []
    bad = tmp_path / "package-lock.json"
    bad.write_text("{not valid json", encoding="utf-8")
    assert dc.parse_package_lock_json(bad) == []


def test_parse_requirements_txt_handles_pip_compile_continuation_and_hashes(tmp_path):
    """pip-compile output is the same file format but with `\\`-continued
    lines and `--hash=...`/`# via ...` trailer lines — this is the gap the
    README named explicitly for Python ("no support yet for ...
    pip-compile output")."""
    reqs = tmp_path / "requirements.txt"
    reqs.write_text(
        "httpx==0.27.0 \\\n"
        "    --hash=sha256:aaaa \\\n"
        "    --hash=sha256:bbbb\n"
        "    # via -r requirements.in\n"
        "pydantic==2.9.2\n",
        encoding="utf-8",
    )
    pinned = dc.parse_requirements_txt(reqs)
    assert set(pinned) == {("httpx", "0.27.0"), ("pydantic", "2.9.2")}


def test_parse_poetry_lock_resolves_every_package(tmp_path):
    lock = tmp_path / "poetry.lock"
    lock.write_text(
        '[[package]]\n'
        'name = "httpx"\n'
        'version = "0.27.0"\n'
        'description = "x"\n'
        '\n'
        '[[package]]\n'
        'name = "pydantic"\n'
        'version = "2.9.2"\n'
        'description = "y"\n',
        encoding="utf-8",
    )
    resolved = dict(dc.parse_poetry_lock(lock))
    assert resolved == {"httpx": "0.27.0", "pydantic": "2.9.2"}


def test_parse_poetry_lock_missing_or_malformed_returns_empty(tmp_path):
    assert dc.parse_poetry_lock(tmp_path / "nope.lock") == []
    bad = tmp_path / "poetry.lock"
    bad.write_text("not [ valid toml", encoding="utf-8")
    assert dc.parse_poetry_lock(bad) == []


def test_parse_pipfile_lock_resolves_default_and_develop_sections(tmp_path):
    lock = tmp_path / "Pipfile.lock"
    lock.write_text(
        """{
        "_meta": {},
        "default": {"httpx": {"version": "==0.27.0", "hashes": []}},
        "develop": {"pytest": {"version": "==7.4.0", "hashes": []}}
        }""",
        encoding="utf-8",
    )
    resolved = dict(dc.parse_pipfile_lock(lock))
    assert resolved == {"httpx": "0.27.0", "pytest": "7.4.0"}


def test_parse_pipfile_lock_missing_or_malformed_returns_empty(tmp_path):
    assert dc.parse_pipfile_lock(tmp_path / "nope.json") == []
    bad = tmp_path / "Pipfile.lock"
    bad.write_text("{not valid json", encoding="utf-8")
    assert dc.parse_pipfile_lock(bad) == []


def test_find_manifest_prefers_poetry_lock_over_requirements_txt(tmp_path):
    (tmp_path / "requirements.txt").write_text("httpx==0.27.0\n", encoding="utf-8")
    (tmp_path / "poetry.lock").write_text('[[package]]\nname = "x"\nversion = "1.0"\n', encoding="utf-8")
    ecosystem, path = dc.find_manifest(tmp_path)
    assert ecosystem == "poetry-lock"
    assert path.name == "poetry.lock"


def test_find_manifest_prefers_pipfile_lock_over_requirements_txt(tmp_path):
    (tmp_path / "requirements.txt").write_text("httpx==0.27.0\n", encoding="utf-8")
    (tmp_path / "Pipfile.lock").write_text('{"default": {}}', encoding="utf-8")
    ecosystem, path = dc.find_manifest(tmp_path)
    assert ecosystem == "pipenv-lock"
    assert path.name == "Pipfile.lock"


def test_check_manifest_dir_reports_vulnerable_pin_from_poetry_lock(tmp_path, monkeypatch):
    lock = tmp_path / "poetry.lock"
    lock.write_text(
        '[[package]]\nname = "jinja2"\nversion = "2.4.1"\n',
        encoding="utf-8",
    )

    def fake_query_osv(package_name, version, ecosystem, client):
        if package_name == "jinja2" and version == "2.4.1":
            return ["GHSA-462w-v97r-4m45"]
        return []

    monkeypatch.setattr(dc, "_query_osv", fake_query_osv)

    findings = dc.check_manifest_dir(tmp_path)
    assert len(findings) == 1
    assert findings[0].package_name == "jinja2"
    assert findings[0].ecosystem == "PyPI"
    assert findings[0].vulnerability_ids == ["GHSA-462w-v97r-4m45"]


def test_check_manifest_dir_reports_vulnerable_pin_from_pipfile_lock(tmp_path, monkeypatch):
    lock = tmp_path / "Pipfile.lock"
    lock.write_text(
        """{"default": {"jinja2": {"version": "==2.4.1", "hashes": []}}}""",
        encoding="utf-8",
    )

    def fake_query_osv(package_name, version, ecosystem, client):
        if package_name == "jinja2" and version == "2.4.1":
            return ["GHSA-462w-v97r-4m45"]
        return []

    monkeypatch.setattr(dc, "_query_osv", fake_query_osv)

    findings = dc.check_manifest_dir(tmp_path)
    assert len(findings) == 1
    assert findings[0].package_name == "jinja2"
    assert findings[0].ecosystem == "PyPI"


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


def test_check_manifest_dir_reports_both_versions_of_a_diamond_dependency(tmp_path, monkeypatch):
    """Integration proof of the diamond-dependency fix: a lockfile with the
    same package name resolved to two different versions must produce two
    separate findings, one per version, each checked against OSV.dev on
    its own -- not one version silently shadowing the other."""
    lock = tmp_path / "package-lock.json"
    lock.write_text(
        """{
        "packages": {
            "node_modules/qs": {"version": "6.5.2"},
            "node_modules/express/node_modules/qs": {"version": "6.11.0"}
        }
        }""",
        encoding="utf-8",
    )

    def fake_query_osv(package_name, version, ecosystem, client):
        if package_name == "qs" and version == "6.5.2":
            return ["GHSA-old-qs"]
        if package_name == "qs" and version == "6.11.0":
            return ["GHSA-new-qs"]
        return []

    monkeypatch.setattr(dc, "_query_osv", fake_query_osv)

    findings = dc.check_manifest_dir(tmp_path)
    by_version = {f.version: f for f in findings}
    assert len(findings) == 2
    assert by_version["6.5.2"].vulnerability_ids == ["GHSA-old-qs"]
    assert by_version["6.11.0"].vulnerability_ids == ["GHSA-new-qs"]
    assert all(f.package_name == "qs" and f.resolution == "exact" for f in findings)


def test_check_manifest_dir_returns_empty_when_no_manifest_present(tmp_path):
    assert dc.check_manifest_dir(tmp_path) == []


def test_check_manifest_dir_marks_lockfile_findings_as_exact(tmp_path, monkeypatch):
    lock = tmp_path / "poetry.lock"
    lock.write_text('[[package]]\nname = "jinja2"\nversion = "2.4.1"\n', encoding="utf-8")

    monkeypatch.setattr(dc, "_query_osv", lambda name, version, ecosystem, client: ["GHSA-x"])

    findings = dc.check_manifest_dir(tmp_path)
    assert len(findings) == 1
    assert findings[0].resolution == "exact"


def test_check_manifest_dir_bare_package_json_resolves_ranges_best_effort(tmp_path, monkeypatch):
    """No package-lock.json next to it -- express's "^4.18.0" range can't
    be checked directly, so it goes through transitive_deps.py's
    registry walk instead, and shows up tagged best-effort-transitive."""
    pkg = tmp_path / "package.json"
    pkg.write_text(
        '{"dependencies": {"left-pad": "1.3.0", "express": "^4.18.0"}}',
        encoding="utf-8",
    )

    def fake_query_npm_registry(package_name, client):
        if package_name == "express":
            return {"dist-tags": {"latest": "4.18.2"}, "versions": {"4.18.2": {"dependencies": {}}}}
        return None

    def fake_query_osv(package_name, version, ecosystem, client):
        if package_name == "express" and version == "4.18.2":
            return ["GHSA-express"]
        return []

    monkeypatch.setattr(td, "_query_npm_registry", fake_query_npm_registry)
    monkeypatch.setattr(dc, "_query_osv", fake_query_osv)

    findings = dc.check_manifest_dir(tmp_path)
    # left-pad is an exact pin but not vulnerable in this fake OSV, so it
    # never produces a finding -- only express's best-effort resolution does.
    assert len(findings) == 1
    assert findings[0].package_name == "express"
    assert findings[0].version == "4.18.2"
    assert findings[0].ecosystem == "npm"
    assert findings[0].resolution == "best-effort-transitive"


def test_check_manifest_dir_bare_pyproject_toml_resolves_best_effort(tmp_path, monkeypatch):
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        '[project]\nname = "demo"\ndependencies = ["jinja2>=2.0"]\n',
        encoding="utf-8",
    )

    def fake_query_pypi_metadata(package_name, client):
        if package_name == "jinja2":
            return {"info": {"version": "2.4.1", "requires_dist": []}}
        return None

    def fake_query_osv(package_name, version, ecosystem, client):
        if package_name == "jinja2" and version == "2.4.1":
            return ["GHSA-462w-v97r-4m45"]
        return []

    monkeypatch.setattr(td, "_query_pypi_metadata", fake_query_pypi_metadata)
    monkeypatch.setattr(dc, "_query_osv", fake_query_osv)

    findings = dc.check_manifest_dir(tmp_path)
    assert len(findings) == 1
    assert findings[0].package_name == "jinja2"
    assert findings[0].version == "2.4.1"
    assert findings[0].ecosystem == "PyPI"
    assert findings[0].resolution == "best-effort-transitive"


def test_check_manifest_dir_requirements_txt_with_ranges_resolves_best_effort(tmp_path, monkeypatch):
    """requirements.txt with a mix: an exact pin (checked directly,
    tagged exact) and a range (resolved through the registry walk,
    tagged best-effort-transitive)."""
    reqs = tmp_path / "requirements.txt"
    reqs.write_text("pydantic==2.9.2\njinja2>=2.0\n", encoding="utf-8")

    def fake_query_pypi_metadata(package_name, client):
        if package_name == "jinja2":
            return {"info": {"version": "2.4.1", "requires_dist": []}}
        return None

    def fake_query_osv(package_name, version, ecosystem, client):
        if package_name == "jinja2" and version == "2.4.1":
            return ["GHSA-462w-v97r-4m45"]
        if package_name == "pydantic" and version == "2.9.2":
            return ["GHSA-pydantic-fake"]
        return []

    monkeypatch.setattr(td, "_query_pypi_metadata", fake_query_pypi_metadata)
    monkeypatch.setattr(dc, "_query_osv", fake_query_osv)

    findings = dc.check_manifest_dir(tmp_path)
    by_name = {f.package_name: f for f in findings}
    assert by_name["pydantic"].resolution == "exact"
    assert by_name["jinja2"].resolution == "best-effort-transitive"
    assert by_name["jinja2"].version == "2.4.1"


def test_find_manifest_pyproject_toml_only_reached_without_lockfile_or_requirements(tmp_path):
    (tmp_path / "pyproject.toml").write_text('[project]\ndependencies = []\n', encoding="utf-8")
    ecosystem, path = dc.find_manifest(tmp_path)
    assert ecosystem == "pyproject"
    assert path.name == "pyproject.toml"


def test_find_manifest_prefers_requirements_txt_over_pyproject_toml(tmp_path):
    (tmp_path / "requirements.txt").write_text("httpx==0.27.0\n", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text('[project]\ndependencies = []\n', encoding="utf-8")
    ecosystem, path = dc.find_manifest(tmp_path)
    assert ecosystem == "PyPI"
    assert path.name == "requirements.txt"


_YARN_LOCK_FIXTURE = """# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.
# yarn lockfile v1


left-pad@1.3.0:
  version "1.3.0"
  resolved "https://registry.yarnpkg.com/left-pad/-/left-pad-1.3.0.tgz#test"
  integrity sha512-test

"@babel/code-frame@^7.0.0", "@babel/code-frame@^7.12.13":
  version "7.18.6"
  resolved "https://registry.yarnpkg.com/@babel/code-frame/-/code-frame-7.18.6.tgz#test"
  integrity sha512-test
  dependencies:
    "@babel/highlight" "^7.18.6"

express@^4.18.0:
  version "4.18.2"
  resolved "https://registry.yarnpkg.com/express/-/express-4.18.2.tgz#test"
"""


def test_parse_yarn_lock_resolves_direct_and_scoped_packages(tmp_path):
    lock = tmp_path / "yarn.lock"
    lock.write_text(_YARN_LOCK_FIXTURE, encoding="utf-8")
    resolved = dict(dc.parse_yarn_lock(lock))
    assert resolved["left-pad"] == "1.3.0"
    assert resolved["@babel/code-frame"] == "7.18.6"
    assert resolved["express"] == "4.18.2"
    # a nested "dependencies:" field's own package name (@babel/highlight)
    # is never itself a top-level header block in this fixture, so it must
    # not show up as if it had its own resolved version:
    assert "@babel/highlight" not in resolved


def test_parse_yarn_lock_multiple_specifiers_share_one_resolved_version(tmp_path):
    """Two different range specifiers resolving to the *same* version is
    the common case (yarn dedupes when it can) -- both specifiers should
    map to that one version."""
    lock = tmp_path / "yarn.lock"
    lock.write_text(
        'ms@2.0.0, ms@2.1.2:\n'
        '  version "2.1.2"\n'
        '  resolved "https://registry.yarnpkg.com/ms/-/ms-2.1.2.tgz#test"\n',
        encoding="utf-8",
    )
    resolved = dict(dc.parse_yarn_lock(lock))
    assert resolved == {"ms": "2.1.2"}


def test_parse_yarn_lock_keeps_both_versions_of_a_diamond_dependency(tmp_path):
    """Two separate header blocks for the same package name, each pinned
    to a genuinely different resolved version -- a real diamond dependency,
    not the "multiple specifiers share one version" dedup case above. Both
    versions must survive so both get checked against OSV.dev."""
    lock = tmp_path / "yarn.lock"
    lock.write_text(
        'ms@2.0.0:\n'
        '  version "2.0.0"\n'
        '  resolved "https://registry.yarnpkg.com/ms/-/ms-2.0.0.tgz#test"\n'
        '\n'
        'ms@^2.1.1:\n'
        '  version "2.1.3"\n'
        '  resolved "https://registry.yarnpkg.com/ms/-/ms-2.1.3.tgz#test"\n',
        encoding="utf-8",
    )
    resolved = dc.parse_yarn_lock(lock)
    assert set(resolved) == {("ms", "2.0.0"), ("ms", "2.1.3")}


def test_check_manifest_dir_reports_both_versions_of_a_yarn_diamond_dependency(tmp_path, monkeypatch):
    lock = tmp_path / "yarn.lock"
    lock.write_text(
        'ms@2.0.0:\n'
        '  version "2.0.0"\n'
        '\n'
        'ms@^2.1.1:\n'
        '  version "2.1.3"\n',
        encoding="utf-8",
    )

    def fake_query_osv(package_name, version, ecosystem, client):
        if package_name == "ms" and version == "2.0.0":
            return ["GHSA-old-ms"]
        if package_name == "ms" and version == "2.1.3":
            return ["GHSA-new-ms"]
        return []

    monkeypatch.setattr(dc, "_query_osv", fake_query_osv)

    findings = dc.check_manifest_dir(tmp_path)
    by_version = {f.version: f for f in findings}
    assert len(findings) == 2
    assert by_version["2.0.0"].vulnerability_ids == ["GHSA-old-ms"]
    assert by_version["2.1.3"].vulnerability_ids == ["GHSA-new-ms"]


def test_parse_yarn_lock_missing_file_returns_empty(tmp_path):
    assert dc.parse_yarn_lock(tmp_path / "nope.lock") == []


def test_parse_yarn_lock_empty_file_returns_empty(tmp_path):
    lock = tmp_path / "yarn.lock"
    lock.write_text("# yarn lockfile v1\n", encoding="utf-8")
    assert dc.parse_yarn_lock(lock) == []


def test_find_manifest_prefers_yarn_lock_over_bare_package_json(tmp_path):
    (tmp_path / "package.json").write_text('{"dependencies": {"left-pad": "^1.3.0"}}', encoding="utf-8")
    (tmp_path / "yarn.lock").write_text('left-pad@^1.3.0:\n  version "1.3.0"\n', encoding="utf-8")
    ecosystem, path = dc.find_manifest(tmp_path)
    assert ecosystem == "yarn-lock"
    assert path.name == "yarn.lock"


def test_find_manifest_prefers_package_lock_json_over_yarn_lock(tmp_path):
    """When both exist (a migration artifact in practice), package-lock.json
    wins arbitrarily -- this check doesn't try to guess which one npm/yarn
    would actually honor for an install."""
    (tmp_path / "package-lock.json").write_text('{"packages": {}}', encoding="utf-8")
    (tmp_path / "yarn.lock").write_text('left-pad@^1.3.0:\n  version "1.3.0"\n', encoding="utf-8")
    ecosystem, path = dc.find_manifest(tmp_path)
    assert ecosystem == "npm-lock"
    assert path.name == "package-lock.json"


def test_check_manifest_dir_reports_vulnerable_pin_from_yarn_lock(tmp_path, monkeypatch):
    """Integration of find_manifest -> parse_yarn_lock -> check_manifest_dir,
    with the real OSV.dev call replaced by a canned response. Marked
    "exact" -- a yarn.lock entry is just as resolved as a package-lock.json
    one, not a best-effort guess."""
    lock = tmp_path / "yarn.lock"
    lock.write_text(_YARN_LOCK_FIXTURE, encoding="utf-8")
    (tmp_path / "package.json").write_text('{"dependencies": {"express": "^4.18.0"}}', encoding="utf-8")

    def fake_query_osv(package_name, version, ecosystem, client):
        if package_name == "express" and version == "4.18.2":
            return ["GHSA-express-fake"]
        return []

    monkeypatch.setattr(dc, "_query_osv", fake_query_osv)

    findings = dc.check_manifest_dir(tmp_path)
    assert len(findings) == 1
    assert findings[0].package_name == "express"
    assert findings[0].version == "4.18.2"
    assert findings[0].ecosystem == "npm"
    assert findings[0].resolution == "exact"
