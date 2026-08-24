from scanner.checks.secret_scan import scan_file, scan_source_tree


def test_scan_file_finds_aws_key(tmp_path):
    target = tmp_path / "config.py"
    target.write_text("AWS_KEY = 'AKIAABCDEFGHIJKLMNOP'\n")
    findings = scan_file(target)
    assert len(findings) == 1
    assert findings[0].pattern_name == "aws_access_key_id"
    assert findings[0].line_number == 1


def test_scan_file_redacts_the_match():
    from scanner.checks.secret_scan import _redact

    redacted = _redact("AKIAABCDEFGHIJKLMNOP")
    assert redacted.startswith("AKIA")
    assert "ABCDEFGHIJKL" not in redacted


def test_scan_file_finds_generic_api_key_assignment(tmp_path):
    target = tmp_path / "settings.py"
    target.write_text('api_key = "sk-thisisareallylongfakeapikeyvalue1234"\n')
    findings = scan_file(target)
    assert any(f.pattern_name == "generic_api_key_assignment" for f in findings)


def test_scan_file_finds_nothing_in_clean_file(tmp_path):
    target = tmp_path / "clean.py"
    target.write_text("def add(a, b):\n    return a + b\n")
    assert scan_file(target) == []


def test_scan_file_on_missing_file_returns_empty_not_error(tmp_path):
    assert scan_file(tmp_path / "does-not-exist.py") == []


def test_scan_source_tree_skips_node_modules(tmp_path):
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "leaky.js").write_text("const k = 'AKIAABCDEFGHIJKLMNOP';\n")
    (tmp_path / "app.py").write_text("x = 1\n")
    findings = scan_source_tree(tmp_path)
    assert findings == []


def test_scan_source_tree_finds_real_planted_secret_in_toy_fixture():
    from pathlib import Path

    fixtures_dir = Path(__file__).resolve().parent / "fixtures"
    findings = scan_source_tree(fixtures_dir)
    assert any(f.pattern_name == "aws_access_key_id" for f in findings)


def test_scan_source_tree_finds_secret_in_dotenv_file(tmp_path):
    """Real bug found dogfooding: Path(".env").suffix == "" in pathlib
    (a leading-dot filename with only one dot has no suffix at all), so a
    literal `.env` file was silently never scanned even though ".env" was
    already listed in _SCANNABLE_SUFFIXES. A .env file is the single most
    likely place a real MCP server target actually keeps a live secret."""
    (tmp_path / ".env").write_text("AWS_ACCESS_KEY_ID=AKIAABCDEFGHIJKLMNOP\n")
    findings = scan_source_tree(tmp_path)
    assert any(f.pattern_name == "aws_access_key_id" for f in findings)


def test_scan_source_tree_finds_secret_in_dotenv_variant_file(tmp_path):
    """Same bug, different shape: Path(".env.local").suffix == ".local",
    not ".env", so environment-specific dotenv variants (.env.local,
    .env.production, etc.) were also silently skipped."""
    (tmp_path / ".env.production").write_text(
        'api_key = "sk-thisisareallylongfakeapikeyvalue1234"\n'
    )
    findings = scan_source_tree(tmp_path)
    assert any(f.pattern_name == "generic_api_key_assignment" for f in findings)


def test_scan_source_tree_still_skips_dotenv_lookalike_with_no_secret(tmp_path):
    """Negative control: a dotenv file that happens to be clean shouldn't
    produce a finding just because it's now scanned."""
    (tmp_path / ".env").write_text("APP_NAME=my-app\n")
    findings = scan_source_tree(tmp_path)
    assert findings == []
