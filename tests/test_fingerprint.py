"""fingerprint.py is Phase 2's load-bearing dependency — a baseline written
today has to hash identically to a live re-fingerprint of the same
unchanged server tomorrow. These tests exist to make that promise concrete,
not just asserted in a docstring.
"""

from scanner.fingerprint import fingerprint_tools, hash_tool, normalize_whitespace


def _tool(name="get_weather", description="Get the weather.", **extra):
    base = {
        "name": name,
        "description": description,
        "input_schema": {"type": "object", "properties": {"city": {"type": "string"}}},
    }
    base.update(extra)
    return base


def test_identical_tool_hashes_identically_across_calls():
    a = hash_tool(_tool())
    b = hash_tool(_tool())
    assert a == b


def test_dict_key_order_does_not_affect_hash():
    tool_a = {
        "name": "get_weather",
        "description": "Get the weather.",
        "input_schema": {"type": "object", "properties": {"city": {"type": "string"}}},
    }
    tool_b = {
        "input_schema": {"properties": {"city": {"type": "string"}}, "type": "object"},
        "description": "Get the weather.",
        "name": "get_weather",
    }
    assert hash_tool(tool_a) == hash_tool(tool_b)


def test_description_change_changes_hash():
    a = hash_tool(_tool(description="Get the weather."))
    b = hash_tool(_tool(description="Get the weather for a city."))
    assert a != b


def test_whitespace_only_change_still_changes_hash():
    """Documented, accepted trade-off (see README) — this hash is
    content-exact, not semantically normalized."""
    a = hash_tool(_tool(description="Get the weather."))
    b = hash_tool(_tool(description="Get the weather. "))
    assert a != b


def test_normalize_whitespace_collapses_runs_and_strips_strings():
    assert normalize_whitespace("Get   the  weather.  ") == "Get the weather."
    assert normalize_whitespace("Get the weather.") == "Get the weather."


def test_normalize_whitespace_recurses_into_nested_structures():
    value = {
        "description": "  Get the   weather.  ",
        "input_schema": {"properties": {"city": {"description": "A  city\nname."}}},
        "tags": [" a ", "b  "],
    }
    normalized = normalize_whitespace(value)
    assert normalized["description"] == "Get the weather."
    assert normalized["input_schema"]["properties"]["city"]["description"] == "A city name."
    assert normalized["tags"] == ["a", "b"]


def test_normalize_whitespace_never_makes_a_real_content_change_disappear():
    """The point of drift.py's whitespace_only_change flag depends on this:
    normalization must not accidentally erase an actual wording change."""
    a = normalize_whitespace("Get the weather.")
    b = normalize_whitespace("Get the weather for a city.")
    assert a != b


def test_normalize_whitespace_leaves_non_string_values_alone():
    assert normalize_whitespace(True) is True
    assert normalize_whitespace(None) is None
    assert normalize_whitespace(42) == 42


def test_schema_change_changes_hash():
    a = hash_tool(_tool())
    b = hash_tool(
        _tool(
            input_schema={
                "type": "object",
                "properties": {"city": {"type": "string"}, "units": {"type": "string"}},
            }
        )
    )
    assert a != b


def test_none_valued_optional_fields_do_not_leak_into_hash():
    """A tool with output_schema=None and one with output_schema simply
    absent should hash the same — a server that starts declaring an empty
    optional field shouldn't register as a false-positive drift."""
    with_none = {**_tool(), "output_schema": None}
    without_field = _tool()
    assert hash_tool(with_none) == hash_tool(without_field)


def test_fingerprint_tools_whole_server_hash_is_order_independent():
    tools_a = [_tool(name="a"), _tool(name="b")]
    tools_b = [_tool(name="b"), _tool(name="a")]
    fp_a = fingerprint_tools(tools_a, "test-slug")
    fp_b = fingerprint_tools(tools_b, "test-slug")
    assert fp_a.whole_server_hash == fp_b.whole_server_hash


def test_fingerprint_tools_records_per_tool_hashes():
    tools = [_tool(name="a"), _tool(name="b", description="Different.")]
    fp = fingerprint_tools(tools, "test-slug")
    assert set(fp.per_tool_hashes.keys()) == {"a", "b"}
    assert fp.per_tool_hashes["a"] != fp.per_tool_hashes["b"]
    assert fp.tool_count == 2


def test_fingerprint_round_trips_through_dict():
    from scanner.fingerprint import ServerFingerprint

    tools = [_tool(name="a")]
    fp = fingerprint_tools(tools, "test-slug")
    restored = ServerFingerprint.from_dict(fp.to_dict())
    assert restored.whole_server_hash == fp.whole_server_hash
    assert restored.per_tool_hashes == fp.per_tool_hashes


def test_fingerprint_tools_rejects_unnamed_tool():
    import pytest

    with pytest.raises(ValueError):
        fingerprint_tools([{"description": "no name"}], "test-slug")
