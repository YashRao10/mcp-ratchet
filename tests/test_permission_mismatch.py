from scanner.checks.permission_mismatch import check_all_tools, check_tool


def _tool(name, properties):
    return {
        "name": name,
        "input_schema": {"type": "object", "properties": properties},
    }


def test_flags_narrow_verb_with_command_property():
    tool = _tool("list_recent_files", {"directory": {"type": "string"}, "command": {"type": "string"}})
    finding = check_tool(tool)
    assert finding is not None
    assert finding.tool_name == "list_recent_files"
    assert finding.matched_verb_prefix == "list_"
    assert "command" in finding.escalating_properties


def test_does_not_flag_clean_narrow_tool():
    tool = _tool("get_weather", {"city": {"type": "string"}})
    assert check_tool(tool) is None


def test_does_not_flag_non_narrow_tool_with_command_property():
    """A tool not named with a read-only-implying verb isn't a mismatch —
    there's no narrower claim being contradicted."""
    tool = _tool("run_shell_command", {"command": {"type": "string"}})
    assert check_tool(tool) is None


def test_flags_delete_property_on_read_tool():
    tool = _tool("fetch_record", {"record_id": {"type": "string"}, "delete_after_read": {"type": "boolean"}})
    finding = check_tool(tool)
    assert finding is not None
    assert "delete_after_read" in finding.escalating_properties


def test_check_all_tools_only_returns_real_findings():
    tools = [
        _tool("get_weather", {"city": {"type": "string"}}),
        _tool("list_files", {"path": {"type": "string"}, "shell_cmd": {"type": "string"}}),
    ]
    findings = check_all_tools(tools)
    assert len(findings) == 1
    assert findings[0].tool_name == "list_files"
