"""Proves proxy/forward.py's transparency requirement: what the proxy
hands upstream must be byte-identical to what the real downstream server
actually said, not a reconstructed or reshaped copy.
"""

from pathlib import Path

from proxy.client_side import DownstreamClient
from proxy.forward import forward_list_tools
from scanner.connect import TargetSpec, enumerate_target

TOY_SERVER = Path(__file__).resolve().parent / "fixtures" / "toy_server.py"


async def test_forward_list_tools_matches_direct_connection_exactly():
    target = TargetSpec(command="python", args=[str(TOY_SERVER)])

    direct_result = await enumerate_target(target)
    assert direct_result.ok

    async with DownstreamClient(target) as downstream:
        forwarded_result = await forward_list_tools(downstream)

    direct_names_and_desc = sorted((t.name, t.description) for t in direct_result.tools)
    forwarded_names_and_desc = sorted((t.name, t.description) for t in forwarded_result.tools)
    assert direct_names_and_desc == forwarded_names_and_desc


async def test_forward_call_tool_returns_real_result_unmodified():
    from proxy.forward import forward_call_tool

    target = TargetSpec(command="python", args=[str(TOY_SERVER)])
    async with DownstreamClient(target) as downstream:
        result = await forward_call_tool(downstream, "get_weather", {"city": "Boston"})

    text = "".join(block.text for block in result.content if getattr(block, "type", None) == "text")
    assert "Boston" in text
    assert result.is_error is not True
