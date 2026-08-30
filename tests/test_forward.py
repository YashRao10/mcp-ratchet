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


async def test_forward_list_tools_is_byte_identical_to_direct():
    """Stronger than the name+description check above: every field of every
    tool the client can see must survive the proxy unchanged. Serialises
    both tool lists with the same canonical dump the fingerprint uses and
    asserts the bytes are equal — this is the transparency guarantee
    (TOR-10) at full fidelity, not just on the two most-looked-at fields."""
    import json

    from scanner.fingerprint import _tool_to_canonical_dict, _stable_json

    target = TargetSpec(command="python", args=[str(TOY_SERVER)])

    direct_result = await enumerate_target(target)
    assert direct_result.ok

    async with DownstreamClient(target) as downstream:
        forwarded_result = await forward_list_tools(downstream)

    def canon(tools):
        return _stable_json(
            sorted((_tool_to_canonical_dict(t) for t in tools), key=lambda d: d["name"])
        )

    direct_bytes = canon(direct_result.tools).encode("utf-8")
    forwarded_bytes = canon(forwarded_result.tools).encode("utf-8")
    assert direct_bytes == forwarded_bytes
    # and there is genuinely more than name+description in that payload
    assert b"input_schema" in direct_bytes


async def test_forward_call_tool_returns_real_result_unmodified():
    from proxy.forward import forward_call_tool

    target = TargetSpec(command="python", args=[str(TOY_SERVER)])

    # a direct downstream call and a forwarded call must return identical content
    async with DownstreamClient(target) as direct:
        direct_result = await direct.call_tool("get_weather", {"city": "Boston"})
    async with DownstreamClient(target) as downstream:
        forwarded_result = await forward_call_tool(downstream, "get_weather", {"city": "Boston"})

    def dump(r):
        return (
            [(getattr(b, "type", None), getattr(b, "text", None)) for b in r.content],
            getattr(r, "is_error", None),
        )

    assert dump(forwarded_result) == dump(direct_result)
    text = "".join(b.text for b in forwarded_result.content if getattr(b, "type", None) == "text")
    assert "Boston" in text
    assert forwarded_result.is_error is not True
