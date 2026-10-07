"""
One dial per address at a time.

The neighbour loop, the address-retry loop and a routed packet's upgrade can all
decide, in the same second, that a node they are not linked to is worth a dial.
Each walks the node's addresses, so two of them opened two sockets to the same
address two milliseconds apart and waited out the same eight-second timeout
twice. A second caller now waits on the dial already in flight and is handed its
outcome.
"""
import asyncio

from src.node import MeshNode
from src.node_id import NodeID
from tests.conftest import make_manager

TARGET = NodeID(b"\x42" * 20)
URI = "fake://a:1"


def _node_counting_dials(delay: float = 0.05, result=None):
    node = MeshNode(transport_manager=make_manager())
    calls = []

    async def _open(node_id, node_hex, uri, timeout, probe):
        calls.append((uri, probe))
        await asyncio.sleep(delay)
        return result

    node._open_dial = _open
    return node, calls


class TestOneDialPerAddress:

    async def test_two_callers_at_once_open_one_dial(self):
        sentinel = object()
        node, calls = _node_counting_dials(result=sentinel)
        first, second = await asyncio.gather(
            node._dial_uri(TARGET, URI, 1.0), node._dial_uri(TARGET, URI, 1.0))
        assert calls == [(URI, False)]
        assert first is sentinel and second is sentinel
        assert node._dials_in_flight == {}

    async def test_other_addresses_are_not_held_back(self):
        node, calls = _node_counting_dials()
        await asyncio.gather(node._dial_uri(TARGET, URI, 1.0),
                             node._dial_uri(TARGET, "fake://b:1", 1.0))
        assert sorted(uri for uri, _ in calls) == [URI, "fake://b:1"]

    async def test_a_dial_after_the_first_ended_dials_again(self):
        node, calls = _node_counting_dials()
        await node._dial_uri(TARGET, URI, 1.0)
        await node._dial_uri(TARGET, URI, 1.0)
        assert len(calls) == 2

    async def test_a_probe_gets_its_own_link(self):
        node, calls = _node_counting_dials()
        await asyncio.gather(node._dial_uri(TARGET, URI, 1.0),
                             node._dial_uri(TARGET, URI, 1.0, probe=True))
        assert sorted(probe for _, probe in calls) == [False, True]

    async def test_the_first_caller_cancelled_releases_the_waiters(self):
        node, calls = _node_counting_dials(delay=10.0)
        first = asyncio.ensure_future(node._dial_uri(TARGET, URI, 5.0))
        await asyncio.sleep(0.01)
        second = asyncio.ensure_future(node._dial_uri(TARGET, URI, 5.0))
        await asyncio.sleep(0.01)
        first.cancel()
        assert await asyncio.wait_for(second, 1.0) is None
        assert node._dials_in_flight == {}
        assert len(calls) == 1

    async def test_a_waiter_keeps_its_own_timeout(self):
        node, _calls = _node_counting_dials(delay=10.0)
        first = asyncio.ensure_future(node._dial_uri(TARGET, URI, 5.0))
        await asyncio.sleep(0.01)
        assert await node._dial_uri(TARGET, URI, 0.05) is None
        assert not first.done()
        first.cancel()
