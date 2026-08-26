"""Two joined, idle nodes must exchange almost nothing.

The original bug: `_maintain_neighbors` sent a FIND_NODE, and the FOUND_NODE
reply woke maintenance, which started again with no delay at all. Since a
FOUND_NODE carries certificate chains (~15 KB), two idle nodes saturated the
link — 3 Mbit/s measured locally, a constant rate on a real link. A mesh smaller
than `_NEIGHBOR_FLOOR` can never reach that floor, so the search never stopped
on its own.

Excluded from the default suite (see the pyproject addopts): this test observes
real time.
"""
import asyncio

import pytest

from src import MeshNode
from src.node import MESSAGE_NAMES
from src.transport_manager import TransportManager
from src.tcp_transport import TCPTransport, TCPServer


def make_node() -> MeshNode:
    mgr = TransportManager()
    mgr.register("tcp", TCPTransport, TCPServer)
    return MeshNode(mgr)


async def _joined_pair(addr: str):
    host, guest = make_node(), make_node()
    code = host.generate_invite()
    await host.start([f"tcp://{addr}"])
    await guest.join(f"tcp://{addr}", code)
    await guest.wait_for_session(timeout=15.0)
    await host.wait_for_session(timeout=15.0)
    await guest.bootstrap()
    await host.bootstrap()
    return host, guest


class TestIdleChatter:
    async def test_two_idle_nodes_stay_quiet(self):
        host, guest = await _joined_pair("127.0.0.1:19341")
        try:
            await asyncio.sleep(2)          # let the join settle
            host.trace.start(seconds=40, events=20000, names=MESSAGE_NAMES)
            await asyncio.sleep(20)
            host.trace.stop()
            summary = host.trace.summary()

            # The threshold is wide on purpose: this test catches a runaway
            # loop, not a variation of a few packets. Before the fix, this
            # window carried megabytes.
            assert summary["bytes_in"] + summary["bytes_out"] < 200_000, summary

            found = [row for row in summary["rows"]
                     if row["type"] == "FOUND_NODE"]
            packets = sum(row["packets"] for row in found)
            assert packets <= 4, f"FOUND_NODE en boucle : {summary['rows']}"
        finally:
            await guest.stop()
            await host.stop()

    async def test_a_reply_that_teaches_nothing_does_not_relaunch_the_search(self):
        """The heart of the bug: a reply must not cause the next question. Our
        own id counts as "already known" — the table refuses to store it, so
        `contains` is false for it forever and every reply mentioning us looked
        like a discovery.

        Measured over a window covering at least one maintenance cycle, or the
        test would also pass on the buggy code."""
        host, guest = await _joined_pair("127.0.0.1:19342")
        try:
            await asyncio.sleep(2)
            wakes = []
            original = host._wake_neighbor_maintenance

            def spy():
                wakes.append(1)
                return original()

            host._wake_neighbor_maintenance = spy
            await asyncio.sleep(25)
            assert len(wakes) <= 3, f"maintenance woke {len(wakes)} times"
        finally:
            await guest.stop()
            await host.stop()

    async def test_discovery_still_works_when_there_is_something_to_find(self):
        """The bound must not turn discovery off: a third node that arrives has
        to be found by the first, which never dialled it."""
        host, guest = await _joined_pair("127.0.0.1:19343")
        third = make_node()
        try:
            code = host.generate_invite()
            await third.join("tcp://127.0.0.1:19343", code)
            await third.wait_for_session(timeout=15.0)
            await third.bootstrap()
            deadline = asyncio.get_event_loop().time() + 30
            while asyncio.get_event_loop().time() < deadline:
                if guest._routing.contains(third.id):
                    break
                await asyncio.sleep(0.5)
            assert guest._routing.contains(third.id), \
                "the third node was never learned"
        finally:
            await third.stop()
            await guest.stop()
            await host.stop()
