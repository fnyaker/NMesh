"""
An answer we cannot match is only an accusation when we can say whose it is.

`RELEASE_DATA` carries one slice of a release, and an unmatched one used to be
charged as a protocol violation against the link it arrived on. Two things make
that wrong, and together they make it dangerous:

* the message is **routable**, so the link is usually a relay, and `src_id` on
  a routed packet is not authenticated — the charge landed on whoever carried
  it rather than on whoever sent it;
* the common unmatched answer is not an attack. It is a slice that arrives
  after `_pull_slice` timed out and popped its key, which over a slow multi-hop
  path — exactly the path a mesh update takes — happens once per slice. A
  hundred-slice download handed an honest relay a hundred violations, which is
  past the *suspect* threshold: its traffic is then dropped, its link cut, and
  the reconnect book refuses to chase it. Two nodes could take each other off
  the mesh by updating from each other.

So it is charged only where it can be attributed, and dropped in silence
everywhere else — which is what every other "an answer to a question we did not
ask" handler in the node already does.
"""
import time

import pytest

from src.node import MeshNode, NodeID, RELEASE_DATA, _Peer, _RELEASE_ID_LEN
from src.packet import Packet
from src.reputation import OK
from tests.conftest import FakeTransport, make_manager


SOURCE = NodeID(b"\x11" * 20)
RELAY = NodeID(b"\x22" * 20)


def _node() -> MeshNode:
    node = MeshNode(transport_manager=make_manager())
    node._running = True
    return node


def _link(node: MeshNode, who: NodeID, *, relay: bool = False) -> _Peer:
    peer = _Peer(FakeTransport(), is_client_side=True)
    peer.authenticated_id = who
    peer.session = object()
    peer.relay_only = relay
    node._peers.append(peer)
    return peer


def _slice(source: NodeID = SOURCE) -> Packet:
    body = (b"\x07" * _RELEASE_ID_LEN) + (0).to_bytes(4, "big") + b"payload"
    return Packet.create(RELEASE_DATA, source.raw, NodeID(b"\x00" * 20).raw, body)


class TestWhoIsCharged:
    async def test_a_relay_carrying_a_late_slice_is_not_an_offender(self):
        node = _node()
        relay = _link(node, RELAY)
        await node._handle_release_data(relay, _slice())
        assert relay._malformed == 0
        assert node._reputation.direct_standing(RELAY) == OK

    async def test_a_hundred_late_slices_still_leave_it_alone(self):
        """The number that used to take an honest relay past *suspect*."""
        node = _node()
        relay = _link(node, RELAY)
        for _ in range(100):
            await node._handle_release_data(relay, _slice())
        assert node._reputation.direct_standing(RELAY) == OK
        assert relay in node._peers

    async def test_a_relay_only_link_is_never_charged(self):
        node = _node()
        peer = _link(node, SOURCE, relay=True)
        await node._handle_release_data(peer, _slice())
        assert peer._malformed == 0

    async def test_the_node_claiming_to_be_the_source_is_still_charged(self):
        """Where `src_id` is checked against the link, the attribution holds —
        and the denial this guards against is real: without it any peer could
        race the real answer with rubbish and make every download of a release
        fail, for ever, at one packet per slice."""
        node = _node()
        peer = _link(node, SOURCE)
        await node._handle_release_data(peer, _slice())
        assert peer._malformed == 1

    async def test_a_slice_we_asked_for_is_delivered_and_charges_nobody(self):
        import asyncio
        node = _node()
        peer = _link(node, SOURCE)
        future = asyncio.get_event_loop().create_future()
        node._pending_slices[(SOURCE, (b"\x07" * _RELEASE_ID_LEN).hex(), 0)] = future
        await node._handle_release_data(peer, _slice())
        assert future.done() and future.result() == b"payload"
        assert peer._malformed == 0
