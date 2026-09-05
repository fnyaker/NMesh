"""
Telling somebody what their join actually did.

`join` opens the link and returns; the handshake it starts finishes, or fails,
some time afterwards. The console reported that return value as success — so a
node refused for every reason there is (a code already spent, an address that
answers as somebody else, a far end that never replied) was told "Joined", and
then sat there with nothing connected and nothing to read. Every one of those
looks like a broken network to the person holding the ticket.

The worst of them was the spent code: `_handle_invite_ack` read the rejection
byte the far end had deliberately sent and returned without recording it, so the
one failure a person can actually fix was the one nothing anywhere mentioned.
"""
import asyncio

import pytest

from src.node import MeshNode, INVITE_ACK, _ACK_REJECTED
from src.node_id import NodeID
from src.packet import Packet
from src.transport_manager import TransportManager
from tests.conftest import FakeServer, FakeTransport


class _RefusingTransport(FakeTransport):
    async def connect(self, address: str) -> None:
        raise ConnectionRefusedError("nothing is listening")


def _manager(transport_cls=FakeTransport) -> TransportManager:
    manager = TransportManager()
    manager.register("fake", transport_cls, FakeServer)
    return manager


async def _wait_for_peer(node, timeout: float = 1.0):
    deadline = asyncio.get_event_loop().time() + timeout
    while not node._peers:
        if asyncio.get_event_loop().time() >= deadline:
            raise TimeoutError("the join opened no link")
        await asyncio.sleep(0)
    return node._peers[-1]


class TestWhatAJoinReports:
    async def test_an_address_with_nothing_on_it_says_so(self):
        node = MeshNode(transport_manager=_manager(_RefusingTransport))
        result = await node.console_join("fake://h:1", "code")
        await node.stop()
        assert result["ok"] is False
        assert result["reason"] == "that address could not be reached"

    async def test_a_refused_code_is_named_rather_than_timed_out(self):
        """The most common join failure by far, and the one that was thrown
        away. Waiting it out would report a timeout, which sends the reader off
        to check their network instead of their ticket."""
        node = MeshNode(transport_manager=_manager())
        task = asyncio.create_task(
            node.console_join("fake://h:1", "code", timeout=5.0))
        peer = await _wait_for_peer(node)
        peer.invite_sent = True
        peer.transport.inject(Packet.create(INVITE_ACK, b"\x02" * 20,
                                            node.id.raw, bytes([_ACK_REJECTED])))
        result = await task
        await node.stop()
        assert result["ok"] is False
        assert result["reason"] == "the invitation was refused"
        assert "one use" in result["detail"]

    async def test_an_address_that_answers_and_proves_nothing_is_not_success(self):
        node = MeshNode(transport_manager=_manager())
        result = await node.console_join("fake://h:1", "code", timeout=0.2)
        await node.stop()
        assert result["ok"] is False
        assert result["reason"] == "the handshake was never finished"

    async def test_a_session_is_reported_with_the_identity_it_reached(self):
        node = MeshNode(transport_manager=_manager())
        target = NodeID(b"\x33" * 20)
        task = asyncio.create_task(
            node.console_join("fake://h:1", "code", timeout=5.0))
        peer = await _wait_for_peer(node)
        peer.authenticated_id = target
        peer.session = object()
        result = await task
        await node.stop()
        assert result == {"ok": True, "node": target.raw.hex()}


class TestAJoinThatFailedLeavesNothingBehind:
    async def test_the_link_is_torn_down(self):
        """A half-open join is not a link, it is a leak — and it is exactly
        what the node would go on to count under "connected"."""
        node = MeshNode(transport_manager=_manager())
        await node.console_join("fake://h:1", "code", timeout=0.2)
        assert node._peers == []
        await node.stop()

    async def test_a_link_that_authenticated_is_kept(self):
        node = MeshNode(transport_manager=_manager())
        task = asyncio.create_task(
            node.console_join("fake://h:1", "code", timeout=5.0))
        peer = await _wait_for_peer(node)
        peer.authenticated_id = NodeID(b"\x33" * 20)
        peer.session = object()
        await task
        assert peer in node._peers
        await node.stop()


class TestTheRejectionByteIsKept:
    async def test_an_accepted_invite_does_not_look_refused(self):
        node = MeshNode(transport_manager=_manager())
        task = asyncio.create_task(
            node.console_join("fake://h:1", "code", timeout=0.3))
        peer = await _wait_for_peer(node)
        await task
        assert peer.invite_refused is False
        await node.stop()
