"""
The address that turns out to be us, and the one that turns out to be somebody
else.

A node dials addresses it learned from gossip, and an entry can name the wrong
machine — including this one. Nothing about that is hostile, which is exactly
why it went unnoticed: our own store holds our own id as a root, so a node that
reached itself *completed* the handshake, counted itself among the nodes it was
connected to, and paid two ML-DSA verifications and ~27 kB for the privilege. A
real trace showed it twice in two seconds.

What is proved here: both halves of the handshake refuse our own identity, and a
dial that reaches the wrong node says so — instead of "no-answer", which is what
an address that connected every single time used to be recorded as — and stops
being dialled, because the entry is wrong rather than slow.
"""
import asyncio
import os

import pytest

from src.node import (MeshNode, HANDSHAKE_ACK, _encode_handshake_ack)
from src.node_id import NodeID
from src.packet import Packet
from tests.conftest import make_manager, make_node


def _node() -> MeshNode:
    return MeshNode(transport_manager=make_manager())


class TestOurOwnIdentityIsRefused:
    """Reaching ourselves is not a link. It must fail, and be named."""

    async def test_a_handshake_presenting_our_key_is_refused(self):
        """The server half: our own HANDSHAKE, played back to us."""
        node, fake = await make_node()
        peer = node._peers[0]
        challenge = os.urandom(32)
        peer.received_challenge = challenge   # what we sign over
        peer.pending_challenge = challenge    # what we verify against
        await node.initiate_handshake(peer)
        fake.inject(fake.sent[0])
        await asyncio.sleep(0.05)
        await node.stop()
        assert [row["reason"] for row in node.handshake_refusals()] == [
            "the identity presented is our own"]
        assert not any(p.type == HANDSHAKE_ACK for p in fake.sent)

    async def test_an_ack_presenting_our_key_is_refused(self):
        """The client half. Refusing only on the server side would still leave
        this side holding a link whose authenticated id is our own, and every
        count of "nodes connected" would believe it."""
        node, fake = await make_node()
        peer = node._peers[0]
        challenge = os.urandom(32)
        peer.received_challenge = challenge
        peer.pending_kem_secret = b"\x00" * 32      # something was in flight
        ciphertext = b"\x11" * 32
        dsa_pub = node._identity.dsa_public_key
        signature = node._identity.sign(challenge + ciphertext + dsa_pub)
        payload = _encode_handshake_ack(ciphertext, dsa_pub, [], None, signature)
        fake.inject(Packet.create(HANDSHAKE_ACK, node.id.raw, node.id.raw,
                                  payload))
        await asyncio.sleep(0.05)
        await node.stop()
        assert [row["reason"] for row in node.handshake_refusals()] == [
            "the identity presented is our own"]
        assert peer.session is None
        assert peer.authenticated_id is None

    async def test_we_never_count_ourselves_as_a_connected_node(self):
        """The reason the guard is worth its lines: the refusal above is what
        keeps the number under the word "nodes" true."""
        node, fake = await make_node()
        peer = node._peers[0]
        challenge = os.urandom(32)
        peer.received_challenge = challenge
        peer.pending_challenge = challenge
        await node.initiate_handshake(peer)
        fake.inject(fake.sent[0])
        await asyncio.sleep(0.05)
        await node.stop()
        assert node._authenticated_peers() == []
        assert not node._routing.contains(node.id)


class TestADialThatReachesTheWrongNode:
    """`_wait_for_peer_authenticated` says only yes or no, so "it answered as
    someone else" and "nobody answered" arrived here as the same word."""

    async def _dial_answering_as(self, node: MeshNode, target: NodeID,
                                 answered: NodeID, uri: str = "fake://h:1"):
        async def answered_elsewhere(peer, want, timeout):
            peer.answered_as = answered
            return False
        node._wait_for_peer_authenticated = answered_elsewhere
        result = await node._dial_uri(target, uri, 0.5)
        return result, (node._dial_log.get(target.raw.hex()) or {}).get(uri)

    async def test_it_is_recorded_as_the_wrong_node_not_as_no_answer(self):
        node = _node()
        target, other = NodeID(b"\x22" * 20), NodeID(b"\x33" * 20)
        node._routing.add(target, ["fake://h:1"])
        result, row = await self._dial_answering_as(node, target, other)
        await node.stop()
        assert result is None
        assert row["outcome"] == "wrong node"
        assert other.raw.hex() in row["detail"]

    async def test_an_address_that_is_us_says_so_in_those_words(self):
        node = _node()
        target = NodeID(b"\x22" * 20)
        node._routing.add(target, ["fake://h:1"])
        _, row = await self._dial_answering_as(node, target, node.id)
        await node.stop()
        assert row["outcome"] == "wrong node"
        assert row["detail"] == "this address is this node itself"

    async def test_the_wrong_address_stops_being_dialled(self):
        """Left in the entry it buys a whole post-quantum handshake per pass to
        learn the same thing."""
        node = _node()
        target, other = NodeID(b"\x22" * 20), NodeID(b"\x33" * 20)
        node._routing.add(target, ["fake://h:1", "fake://good:2"])
        await self._dial_answering_as(node, target, other)
        await node.stop()
        assert node._routing.get(target).addresses == ["fake://good:2"]

    async def test_the_node_itself_is_kept(self):
        """One address was wrong. The node is still real, its other addresses
        may be good, and a punch can still reach it."""
        node = _node()
        target, other = NodeID(b"\x22" * 20), NodeID(b"\x33" * 20)
        node._routing.add(target, ["fake://h:1"])
        await self._dial_answering_as(node, target, other)
        await node.stop()
        assert node._routing.contains(target)

    async def test_a_silent_address_is_still_no_answer(self):
        """The old word still fits the old case: nothing proved an identity."""
        node = _node()
        target = NodeID(b"\x22" * 20)
        node._routing.add(target, ["fake://h:1"])

        async def never(peer, want, timeout):
            return False
        node._wait_for_peer_authenticated = never
        await node._dial_uri(target, "fake://h:1", 0.5)
        await node.stop()
        row = node._dial_log[target.raw.hex()]["fake://h:1"]
        assert row["outcome"] == "no-answer"
        assert node._routing.get(target).addresses == ["fake://h:1"]


class TestForgettingOneAddress:
    def test_the_entry_keeps_its_place_in_the_recency_order(self):
        """`add` builds a fresh NodeEntry, whose `last_seen` defaults to now —
        re-adding would report a node we just failed to reach as the most
        recently seen one."""
        node = _node()
        target = NodeID(b"\x22" * 20)
        node._routing.add(target, ["fake://a:1", "fake://b:2"])
        before = node._routing.get(target).last_seen
        assert node._routing.drop_address(target, "fake://a:1") is True
        assert node._routing.get(target).last_seen == before

    def test_an_address_we_never_held_changes_nothing(self):
        node = _node()
        target = NodeID(b"\x22" * 20)
        node._routing.add(target, ["fake://a:1"])
        assert node._routing.drop_address(target, "fake://z:9") is False
        assert node._routing.get(target).addresses == ["fake://a:1"]

    def test_an_unknown_node_is_not_invented(self):
        node = _node()
        assert node._routing.drop_address(NodeID(b"\x44" * 20), "fake://a:1") is False
