"""
Pseudos on the mesh: the gossip plane, and what happens to a peer that lies.

The claim itself is proved in ``test_pseudo_dir.py``. What is proved here is the
node's behaviour around it — that the epidemic stops, that a rename overtakes the
old name, that our own name is never the network's to change, and that a peer
sending something a correct node would never send is counted and eventually cut.
"""
import os

import pytest

from src.crypto import CryptoIdentity
from src.node import (MeshNode, PSEUDO_ANNOUNCE, _MAX_MALFORMED,
                      _PSEUDO_RATE_MAX, _PSEUDO_SYNC_MAX, _DIRECT_TYPES)
from src.node_id import NodeID
from src.packet import Packet
from src.pseudo import MAX_PSEUDO, PseudoError
from src.pseudo_dir import build_claim, parse_claim, _HDR, _signing_input, CLAIM_VERSION
from tests.conftest import make_manager, settle


def _claim(ident, pseudo="alice", ts=1000):
    return build_claim(pseudo, ident.dsa_public_key, ident.sign, ts)


class _FakePeer:
    def __init__(self):
        self.authenticated_id = NodeID(os.urandom(20))
        self.session = object()
        self.sent = []
        self.relay_only = False
        self._malformed = 0
        self.stopped = False
        self.tarpit_until = 0.0    # served, like any peer nothing is held against

    def note_abuse(self) -> bool:
        self._malformed += 1
        return self._malformed > _MAX_MALFORMED

    async def send(self, pkt):
        self.sent.append(pkt)

    async def stop(self):
        self.stopped = True


class _FakeTransport:
    def __init__(self):
        self.closed = False

    async def close(self):
        self.closed = True


async def _node(pseudo=None):
    return MeshNode(transport_manager=make_manager(), pseudo=pseudo)


def _announce(peer, raw):
    return Packet.create(PSEUDO_ANNOUNCE, peer.authenticated_id.raw,
                         b"\xff" * 20, raw)


class TestOwnPseudo:
    async def test_set_and_read(self):
        node = await _node()
        try:
            assert node.pseudo == ""
            assert node.set_pseudo("  Alice   Ada ") == "Alice Ada"
            assert node.pseudo == "Alice Ada"
            assert node.pseudo_of(node.id) == "Alice Ada"
        finally:
            await node.stop()

    async def test_configured_at_construction(self):
        node = await _node("bob")
        try:
            assert node.pseudo == "bob"
        finally:
            await node.stop()

    async def test_a_name_the_network_would_refuse_is_refused_here(self):
        for bad in ("x" * (MAX_PSEUDO + 1), "bo​b", "ali‮ce"):
            with pytest.raises(PseudoError):
                await _node(bad)

    async def test_clearing_the_pseudo(self):
        node = await _node("bob")
        try:
            assert node.set_pseudo("") == ""
            assert node.pseudo == "" and node.pseudo_of(node.id) == ""
        finally:
            await node.stop()

    async def test_rename_moves_the_timestamp_forward(self):
        # Two renames inside one second must still be distinguishable, or peers
        # keep the first and the second silently never lands.
        node = await _node("one")
        try:
            first = node._pseudo_book.ts_of(node.id.raw)
            node.set_pseudo("two")
            second = node._pseudo_book.ts_of(node.id.raw)
            node.set_pseudo("three")
            third = node._pseudo_book.ts_of(node.id.raw)
            assert first < second < third
            assert node.pseudo_of(node.id) == "three"
        finally:
            await node.stop()

    async def test_nobody_else_can_rename_us(self):
        # A claim about our id, signed by someone else, does not verify: the id
        # in a claim is derived from the key that signed it.
        node = await _node("mine")
        try:
            attacker = CryptoIdentity()
            peer = _FakePeer()
            await node._handle_pseudo_announce(peer, _announce(peer, _claim(attacker, "theirs")))
            await settle(node)
            assert node.pseudo_of(node.id) == "mine"
        finally:
            await node.stop()


class TestGossip:
    async def test_a_new_claim_is_learned_and_passed_on(self):
        node = await _node()
        author = CryptoIdentity()
        try:
            listener = _FakePeer()
            node._peers.append(listener)
            sender = _FakePeer()
            node._peers.append(sender)
            raw = _claim(author, "carol")
            await node._handle_pseudo_announce(sender, _announce(sender, raw))
            await settle(node)
            assert node.pseudo_of(NodeID.from_public_key(author.dsa_public_key)) == "carol"
            # Re-gossiped to everyone but the peer it came from.
            assert [p.payload for p in listener.sent] == [raw]
            assert sender.sent == []
        finally:
            await node.stop()

    async def test_the_epidemic_terminates(self):
        # A claim we already hold changes nothing, so it is not passed on — which
        # is the only thing stopping it circulating forever.
        node = await _node()
        author = CryptoIdentity()
        try:
            listener = _FakePeer()
            node._peers.append(listener)
            sender = _FakePeer()
            raw = _claim(author, "carol")
            for _ in range(5):
                await node._handle_pseudo_announce(sender, _announce(sender, raw))
                await settle(node)
            assert len(listener.sent) == 1
        finally:
            await node.stop()

    async def test_a_rename_does_travel_on(self):
        node = await _node()
        author = CryptoIdentity()
        try:
            listener = _FakePeer()
            node._peers.append(listener)
            sender = _FakePeer()
            await node._handle_pseudo_announce(sender, _announce(sender, _claim(author, "one", 10)))
            await settle(node)
            await node._handle_pseudo_announce(sender, _announce(sender, _claim(author, "two", 20)))
            await settle(node)
            assert len(listener.sent) == 2
            assert node.pseudo_of(NodeID.from_public_key(author.dsa_public_key)) == "two"
        finally:
            await node.stop()

    async def test_a_replayed_old_claim_does_not_roll_a_name_back(self):
        node = await _node()
        author = CryptoIdentity()
        try:
            sender = _FakePeer()
            old = _claim(author, "one", 10)
            await node._handle_pseudo_announce(sender, _announce(sender, _claim(author, "two", 20)))
            await settle(node)
            await node._handle_pseudo_announce(sender, _announce(sender, old))
            assert node.pseudo_of(NodeID.from_public_key(author.dsa_public_key)) == "two"
        finally:
            await node.stop()

    async def test_sync_to_a_new_peer_leads_with_our_own_name(self):
        node = await _node("mine")
        try:
            for _ in range(3):
                claim = _claim(CryptoIdentity(), "other")
                node._pseudo_book.offer(parse_claim(claim, node._identity.verify), claim)
            peer = _FakePeer()
            await node._sync_pseudos_to(peer)
            assert peer.sent[0].payload == node._pseudo_claim
            assert len(peer.sent) == 4
        finally:
            await node.stop()

    async def test_sync_is_bounded(self):
        node = await _node()
        try:
            for i in range(_PSEUDO_SYNC_MAX + 20):
                claim = _claim(CryptoIdentity(), f"p{i}")
                node._pseudo_book.offer(parse_claim(claim, node._identity.verify), claim)
            peer = _FakePeer()
            await node._sync_pseudos_to(peer)
            assert len(peer.sent) == _PSEUDO_SYNC_MAX
        finally:
            await node.stop()

    async def test_announce_is_a_direct_type(self):
        # It is re-stamped at every hop, so the receiving gate must require the
        # sender to be the peer it came from — that is what a direct type means.
        assert PSEUDO_ANNOUNCE in _DIRECT_TYPES

    async def test_rate_limited_per_link(self):
        node = await _node()
        try:
            peer = _FakePeer()
            allowed = sum(node._pseudo_allowed(peer)
                          for _ in range(_PSEUDO_RATE_MAX + 20))
            assert allowed == _PSEUDO_RATE_MAX
        finally:
            await node.stop()


class TestHostilePeers:
    async def _feed(self, node, peer, payload):
        await node._handle_pseudo_announce(peer, _announce(peer, payload))
        await settle(node)

    async def test_garbage_is_charged_to_the_sender(self):
        node = await _node()
        try:
            peer = _FakePeer()
            for junk in (b"", os.urandom(50), b"\x02" + b"\xff" * 40):
                await self._feed(node, peer, junk)
            assert peer._malformed == 3
            assert len(node._pseudo_book) == 0
        finally:
            await node.stop()

    async def test_a_forged_signature_is_charged(self):
        node = await _node()
        try:
            peer = _FakePeer()
            raw = bytearray(_claim(CryptoIdentity(), "carol"))
            raw[-1] ^= 0xFF
            await self._feed(node, peer, bytes(raw))
            assert peer._malformed == 1 and len(node._pseudo_book) == 0
        finally:
            await node.stop()

    async def test_a_signed_but_non_canonical_name_is_charged(self):
        # The signature is genuine; the name is not in the one form the protocol
        # allows. That is not sloppiness, it is a lookalike attempt.
        node = await _node()
        try:
            ident = CryptoIdentity()
            pseudo = "ali‮ce"
            node_id = NodeID.from_public_key(ident.dsa_public_key).raw
            encoded = pseudo.encode("utf-8")
            sig = ident.sign(_signing_input(node_id, pseudo, 7))
            forged = (_HDR.pack(CLAIM_VERSION, 7, len(ident.dsa_public_key),
                                len(encoded), len(sig))
                      + ident.dsa_public_key + encoded + sig)
            peer = _FakePeer()
            await self._feed(node, peer, forged)
            assert peer._malformed == 1 and len(node._pseudo_book) == 0
        finally:
            await node.stop()

    async def test_a_persistent_liar_is_cut(self):
        node = await _node()
        try:
            peer = _FakePeer()
            peer.transport = _FakeTransport()
            node._peers.append(peer)
            for _ in range(_MAX_MALFORMED + 2):
                await self._feed(node, peer, os.urandom(50))
            # The reap runs detached (we are inside the peer's own receive task),
            # so let it land before looking.
            import asyncio
            for _ in range(5):
                await asyncio.sleep(0)
            assert peer not in node._peers
            assert peer.transport.closed
        finally:
            await node.stop()

    async def test_an_honest_peer_is_never_charged(self):
        node = await _node()
        try:
            peer = _FakePeer()
            for i in range(5):
                await self._feed(node, peer, _claim(CryptoIdentity(), f"p{i}"))
            assert peer._malformed == 0 and len(node._pseudo_book) == 5
        finally:
            await node.stop()


class TestSearch:
    async def test_partial_search_ranks_best_first(self):
        node = await _node()
        try:
            for name in ("Alice Ada", "alicia", "Bob"):
                raw = _claim(CryptoIdentity(), name)
                node._pseudo_book.offer(parse_claim(raw, node._identity.verify), raw)
            names = [h["pseudo"] for h in node.find_pseudo("ali")]
            assert set(names) == {"Alice Ada", "alicia"}
            assert node.find_pseudo("bo")[0]["pseudo"] == "Bob"
            assert node.find_pseudo("zz") == []
        finally:
            await node.stop()

    async def test_search_finds_by_a_word_inside_the_name(self):
        node = await _node("Alice Ada")
        try:
            assert node.find_pseudo("ada")[0]["id"] == node.id.raw.hex()
        finally:
            await node.stop()

    async def test_results_are_bounded(self):
        node = await _node()
        try:
            from src.node import _PSEUDO_SEARCH_MAX
            for i in range(_PSEUDO_SEARCH_MAX + 20):
                raw = _claim(CryptoIdentity(), f"alice{i}")
                node._pseudo_book.offer(parse_claim(raw, node._identity.verify), raw)
            assert len(node.find_pseudo("alice", limit=10_000)) == _PSEUDO_SEARCH_MAX
        finally:
            await node.stop()

    async def test_every_result_carries_the_id(self):
        # The name is a label; the id is the identity, and it is never optional.
        node = await _node("alice")
        try:
            assert all(len(h["id"]) == 40 for h in node.find_pseudo("ali"))
        finally:
            await node.stop()
