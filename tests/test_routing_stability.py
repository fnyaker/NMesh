"""
Routing stability — the three faults that made relayed paths flaky.

1. **FOUND_NODE outgrew the packet.** A post-quantum chain to a root is ~15 KB,
   so packing Kademlia's k=20 entries blew the 60 000-byte cap: ``Packet.create``
   raised inside the handler, the receive loop swallowed it, and *every* lookup
   in a mesh holding more than four certified nodes timed out with no trace.
2. **Route acquisition ran inside the receive loop.** Forwarding a packet with
   no live relay awaited a lookup/dial/punch there, freezing the link for the
   whole budget — and the FOUND_NODE that lookup waited for often had to come
   back over that very link, so it could only ever time out.
3. **Replies were routed by a fresh XOR guess.** The path the request had just
   proven was thrown away, so an answer could walk off into a dead end.
4. **``stop()`` could wait forever** on a cancelled receive task that never woke
   up — roughly one teardown in three once a node had several peers.
"""
import asyncio
import os
import time

import pytest

from src.cert import Certificate
from src.crypto import CryptoIdentity, SessionKey
from src.cert import FINGERPRINT_LEN
from src.node import (
    MeshNode, DATA, ECHO_REPLY, ECHO_REQUEST, FIND_NODE, FOUND_NODE,
    _CERT_HINT_MAX, _CERT_LEN, _CERT_REF, _EntryPacker, _HINTS_OK,
    _HINT_PEERS_MAX, _POOL_COUNT, _decode_cert_hints, _decode_entries,
    _encode_cert_hints, _encode_entries,
    _FOUND_NODE_MAX_BYTES, _MAX_DEFERRED_ROUTES, _PEER_STOP_TIMEOUT,
    _ROUTE_HINT_MAX, _ROUTE_HINT_TTL, _QID_LEN,
)
from src.node_id import NodeID
from src.packet import Packet
from src import routing as routing_mod
from src.routing import NodeEntry
from tests.conftest import FakeTransport, make_manager


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

async def _attach(node: MeshNode, node_id: NodeID) -> tuple:
    """Attach a fake link that already looks authenticated as ``node_id``."""
    fake = FakeTransport()
    peer = await node._inject_peer(fake)
    peer.authenticated_id = node_id
    peer.session = SessionKey(os.urandom(32))
    return peer, fake


def _certified_routing_table(node: MeshNode, count: int) -> CryptoIdentity:
    """Fill ``node``'s routing table with ``count`` nodes certified by a shared
    root — the state a node reaches after a while on a real mesh, and the state
    that used to make its FOUND_NODE unsendable."""
    root = CryptoIdentity()
    root_id = NodeID.from_public_key(root.dsa_public_key)
    node._cert_store.add(root.self_signed_cert())
    node._cert_store.add_root(root_id)
    for i in range(count):
        leaf = CryptoIdentity()
        leaf_id = NodeID.from_public_key(leaf.dsa_public_key)
        node._cert_store.add(root.issue_cert(leaf_id, leaf.dsa_public_key))
        node._routing.add(leaf_id, [f"tcp://10.0.0.{i + 1}:9000"],
                          leaf.dsa_public_key)
    return root


# ---------------------------------------------------------------------------
# 1 — FOUND_NODE always fits in a packet
# ---------------------------------------------------------------------------

class TestFoundNodeFitsThePacket:
    async def test_reply_is_sent_with_a_large_certified_table(self):
        """The regression: 20 certified nodes made the reply ~292 KB, so no
        FOUND_NODE was ever emitted and the lookup died silently."""
        node = MeshNode(transport_manager=make_manager())
        _certified_routing_table(node, 20)
        peer, fake = await _attach(node, NodeID(os.urandom(20)))

        query_id = os.urandom(_QID_LEN)
        await node._handle_find_node(
            peer, Packet.create(FIND_NODE, peer.authenticated_id.raw,
                                node.id.raw, os.urandom(20) + query_id))

        reply = next(p for p in fake.sent if p.type == FOUND_NODE)
        assert len(reply.payload) <= _FOUND_NODE_MAX_BYTES + _QID_LEN
        entries, _used = _decode_entries(reply.payload[_QID_LEN:])
        assert entries, "a reply must still carry usable entries"
        for entry in entries:
            assert node._cert_store.verify_chain(entry.cert_chain) is not None
        await node.stop()

    async def test_chain_less_entries_do_not_crowd_out_usable_ones(self):
        """Only entries with a chain to a root are usable — the receiver drops
        the rest. Scanning exactly k left the reply empty whenever the k nearest
        happened to be chain-less, which is most of a table learned by gossip."""
        node = MeshNode(transport_manager=make_manager())
        _certified_routing_table(node, 4)
        for i in range(40):        # no cert chain for any of these
            stranger = CryptoIdentity()
            node._routing.add(NodeID.from_public_key(stranger.dsa_public_key),
                              [f"tcp://10.1.0.{(i % 250) + 1}:9000"],
                              stranger.dsa_public_key)
        peer, fake = await _attach(node, NodeID(os.urandom(20)))

        await node._handle_find_node(
            peer, Packet.create(FIND_NODE, peer.authenticated_id.raw,
                                node.id.raw, os.urandom(20) + os.urandom(_QID_LEN)))

        entries, _used = _decode_entries(
            next(p for p in fake.sent if p.type == FOUND_NODE).payload[_QID_LEN:])
        assert entries and all(e.cert_chain for e in entries)
        await node.stop()


class TestEntryPacker:
    def _entry(self, root: CryptoIdentity, index: int) -> NodeEntry:
        leaf = CryptoIdentity()
        leaf_id = NodeID.from_public_key(leaf.dsa_public_key)
        chain = [root.issue_cert(leaf_id, leaf.dsa_public_key),
                 root.self_signed_cert()]
        return NodeEntry(leaf_id, [f"tcp://10.0.0.{index + 1}:9000"],
                         leaf.dsa_public_key, chain)

    def test_shared_certs_are_sent_once(self):
        """Every chain ends on the same root; repeating a ~7 KB certificate per
        entry was half the packet."""
        root = CryptoIdentity()
        entries = [self._entry(root, i) for i in range(3)]
        pooled = len(_encode_entries(entries))
        alone = sum(len(_encode_entries([e])) for e in entries)
        assert pooled < alone
        assert len(_decode_entries(_encode_entries(entries))[0]) == 3

    def test_budget_is_never_exceeded(self):
        root = CryptoIdentity()
        packer = _EntryPacker(20_000)
        added = 0
        for i in range(10):
            if not packer.add(self._entry(root, i)):
                break
            added += 1
        assert 0 < added < 10
        assert len(packer.encode()) <= 20_000

    def test_round_trip_preserves_ids_addresses_and_chains(self):
        root = CryptoIdentity()
        entries = [self._entry(root, i) for i in range(2)]
        decoded, _used = _decode_entries(_encode_entries(entries))
        assert [e.node_id for e in decoded] == [e.node_id for e in entries]
        assert [e.addresses for e in decoded] == [e.addresses for e in entries]
        assert [len(e.cert_chain) for e in decoded] == [2, 2]


class TestFoundNodeDecoderIsHostileProof:
    """Reject by default: no hostile body may crash the decoder or buy us
    unbounded certificate verification."""

    def test_random_bytes_never_crash(self):
        for _ in range(300):
            try:
                _decode_entries(os.urandom(int.from_bytes(os.urandom(1), "big")))
            except ValueError:
                pass

    def test_oversized_pool_is_rejected(self):
        with pytest.raises(ValueError):
            _decode_entries((10_000).to_bytes(2, "big"))

    def test_chain_index_out_of_range_is_rejected(self):
        body = (0).to_bytes(2, "big") + bytes([1])          # empty pool, 1 entry
        body += os.urandom(20) + bytes([0, 1]) + (0).to_bytes(2, "big")
        with pytest.raises(ValueError):
            _decode_entries(body)

    def test_entry_count_above_k_is_rejected(self):
        with pytest.raises(ValueError):
            _decode_entries((0).to_bytes(2, "big") + bytes([21]))


# ---------------------------------------------------------------------------
# 2 — route acquisition never runs in a receive loop
# ---------------------------------------------------------------------------

class TestForwardingNeverBlocksTheLink:
    async def test_unroutable_packet_returns_immediately(self):
        """A peer that sends packets for unreachable destinations used to freeze
        the link it sent them on for the whole on-demand budget."""
        node = MeshNode(transport_manager=make_manager())
        node._running = True
        peer, _ = await _attach(node, NodeID(os.urandom(20)))

        async def _slow_acquire(target, timeout=None):
            await asyncio.sleep(30)
            return None
        node._ensure_route_to = _slow_acquire

        packet = Packet.create(ECHO_REQUEST, peer.authenticated_id.raw,
                               os.urandom(20), os.urandom(_QID_LEN))
        started = time.monotonic()
        await node._handle_packet(peer, packet)
        assert time.monotonic() - started < 1.0
        assert node._deferred_routes, "acquisition must still be attempted"
        await node.stop()

    async def test_deferred_acquisitions_are_bounded(self):
        node = MeshNode(transport_manager=make_manager())
        node._running = True
        peer, _ = await _attach(node, NodeID(os.urandom(20)))

        async def _slow_acquire(target, timeout=None):
            await asyncio.sleep(30)
            return None
        node._ensure_route_to = _slow_acquire

        for _ in range(_MAX_DEFERRED_ROUTES * 3):
            await node._handle_packet(
                peer, Packet.create(ECHO_REQUEST, peer.authenticated_id.raw,
                                    os.urandom(20), os.urandom(_QID_LEN)))
        assert len(node._deferred_routes) <= _MAX_DEFERRED_ROUTES
        await node.stop()

    async def test_deferred_send_happens_once_a_route_appears(self):
        """Deferring must not mean dropping: the packet goes out on the link the
        background acquisition produces."""
        node = MeshNode(transport_manager=make_manager())
        node._running = True
        ingress, _ = await _attach(node, NodeID(os.urandom(20)))
        target = NodeID(os.urandom(20))
        acquired: dict = {}

        async def _acquire(t, timeout=None):
            if t != target:
                return None
            peer, link = await _attach(node, target)
            acquired["link"] = link
            return peer
        node._ensure_route_to = _acquire

        # The only other peer is the one it came from, which is excluded as a
        # next hop, so the fast path has nothing and must defer.
        await node._forward_packet(
            ingress, Packet.create(DATA, ingress.authenticated_id.raw,
                                   target.raw, b"payload"))
        assert node._deferred_routes, "the fast path must have found no route"
        await asyncio.wait_for(
            asyncio.gather(*list(node._deferred_routes)), timeout=5.0)
        assert any(p.type == DATA for p in acquired["link"].sent)
        await node.stop()

    async def test_stop_cancels_pending_acquisitions(self):
        node = MeshNode(transport_manager=make_manager())
        node._running = True
        peer, _ = await _attach(node, NodeID(os.urandom(20)))

        async def _slow_acquire(target, timeout=None):
            await asyncio.sleep(30)
            return None
        node._ensure_route_to = _slow_acquire

        await node._handle_packet(
            peer, Packet.create(ECHO_REQUEST, peer.authenticated_id.raw,
                                os.urandom(20), os.urandom(_QID_LEN)))
        tasks = list(node._deferred_routes)
        await node.stop()
        assert all(t.done() for t in tasks)


# ---------------------------------------------------------------------------
# 3 — replies follow the path the request came in on
# ---------------------------------------------------------------------------

class TestReversePathRouting:
    async def test_ingress_link_beats_xor_proximity(self):
        node = MeshNode(transport_manager=make_manager())
        node._running = True
        source = NodeID(b"\x00" * 20)
        far, _ = await _attach(node, NodeID(b"\xff" * 20))     # far from source
        near, _ = await _attach(node, NodeID(b"\x01" + b"\x00" * 19))  # nearest

        assert node._route_candidates(source)[0] is near      # guess, before evidence
        await node._handle_packet(
            far, Packet.create(ECHO_REQUEST, source.raw, node.id.raw,
                               os.urandom(_QID_LEN)))
        assert node._route_candidates(source)[0] is far       # evidence wins
        await node.stop()

    async def test_reply_goes_back_the_way_the_request_came(self):
        node = MeshNode(transport_manager=make_manager())
        node._running = True
        source = NodeID(b"\x00" * 20)
        far, far_link = await _attach(node, NodeID(b"\xff" * 20))
        near, near_link = await _attach(node, NodeID(b"\x01" + b"\x00" * 19))

        await node._handle_packet(
            far, Packet.create(ECHO_REQUEST, source.raw, node.id.raw,
                               os.urandom(_QID_LEN)))
        assert any(p.type == ECHO_REPLY for p in far_link.sent)
        assert not near_link.sent
        await node.stop()

    async def test_direct_link_still_wins(self):
        """A hint may reorder relays; it must never displace the target itself."""
        node = MeshNode(transport_manager=make_manager())
        node._running = True
        source = NodeID(b"\x00" * 20)
        relay, _ = await _attach(node, NodeID(b"\xff" * 20))
        direct, _ = await _attach(node, source)

        node._route_hints[source] = (relay.authenticated_id, time.monotonic())
        assert node._route_candidates(source)[0] is direct
        await node.stop()

    async def test_hint_is_dropped_when_its_link_dies(self):
        node = MeshNode(transport_manager=make_manager())
        node._running = True
        source = NodeID(b"\x00" * 20)
        relay, _ = await _attach(node, NodeID(b"\xff" * 20))

        await node._handle_packet(
            relay, Packet.create(ECHO_REQUEST, source.raw, node.id.raw,
                                 os.urandom(_QID_LEN)))
        assert source in node._route_hints
        await node._reap_peer(relay)
        assert source not in node._route_hints
        await node.stop()

    async def test_stale_hint_is_ignored(self):
        node = MeshNode(transport_manager=make_manager())
        node._running = True
        source = NodeID(b"\x00" * 20)
        relay, _ = await _attach(node, NodeID(b"\xff" * 20))
        near, _ = await _attach(node, NodeID(b"\x01" + b"\x00" * 19))

        node._route_hints[source] = (relay.authenticated_id,
                                     time.monotonic() - _ROUTE_HINT_TTL - 1)
        assert node._route_candidates(source)[0] is near
        assert source not in node._route_hints
        await node.stop()

    async def test_unanswered_query_forgets_the_hint(self):
        """Self-repair: a hop that stops carrying traffic (or lies to attract it)
        costs one timed-out query, then it is gone."""
        node = MeshNode(transport_manager=make_manager())
        node._running = True
        target = NodeID(b"\x00" * 20)
        relay, _ = await _attach(node, NodeID(b"\xff" * 20))
        node._route_hints[target] = (relay.authenticated_id, time.monotonic())

        assert await node._kad_query_node(target, target, timeout=0.1) is None
        assert target not in node._route_hints
        await node.stop()

    async def test_hint_table_stays_bounded(self):
        node = MeshNode(transport_manager=make_manager())
        node._running = True
        relay, _ = await _attach(node, NodeID(b"\xff" * 20))
        for _ in range(_ROUTE_HINT_MAX * 2):
            await node._handle_packet(
                relay, Packet.create(ECHO_REQUEST, os.urandom(20), node.id.raw,
                                     os.urandom(_QID_LEN)))
        assert len(node._route_hints) <= _ROUTE_HINT_MAX
        await node.stop()

    async def test_no_hint_for_a_peer_we_reach_directly(self):
        node = MeshNode(transport_manager=make_manager())
        node._running = True
        source = NodeID(b"\x00" * 20)
        direct, _ = await _attach(node, source)

        await node._handle_packet(
            direct, Packet.create(ECHO_REQUEST, source.raw, node.id.raw,
                                  os.urandom(_QID_LEN)))
        assert source not in node._route_hints
        await node.stop()


# ---------------------------------------------------------------------------
# 4 — shutdown always finishes
# ---------------------------------------------------------------------------

class _DeafTransport(FakeTransport):
    """A link whose receive swallows one cancellation and then never wakes —
    the shape a task left in the "cancelling" state has. ``stop()`` used to wait
    on it forever."""

    def __init__(self) -> None:
        super().__init__()
        self.closed = False

    async def receive(self) -> Packet:
        try:
            await asyncio.Future()
        except asyncio.CancelledError:
            await asyncio.Future()
        raise AssertionError("unreachable")

    async def close(self) -> None:
        self.closed = True


class TestShutdownAlwaysFinishes:
    async def test_peer_stop_is_bounded(self):
        node = MeshNode(transport_manager=make_manager())
        transport = _DeafTransport()
        peer = await node._inject_peer(transport)

        started = time.monotonic()
        await peer.stop()
        assert time.monotonic() - started < _PEER_STOP_TIMEOUT + 2.0
        assert transport.closed, "the link must be torn down either way"

    async def test_node_stop_is_bounded_with_several_deaf_peers(self):
        node = MeshNode(transport_manager=make_manager())
        node._running = True
        transports = [_DeafTransport() for _ in range(5)]
        for transport in transports:
            await node._inject_peer(transport)

        started = time.monotonic()
        await node.stop()
        # Bounded per peer *and* shared: five links must not stack five waits.
        assert time.monotonic() - started < _PEER_STOP_TIMEOUT + 2.0
        assert all(t.closed for t in transports)
        assert not node._peers


# ---------------------------------------------------------------------------
# 5 — a lookup that reaches the id it is looking for must *learn* it
# ---------------------------------------------------------------------------

class TestResponderAnswersAboutItself:
    """Kademlia's reply classically excludes the responder. Here a querier often
    reaches a node only through a relay, so leaving ourselves out meant it never
    learned our entry: the FIND_NODE routed to the very id being looked up came
    back with that node's neighbours, the shortlist stopped improving, and the
    lookup gave up one hop short of an id it had actually reached. Seen as a
    flaky `_kademlia_lookup` returning False in a relay star."""

    async def test_reply_contains_the_responder_when_it_is_the_target(self):
        node = MeshNode(transport_manager=make_manager())
        _certified_routing_table(node, 4)
        peer, fake = await _attach(node, NodeID(os.urandom(20)))

        await node._handle_find_node(
            peer, Packet.create(FIND_NODE, peer.authenticated_id.raw,
                                node.id.raw, node.id.raw + os.urandom(_QID_LEN)))

        entries, _used = _decode_entries(
            next(p for p in fake.sent if p.type == FOUND_NODE).payload[_QID_LEN:])
        assert entries[0].node_id == node.id, "we are the closest entry to our own id"
        assert entries[0].cert_chain, "our entry must carry its chain or it is dropped"
        await node.stop()

    async def test_own_entry_is_ranked_by_distance_like_any_other(self):
        """No privilege: for a target next to another node, that node comes
        first — the budget is not spent on us just because we are answering."""
        node = MeshNode(transport_manager=make_manager())
        _certified_routing_table(node, 8)
        nearest = min((e.node_id for e in node._routing.all_entries()),
                      key=lambda n: n.distance(NodeID(b"\x00" * 20)))
        peer, fake = await _attach(node, NodeID(os.urandom(20)))

        await node._handle_find_node(
            peer, Packet.create(FIND_NODE, peer.authenticated_id.raw,
                                node.id.raw, nearest.raw + os.urandom(_QID_LEN)))

        entries, _used = _decode_entries(
            next(p for p in fake.sent if p.type == FOUND_NODE).payload[_QID_LEN:])
        assert entries[0].node_id == nearest
        await node.stop()

    async def test_own_entry_still_verifies_at_the_receiver(self):
        """The entry is only useful if the receiver accepts it: chain valid and
        its first certificate's subject *is* the node id (no relay forgery)."""
        node = MeshNode(transport_manager=make_manager())
        _certified_routing_table(node, 2)
        peer, fake = await _attach(node, NodeID(os.urandom(20)))

        await node._handle_find_node(
            peer, Packet.create(FIND_NODE, peer.authenticated_id.raw,
                                node.id.raw, node.id.raw + os.urandom(_QID_LEN)))

        own = next(e for e in _decode_entries(
            next(p for p in fake.sent if p.type == FOUND_NODE).payload[_QID_LEN:])[0]
            if e.node_id == node.id)
        assert node._cert_store.verify_chain(own.cert_chain) is not None
        assert own.cert_chain[0].subject_id == node.id
        await node.stop()


class TestLookupDoesNotInheritAnotherLookupsFailure:
    """`_kademlia_lookup` used to return an in-flight lookup's verdict as its
    own. That lookup started from another shortlist at another time, so a fresh
    caller could be told "not found" for an id it never actually asked about."""

    async def _finished_pending(self, node: MeshNode, target: NodeID):
        """A lookup for ``target`` that is already in flight and about to end
        without having learned it."""
        event = asyncio.Event()
        node._pending_lookups[target] = event

        async def finish():
            await asyncio.sleep(0)
            node._pending_lookups.pop(target, None)
            event.set()

        asyncio.ensure_future(finish())
        return event

    async def test_runs_its_own_lookup_after_piggybacking(self):
        node = MeshNode(transport_manager=make_manager())
        target = NodeID(os.urandom(20))
        await self._finished_pending(node, target)
        calls = []

        async def fake_kad_lookup(t, **kwargs):
            calls.append(t)
            node._routing.add(t, ["tcp://10.9.9.9:9000"], b"key")
            return [t]

        node.kad_lookup = fake_kad_lookup
        assert await node._kademlia_lookup(target, timeout=5.0) is True
        assert calls == [target], "the fresh caller must ask for itself"
        await node.stop()

    async def test_no_second_lookup_when_the_first_found_it(self):
        node = MeshNode(transport_manager=make_manager())
        target = NodeID(os.urandom(20))
        event = asyncio.Event()
        node._pending_lookups[target] = event

        async def finish():
            await asyncio.sleep(0)
            node._routing.add(target, ["tcp://10.9.9.9:9000"], b"key")
            node._pending_lookups.pop(target, None)
            event.set()

        asyncio.ensure_future(finish())
        calls = []
        node.kad_lookup = lambda *a, **k: calls.append(1)

        assert await node._kademlia_lookup(target, timeout=5.0) is True
        assert calls == [], "no redundant round when the answer is already there"
        await node.stop()

    async def test_gives_up_when_the_slot_was_taken_again(self):
        """Bounded: a caller never chains onto a second in-flight lookup, so two
        nodes cannot keep deferring to each other."""
        node = MeshNode(transport_manager=make_manager())
        target = NodeID(os.urandom(20))
        event = asyncio.Event()
        node._pending_lookups[target] = event

        async def finish():
            await asyncio.sleep(0)
            event.set()          # released, but the slot stays occupied

        asyncio.ensure_future(finish())
        calls = []
        node.kad_lookup = lambda *a, **k: calls.append(1)

        assert await node._kademlia_lookup(target, timeout=5.0) is False
        assert calls == []
        await node.stop()

    async def test_timeout_keeps_the_in_flight_verdict(self):
        node = MeshNode(transport_manager=make_manager())
        target = NodeID(os.urandom(20))
        node._pending_lookups[target] = asyncio.Event()   # never set
        calls = []
        node.kad_lookup = lambda *a, **k: calls.append(1)

        assert await node._kademlia_lookup(target, timeout=0.05) is False
        assert calls == [], "a timed-out wait must not start a second lookup"
        await node.stop()


class TestNoSelfInflictedLookupLoop:
    """A reply must never be the cause of the next question.

    `_handle_found_node` woke maintenance as soon as a reply held valid
    entries. Since the routing table refuses to store our own id, `contains` is
    false for it forever: a reply that merely echoes our own identity back
    looked like a discovery, and restarted a FIND_NODE — endlessly, at ~15 KB of
    certificates per round."""

    def test_our_own_id_is_never_a_discovery(self):
        from src.node import MeshNode
        from tests.conftest import make_manager
        node = MeshNode(transport_manager=make_manager())
        # The table refuses our own id, so `contains` stays false forever:
        # that is exactly the trap the handler has to know about.
        node._routing.add(node.id, [], b"")
        assert not node._routing.contains(node.id)

    def test_a_known_id_is_not_a_discovery_either(self):
        from src.node import MeshNode
        from src.node_id import NodeID
        from tests.conftest import make_manager
        node = MeshNode(transport_manager=make_manager())
        other = NodeID(bytes(range(20)))
        assert not node._routing.contains(other)
        node._routing.add(other, [], b"\x01" * 8)
        assert node._routing.contains(other)

    def test_the_maintenance_loop_has_a_floor_between_cycles(self):
        """A wake-up may shorten the wait, never remove it."""
        from src import node as node_mod
        assert node_mod._NEIGHBOR_MIN_INTERVAL > 0
        assert node_mod._NEIGHBOR_IDLE_MAX >= node_mod._NEIGHBOR_REFRESH

    def test_a_wake_resets_the_backoff(self):
        from src.node import MeshNode
        from tests.conftest import make_manager
        node = MeshNode(transport_manager=make_manager())
        node._neighbor_idle_cycles = 5
        node._running = True
        node._wake_neighbor_maintenance()
        assert node._neighbor_idle_cycles == 0


# ---------------------------------------------------------------------------
# 5 — a certificate both ends hold travels as its name
# ---------------------------------------------------------------------------

class TestReferringToACertificateInsteadOfSendingIt:
    """The largest thing on an idle node's wire was the same chains, again.

    A trace of a node doing nothing: 29% of every byte was FOUND_NODE, and the
    answers from one peer were byte-for-byte the same size at 8 s, 19 s and
    105 s. Certificates are ~7 kB, chains overwhelmingly end on one root, and
    the pool already stopped a *single* answer repeating one — but nothing
    stopped the next answer repeating all of them."""

    def _query(self, node, peer, target: bytes, tail: bytes = b""):
        return Packet.create(FIND_NODE, peer.authenticated_id.raw, node.id.raw,
                             target + os.urandom(_QID_LEN) + tail)

    async def test_the_answer_shrinks_and_says_the_same_thing(self):
        node = MeshNode(transport_manager=make_manager())
        _certified_routing_table(node, 8)
        peer, fake = await _attach(node, NodeID(os.urandom(20)))
        target = os.urandom(20)
        try:
            await node._handle_find_node(peer, self._query(node, peer, target))
            plain = next(p for p in fake.sent if p.type == FOUND_NODE)
            classic, used = _decode_entries(plain.payload[_QID_LEN:],
                                            node._cert_store.by_fingerprint)

            fake.sent.clear()
            hints = _encode_cert_hints(node._cert_store.fingerprints(_CERT_HINT_MAX))
            await node._handle_find_node(peer, self._query(node, peer, target, hints))
            short = next(p for p in fake.sent if p.type == FOUND_NODE)
            referred, _ = _decode_entries(short.payload[_QID_LEN:],
                                          node._cert_store.by_fingerprint)

            assert len(short.payload) < len(plain.payload) / 10
            # The same answer, and more of it: entries the byte budget had no
            # room for now fit. Closest-first either way, so the shorter answer
            # begins with exactly what the long one said.
            assert [e.node_id for e in classic] == \
                   [e.node_id for e in referred][:len(classic)]
            assert all(node._cert_store.verify_chain(e.cert_chain)
                       for e in referred)
        finally:
            await node.stop()

    async def test_a_name_the_responder_does_not_hold_is_simply_not_used(self):
        """The hint is an offer, never an instruction: what a querier names and
        what a responder would send are two lists, and only their intersection
        travels short."""
        node = MeshNode(transport_manager=make_manager())
        _certified_routing_table(node, 4)
        peer, fake = await _attach(node, NodeID(os.urandom(20)))
        try:
            hints = _encode_cert_hints([b"\xaa" * FINGERPRINT_LEN])
            await node._handle_find_node(
                peer, self._query(node, peer, os.urandom(20), hints))
            reply = next(p for p in fake.sent if p.type == FOUND_NODE)
            # Nothing we hold is named `\xaa...`, so nothing was referred to and
            # the answer is the classic one.
            entries, _ = _decode_entries(reply.payload[_QID_LEN:], lambda d: None)
            assert entries and all(e.cert_chain for e in entries)
        finally:
            await node.stop()

    async def test_a_reference_the_receiver_cannot_resolve_voids_the_chain(self):
        """Which is exactly what an unparseable certificate already did. A
        reference can only ever find one this node verified and stored, so it
        adds no authority — and finding nothing costs the sender its entry,
        never the receiver anything."""
        node = MeshNode(transport_manager=make_manager())
        _certified_routing_table(node, 4)
        peer, fake = await _attach(node, NodeID(os.urandom(20)))
        try:
            hints = _encode_cert_hints(node._cert_store.fingerprints(_CERT_HINT_MAX))
            await node._handle_find_node(
                peer, self._query(node, peer, os.urandom(20), hints))
            reply = next(p for p in fake.sent if p.type == FOUND_NODE)
            entries, _ = _decode_entries(reply.payload[_QID_LEN:], lambda d: None)
            assert all(e.cert_chain == [] for e in entries)
        finally:
            await node.stop()


class TestFindingOutWhoUnderstandsThem:
    """A lookup is routed: the node that answers may be several hops away, so
    the features two *links* agreed on say nothing about it. The answer itself
    is what carries the news — as trailing bytes, which is precisely what a
    build that has never heard of them reads it as."""

    async def test_the_answer_carries_the_marker(self):
        node = MeshNode(transport_manager=make_manager())
        _certified_routing_table(node, 2)
        peer, fake = await _attach(node, NodeID(os.urandom(20)))
        try:
            await node._handle_find_node(peer, Packet.create(
                FIND_NODE, peer.authenticated_id.raw, node.id.raw,
                os.urandom(20) + os.urandom(_QID_LEN)))
            reply = next(p for p in fake.sent if p.type == FOUND_NODE)
            _entries, used = _decode_entries(reply.payload[_QID_LEN:])
            assert reply.payload[_QID_LEN + used:] == _HINTS_OK
        finally:
            await node.stop()

    async def test_nothing_is_sent_to_a_node_that_has_not_said_so(self):
        """A build that has not heard of fingerprints checks the payload length
        exactly and drops anything longer — so a tail sent to one of those is
        not a few wasted bytes, it is a lookup that never happens."""
        node = MeshNode(transport_manager=make_manager())
        node._running = True
        far = NodeID(b"\x77" * 20)
        relay, fake = await _attach(node, NodeID(b"\xff" * 20))
        try:
            await node._kad_query_node(far, far, timeout=0.05)
            asked = next(p for p in fake.sent if p.type == FIND_NODE)
            assert len(asked.payload) == 20 + _QID_LEN
        finally:
            await node.stop()

    async def test_once_it_has_answered_we_start_naming_what_we_hold(self):
        node = MeshNode(transport_manager=make_manager())
        _certified_routing_table(node, 3)
        node._running = True
        far = NodeID(b"\x77" * 20)
        relay, fake = await _attach(node, NodeID(b"\xff" * 20))
        try:
            node._note_cert_hints(far.raw)
            await node._kad_query_node(far, far, timeout=0.05)
            asked = next(p for p in fake.sent if p.type == FIND_NODE)
            tail = asked.payload[20 + _QID_LEN:]
            assert tail and len(tail) % FINGERPRINT_LEN == 0
            assert _decode_cert_hints(tail) == frozenset(
                node._cert_store.fingerprints(_CERT_HINT_MAX))
        finally:
            await node.stop()

    async def test_the_marker_is_learned_from_an_answer(self):
        node = MeshNode(transport_manager=make_manager())
        peer, fake = await _attach(node, NodeID(b"\xff" * 20))
        far = NodeID(b"\x77" * 20)
        try:
            query_id = os.urandom(_QID_LEN)
            future = asyncio.get_event_loop().create_future()
            node._pending_finds[query_id] = future
            await node._handle_found_node(peer, Packet.create(
                FOUND_NODE, far.raw, node.id.raw,
                query_id + _encode_entries([]) + _HINTS_OK))
            assert far.raw in node._cert_hint_peers
        finally:
            await node.stop()

    async def test_an_answer_without_it_teaches_nothing(self):
        node = MeshNode(transport_manager=make_manager())
        peer, fake = await _attach(node, NodeID(b"\xff" * 20))
        far = NodeID(b"\x77" * 20)
        try:
            query_id = os.urandom(_QID_LEN)
            node._pending_finds[query_id] = asyncio.get_event_loop().create_future()
            await node._handle_found_node(peer, Packet.create(
                FOUND_NODE, far.raw, node.id.raw, query_id + _encode_entries([])))
            assert far.raw not in node._cert_hint_peers
        finally:
            await node.stop()

    def test_the_table_is_bounded(self):
        node = MeshNode(transport_manager=make_manager())
        for i in range(_HINT_PEERS_MAX + 40):
            node._note_cert_hints(i.to_bytes(20, "big"))
        assert len(node._cert_hint_peers) <= _HINT_PEERS_MAX


class TestTheTailIsHostileInput:
    """It arrives on a link that has authenticated, but authentication is not
    trust: the tail is parsed like anything else off the wire."""

    @pytest.mark.parametrize("tail", [
        b"\x00", b"\xff" * (FINGERPRINT_LEN - 1),
        b"\xff" * (FINGERPRINT_LEN + 1),
        b"\xff" * (FINGERPRINT_LEN * (_CERT_HINT_MAX + 1)),
    ])
    def test_a_tail_that_is_not_a_list_of_names_is_refused(self, tail):
        assert _decode_cert_hints(tail) is None

    def test_the_classic_question_stays_valid_for_ever(self):
        assert _decode_cert_hints(b"") == frozenset()

    async def test_a_short_payload_is_dropped_rather_than_sliced(self):
        """The length check the tail replaced was doing two jobs."""
        node = MeshNode(transport_manager=make_manager())
        peer, fake = await _attach(node, NodeID(b"\xff" * 20))
        try:
            for payload in (b"", b"x" * 8, b"y" * (19 + _QID_LEN)):
                await node._handle_find_node(peer, Packet.create(
                    FIND_NODE, peer.authenticated_id.raw, node.id.raw, payload))
            assert not [p for p in fake.sent if p.type == FOUND_NODE]
        finally:
            await node.stop()

    def test_a_truncated_reference_is_a_parse_error_not_a_crash(self):
        body = _POOL_COUNT.pack(1) + _CERT_LEN.pack(_CERT_REF) + b"\x00" * 4
        with pytest.raises(ValueError):
            _decode_entries(body, lambda d: None)


# ---------------------------------------------------------------------------
# 6 — an id that answers nobody stops being handed round
# ---------------------------------------------------------------------------

class TestAnIdThatNeverAnswers:
    """A trace of an idle node: one id was asked in every lookup round for the
    whole capture and never appeared as the source of a single packet. Every
    answer from every peer re-taught it, every round asked after it again, and
    every pass tried to dial it — at an address that turned out to be this very
    machine's. That is what a routing table looks like when it is still carrying
    somebody's previous identity."""

    def _table(self, node, ids):
        for node_id in ids:
            node._routing.add(node_id, ["tcp://10.0.0.1:9000"], b"\x01" * 32)

    def test_silence_is_counted_and_an_answer_clears_it(self):
        node = MeshNode(transport_manager=make_manager())
        ghost = NodeID(b"\x11" * 20)
        self._table(node, [ghost])
        for _ in range(routing_mod.SILENT_AFTER):
            node._routing.note_unanswered(ghost)
        assert node._routing.get(ghost).unanswered == routing_mod.SILENT_AFTER
        node._routing.note_answered(ghost)
        assert node._routing.get(ghost).unanswered == 0
        assert node._routing.get(ghost).answered_at is not None

    def test_it_drops_out_of_what_we_ask_dial_and_advertise(self):
        node = MeshNode(transport_manager=make_manager())
        ghost, live = NodeID(b"\x11" * 20), NodeID(b"\x22" * 20)
        self._table(node, [ghost, live])
        for _ in range(routing_mod.SILENT_AFTER):
            node._routing.note_unanswered(ghost)
            node._routing.note_unanswered(live)
        node._routing.note_answered(live)
        closest = [e.node_id for e in node._routing.get_closest(NodeID(b"\x00" * 20))]
        assert ghost not in closest and live in closest
        assert node._routing.silent_ids() == [ghost.raw.hex()]
        # The entry is still there: the id is real, and somebody else may reach
        # it. We have only stopped naming it.
        assert node._routing.contains(ghost)

    def test_one_that_answered_before_is_only_having_a_bad_minute(self):
        """Never once, not lately. An id that has answered is a node with a
        problem, and the answer to that is patience."""
        node = MeshNode(transport_manager=make_manager())
        flaky = NodeID(b"\x33" * 20)
        self._table(node, [flaky])
        node._routing.note_answered(flaky)
        for _ in range(routing_mod.SILENT_AFTER * 4):
            node._routing.note_unanswered(flaky)
        assert node._routing.is_silent(node._routing.get(flaky)) is False

    def test_being_re_advertised_does_not_wipe_the_count(self):
        """The whole reason the count lives on the entry. Everyone on the mesh
        re-teaches a ghost, and an entry rebuilt with a clean sheet on every
        answer never reaches any threshold at all."""
        node = MeshNode(transport_manager=make_manager())
        ghost = NodeID(b"\x11" * 20)
        self._table(node, [ghost])
        for _ in range(routing_mod.SILENT_AFTER):
            node._routing.note_unanswered(ghost)
        node._routing.add(ghost, ["tcp://10.0.0.9:9000"], b"\x01" * 32)
        assert node._routing.get(ghost).unanswered == routing_mod.SILENT_AFTER
        assert node._routing.is_silent(node._routing.get(ghost)) is True

    def test_it_is_asked_again_after_a_while(self, monkeypatch):
        """A node that comes back is found within `SILENT_RETRY`, and one that
        never does costs one packet per five minutes instead of one per ten
        seconds."""
        node = MeshNode(transport_manager=make_manager())
        ghost = NodeID(b"\x11" * 20)
        self._table(node, [ghost])
        for _ in range(routing_mod.SILENT_AFTER):
            node._routing.note_unanswered(ghost)
        later = time.monotonic() + routing_mod.SILENT_RETRY + 1
        monkeypatch.setattr(routing_mod.time, "monotonic", lambda: later)
        assert node._routing.is_silent(node._routing.get(ghost)) is False
        assert [e.node_id for e in
                node._routing.get_closest(NodeID(b"\x00" * 20))] == [ghost]

    async def test_a_lookup_counts_who_answered(self):
        node = MeshNode(transport_manager=make_manager())
        node._running = True
        answers, silent = NodeID(b"\x44" * 20), NodeID(b"\x55" * 20)
        self._table(node, [answers, silent])

        async def reply(node_id, target, timeout=5.0):
            return [] if node_id == answers else None
        node._kad_query_node = reply
        await node.kad_lookup(NodeID(b"\x00" * 20), k=20, alpha=3, max_rounds=1)
        await node.stop()
        assert node._routing.get(answers).answered_at is not None
        assert node._routing.get(answers).unanswered == 0
        assert node._routing.get(silent).unanswered == 1

    async def test_an_empty_answer_is_still_an_answer(self):
        """A node with nothing to say about this target has said so. Reading
        that as silence would retire the quiet edges of a small mesh."""
        node = MeshNode(transport_manager=make_manager())
        node._running = True
        quiet = NodeID(b"\x66" * 20)
        self._table(node, [quiet])
        node._kad_query_node = lambda node_id, target, timeout=5.0: _empty()
        await node.kad_lookup(NodeID(b"\x00" * 20), k=20, alpha=3, max_rounds=1)
        await node.stop()
        assert node._routing.get(quiet).answered_at is not None

    async def test_the_console_says_so_rather_than_leaving_a_dead_row(self):
        node = MeshNode(transport_manager=make_manager())
        ghost = NodeID(b"\x11" * 20)
        self._table(node, [ghost])
        for _ in range(routing_mod.SILENT_AFTER):
            node._routing.note_unanswered(ghost)
        snapshot = await node.console_snapshot()
        row = next(r for r in snapshot["routing"]
                   if r["id"] == ghost.raw.hex())
        await node.stop()
        assert row["silent"] is True


async def _empty():
    return []
