"""
Regression tests for the NAT/relay hardening fixes.

Each test pins one bug that was reproduced live before the fix:

  - A PING carrying no advertised addresses still earns a PONG — a NATted
    node with nothing to advertise must not look dead (its keepalive RTT
    would otherwise stay stuck forever).
  - ``console_ping_node`` falls back to the routed ECHO probe when no PONG
    arrives, instead of claiming reachability from a direct link's mere
    existence (half-dead punched link).
  - E2E re-key: a valid handshake for an already-established peer parks a
    *candidate* session instead of overwriting the live one (a stale/late
    duplicate handshake used to poison the session permanently — every DATA
    packet then failed GCM, silently). A DATA packet that decrypts under the
    candidate promotes it (that is how a peer that lost its session heals).
  - UDP reliability: modular sequence handling (2^32 wrap no longer wedges
    the link), bounded state under sequence-number spray, re-ACK of
    duplicates.
  - UDP keepalive: the dead-link timeout spans 3 keepalive intervals (a
    shorter one killed healthy quiet links — route flapping).
  - TCP connect: a dial that never answers fails inside the bounded connect
    timeout instead of hanging for the OS SYN timeout.
"""
import asyncio
import os
import time

import pytest

from src.node import (MeshNode, PING, PONG, DATA, E2E_HANDSHAKE, E2E_HANDSHAKE_ACK,
                      _encode_addresses, _encode_e2e_handshake)
from src.node_id import NodeID
from src.packet import Packet
from src.crypto import SessionKey
from tests.conftest import FakeTransport, make_node, make_manager
from tests.test_e2e import _cross_trust, _make_authed_pair, _until


# ---------------------------------------------------------------------------
# PING/PONG — a node with nothing to advertise still gets its liveness reply
# ---------------------------------------------------------------------------

class TestPingEmptyAdvertised:
    async def test_empty_address_list_still_pongs(self):
        node, fake = await make_node()
        sender_id = NodeID.generate()
        node._peers[0].authenticated_id = sender_id
        payload = _encode_addresses([])            # nothing to advertise (NATted)
        ping = Packet.create(PING, sender_id.raw, node.id.raw, payload)
        fake.inject(ping)
        await _until(lambda: any(p.type == PONG for p in fake.sent))
        await node.stop()
        assert any(p.type == PONG for p in fake.sent)

    async def test_all_invalid_addresses_still_pongs(self):
        """Every advertised URI invalid → no routing merge, but still a PONG."""
        node, fake = await make_node()
        sender_id = NodeID.generate()
        node._peers[0].authenticated_id = sender_id
        payload = _encode_addresses(["not-a-uri", "also||bad"])
        ping = Packet.create(PING, sender_id.raw, node.id.raw, payload)
        fake.inject(ping)
        await _until(lambda: any(p.type == PONG for p in fake.sent))
        await node.stop()
        assert any(p.type == PONG for p in fake.sent)
        assert node._routing.get(sender_id) is None   # nothing junky merged


# ---------------------------------------------------------------------------
# console_ping_node — honesty about the PONG, ECHO fallback
# ---------------------------------------------------------------------------

class TestConsolePing:
    async def test_direct_ping_reports_rtt_when_pong_arrives(self):
        node, fake = await make_node()
        target = NodeID.generate()
        peer = node._peers[0]
        peer.authenticated_id = target
        peer.session = SessionKey(os.urandom(32))

        async def answer_pong():
            await _until(lambda: any(p.type == PING for p in fake.sent))
            fake.inject(Packet.create(PONG, target.raw, node.id.raw, b""))
        task = asyncio.create_task(answer_pong())
        try:
            res = await node.console_ping_node(target.raw.hex())
        finally:
            await node.stop()
            await task
        assert res["reachable"] is True and res["via"] == "direct"
        assert res["rtt_ms"] is not None

    async def test_no_pong_falls_back_to_routed_echo(self, monkeypatch):
        """A direct link that never PONGs must not be declared reachable on
        faith: the console probe falls through to the routed ECHO, whose reply
        proves liveness end to end."""
        monkeypatch.setattr("src.node._DIRECT_PING_TIMEOUT", 0.2)
        node, fake = await make_node()
        target = NodeID.generate()
        peer = node._peers[0]
        peer.authenticated_id = target
        peer.session = SessionKey(os.urandom(32))

        async def fake_routed(nid, timeout=5.0):
            assert nid == target
            return 7.5
        monkeypatch.setattr(node, "_routed_ping", fake_routed)
        try:
            res = await node.console_ping_node(target.raw.hex())
        finally:
            await node.stop()
        assert res["reachable"] is True and res["via"] == "route"
        assert res["rtt_ms"] == 7.5

    async def test_no_pong_and_no_route_reports_unreachable(self, monkeypatch):
        monkeypatch.setattr("src.node._DIRECT_PING_TIMEOUT", 0.2)
        node, fake = await make_node()
        target = NodeID.generate()
        peer = node._peers[0]
        peer.authenticated_id = target
        peer.session = SessionKey(os.urandom(32))

        async def no_route(nid, timeout=5.0):
            return None
        monkeypatch.setattr(node, "_routed_ping", no_route)

        async def no_peer(nid):
            return None
        monkeypatch.setattr(node, "_ensure_route_to", no_peer)
        try:
            res = await node.console_ping_node(target.raw.hex())
        finally:
            await node.stop()
        assert res["reachable"] is False


# ---------------------------------------------------------------------------
# E2E re-key — stale handshakes can't poison, real re-keys heal
# ---------------------------------------------------------------------------

def _craft_e2e_handshake(node: MeshNode, target: NodeID) -> Packet:
    """Build a well-formed, fully-signed E2E_HANDSHAKE as ``node`` would send
    (fresh nonce + KEM keypair), without touching any pending state."""
    nonce = os.urandom(32)
    kem_pub, _ = node._identity.generate_kem_keypair()
    dsa_pub = node._identity.dsa_public_key
    chain = node._cert_store.get_chain_to_root(node.id) or []
    sig = node._identity.sign(nonce + kem_pub + dsa_pub)
    payload = _encode_e2e_handshake(nonce, kem_pub, dsa_pub, chain, sig)
    return Packet.create(E2E_HANDSHAKE, node.id.raw, target.raw, payload)


class TestE2ERekey:
    async def test_stale_handshake_does_not_overwrite_live_session(self):
        """The poisoning bug: an established session was overwritten by any
        late/duplicate handshake while the initiator ignored the ACK → both
        ends held different keys forever. Now: candidate parked, live kept."""
        node_a, fake_a = await make_node()
        node_b, fake_b = await make_node()
        _cross_trust(node_a, node_b)
        await _make_authed_pair(node_a, fake_a, node_b, fake_b)

        live = SessionKey(os.urandom(32))
        node_b._e2e_sessions[node_a.id] = live

        before = len(fake_b.sent)
        fake_b.inject(_craft_e2e_handshake(node_a, node_b.id))
        await _until(lambda: len(fake_b.sent) > before)

        assert node_b._e2e_sessions[node_a.id] is live        # untouched
        assert node_a.id in node_b._e2e_rekey                  # candidate parked
        assert any(p.type == E2E_HANDSHAKE_ACK for p in fake_b.sent[before:])
        await node_a.stop()
        await node_b.stop()

    async def test_candidate_promoted_by_data_that_decrypts(self):
        """A peer that really re-keyed (lost its session) completes the
        handshake and its DATA proves it: the candidate is promoted."""
        node_a, fake_a = await make_node()
        node_b, fake_b = await make_node()
        _cross_trust(node_a, node_b)
        await _make_authed_pair(node_a, fake_a, node_b, fake_b)

        stale = SessionKey(os.urandom(32))
        node_b._e2e_sessions[node_a.id] = stale

        # A genuinely re-initiates (pending state set) → B parks a candidate,
        # ACKs → A completes the new session and sends DATA under it.
        await node_a._initiate_e2e_handshake(node_b.id)
        hs = next(p for p in fake_a.sent if p.type == E2E_HANDSHAKE)
        before = len(fake_b.sent)
        fake_b.inject(hs)
        await _until(lambda: any(p.type == E2E_HANDSHAKE_ACK for p in fake_b.sent[before:]))
        ack = next(p for p in fake_b.sent[before:] if p.type == E2E_HANDSHAKE_ACK)
        fake_a.inject(ack)
        await _until(lambda: node_b.id in node_a._e2e_sessions)
        new_key = node_a._e2e_sessions[node_b.id].key_bytes
        assert node_a.id in node_b._e2e_rekey
        assert node_b._e2e_sessions[node_a.id] is stale        # not yet rotated

        await node_a.send_data(node_b.id, b"proof of re-key")
        data_pkt = next(p for p in fake_a.sent if p.type == DATA)
        fake_b.inject(data_pkt)
        src, payload = await asyncio.wait_for(node_b.receive_data(), timeout=2.0)

        assert (src, payload) == (node_a.id, b"proof of re-key")
        assert node_b._e2e_sessions[node_a.id].key_bytes == new_key  # promoted
        assert node_a.id not in node_b._e2e_rekey
        await node_a.stop()
        await node_b.stop()

    async def test_data_under_unknown_key_stays_dropped(self):
        """No candidate parked → a DATA packet that fails GCM is dropped as
        before (reject by default, nothing leaks)."""
        node_a, fake_a = await make_node()
        node_b, fake_b = await make_node()
        _cross_trust(node_a, node_b)
        await _make_authed_pair(node_a, fake_a, node_b, fake_b)

        node_b._e2e_sessions[node_a.id] = SessionKey(os.urandom(32))
        wrong = Packet.create_encrypted(DATA, node_a.id.raw, node_b.id.raw,
                                        b"garbage", SessionKey(os.urandom(32)))
        fake_b.inject(wrong)
        await asyncio.sleep(0.1)
        assert node_b._data_queue.empty()
        await node_a.stop()
        await node_b.stop()

    async def test_rekey_candidate_expires(self):
        node, _ = await make_node()
        peer_id = NodeID.generate()
        node._e2e_rekey[peer_id] = (SessionKey(os.urandom(32)),
                                    time.monotonic() - 0.01)   # already expired
        assert node._e2e_rekey_get(peer_id) is None
        assert peer_id not in node._e2e_rekey
        await node.stop()

    async def test_rekey_store_is_bounded(self):
        import src.node as nodemod
        node, _ = await make_node()
        for i in range(nodemod._E2E_REKEY_MAX + 10):
            node._e2e_rekey_store(NodeID.generate(), SessionKey(os.urandom(32)))
        assert len(node._e2e_rekey) <= nodemod._E2E_REKEY_MAX
        await node.stop()


# ---------------------------------------------------------------------------
# UDP reliability — modular sequence window, bounded state
# ---------------------------------------------------------------------------

class TestUdpReliableLink:
    def _link(self):
        from src.udp_transport import _ReliableLink, FLAG_DATA
        return _ReliableLink(), FLAG_DATA

    def test_in_order_delivery(self):
        link, DATA_FLAG = self._link()
        assert link.process_incoming(0, DATA_FLAG, b"a") == [b"a"]
        assert link.process_incoming(1, DATA_FLAG, b"b") == [b"b"]

    def test_out_of_order_buffered_then_flushed(self):
        link, DATA_FLAG = self._link()
        assert link.process_incoming(0, DATA_FLAG, b"a") == [b"a"]
        assert link.process_incoming(2, DATA_FLAG, b"c") == []     # gap at 1
        assert link.process_incoming(3, DATA_FLAG, b"d") == []
        assert link.process_incoming(1, DATA_FLAG, b"b") == [b"b", b"c", b"d"]

    def test_duplicate_retransmit_dropped_and_reacked(self):
        link, DATA_FLAG = self._link()
        link.process_incoming(0, DATA_FLAG, b"a")
        assert link.process_incoming(0, DATA_FLAG, b"a") == []    # behind cursor
        assert link.needs_ack()                                    # re-ACKed

    def test_sequence_spray_stays_bounded(self):
        """A hostile peer spraying unique sequence numbers must not grow
        receive-side state without bound (was an unbounded seen-set)."""
        from src.udp_transport import _MAX_REORDER
        link, DATA_FLAG = self._link()
        link.process_incoming(0, DATA_FLAG, b"a")
        for seq in range(1, 10 * _MAX_REORDER):
            link.process_incoming(seq, DATA_FLAG, b"x")
        assert len(link._reorder) <= _MAX_REORDER
        assert not hasattr(link, "_recv_seen")

    def test_seq_wrap_does_not_wedge(self):
        """At the 2^32 wrap the modular comparison keeps delivering (the old
        seen-set dropped every post-wrap frame as a 'duplicate')."""
        link, DATA_FLAG = self._link()
        link._recv_next = 0xFFFFFFFF
        assert link.process_incoming(0xFFFFFFFF, DATA_FLAG, b"last") == [b"last"]
        assert link.process_incoming(0, DATA_FLAG, b"first") == [b"first"]
        # a pre-wrap retransmit is behind the cursor → dropped, re-acked
        assert link.process_incoming(0xFFFFFFFE, DATA_FLAG, b"old") == []
        assert link.needs_ack()


class TestUdpKeepalive:
    def test_dead_link_timeout_spans_three_intervals(self):
        """The comment says '3 missed keepalives → dead link'; the value must
        honour it and exceed the mesh PING cadence (20s), or healthy quiet
        links get killed (route flapping)."""
        from src.udp_transport import _KEEPALIVE_INTERVAL, _KEEPALIVE_TIMEOUT
        assert _KEEPALIVE_TIMEOUT >= 3 * _KEEPALIVE_INTERVAL
        assert _KEEPALIVE_TIMEOUT > 20.0


# ---------------------------------------------------------------------------
# TCP connect — bounded dial
# ---------------------------------------------------------------------------

class TestTcpConnectTimeout:
    async def test_hanging_dial_fails_within_timeout(self, monkeypatch):
        import src.tcp_transport as tcpt

        monkeypatch.setattr(tcpt, "_CONNECT_TIMEOUT", 0.3)

        async def hang(*args, **kwargs):
            await asyncio.sleep(60)
        monkeypatch.setattr(asyncio, "open_connection", hang)

        t = tcpt.TCPTransport()
        t0 = time.monotonic()
        with pytest.raises(TimeoutError):
            await t.connect("127.0.0.1:9")
        assert time.monotonic() - t0 < 5.0
