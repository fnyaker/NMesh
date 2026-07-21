"""
Tests for the E2E encryption layer (E2E_HANDSHAKE / E2E_HANDSHAKE_ACK / DATA).

Topology used by most tests:
    A ──[t_ab]──> B ──[t_bc]──> C
    A <──[t_ba]── B <──[t_cb]── C

Each arrow is a FakeTransport. Packets are forwarded manually between
the paired transports via _pump() so we control timing precisely.
"""
import asyncio
import os
import pytest
from src.node import MeshNode, DATA, E2E_HANDSHAKE, E2E_HANDSHAKE_ACK
from src.node_id import NodeID
from src.packet import Packet
from src.crypto import CryptoIdentity, SessionKey
from tests.conftest import FakeTransport, make_node, make_manager


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

async def _until(pred, timeout: float = 2.0) -> bool:
    """Wait until pred() is true, polling the event loop. Replaces fixed
    ``sleep(0.1)`` propagation waits: on in-memory transports a step completes
    in a few event-loop hops (~ms), so this returns almost immediately instead
    of always paying the full delay, while still tolerating slow PQ crypto."""
    deadline = asyncio.get_event_loop().time() + timeout
    while not pred():
        if asyncio.get_event_loop().time() >= deadline:
            return False
        await asyncio.sleep(0.001)
    return True


async def _make_authed_pair(
    node_a: MeshNode,
    fake_a: FakeTransport,
    node_b: MeshNode,
    fake_b: FakeTransport,
) -> None:
    """Establish a direct peer session (HANDSHAKE) between node_a and node_b.
    fake_a is the transport injected into node_a; fake_b into node_b.
    After this, node_a._peers[0].authenticated_id == node_b.id (and vice versa).
    """
    challenge = os.urandom(32)
    node_b._peers[0].invite_accepted = True
    node_b._peers[0].pending_challenge = challenge
    node_a._peers[0].invite_accepted = True
    node_a._peers[0].received_challenge = challenge
    await node_a.initiate_handshake(node_a._peers[0])
    fake_b.inject(fake_a.sent[-1])
    await _until(lambda: any(p.type == 0x09 for p in fake_b.sent))
    ack = next(p for p in fake_b.sent if p.type == 0x09)
    fake_a.inject(ack)
    await _until(lambda: node_a._peers[0].authenticated_id is not None)


async def _make_chain() -> tuple[
    MeshNode, FakeTransport,   # node_a  + transport A→B
    MeshNode, FakeTransport, FakeTransport,  # node_b  + transport B→A, B→C
    MeshNode, FakeTransport,   # node_c  + transport C→B
]:
    """
    Build a 3-node chain A–B–C with authenticated peer sessions.

    node_a has one peer using t_ab (sends to node_b side).
    node_b has two peers: t_ba (side facing A) and t_bc (side facing C).
    node_c has one peer using t_cb (sends to node_b side).

    Cross-wiring: t_ab.sent → injected into node_b via t_ba.inject
                  t_ba.sent → injected into node_a via t_ab.inject
                  (same pattern for B↔C)
    """
    t_ab = FakeTransport()
    t_ba = FakeTransport()
    t_bc = FakeTransport()
    t_cb = FakeTransport()

    node_a = MeshNode(transport_manager=make_manager())
    node_b = MeshNode(transport_manager=make_manager())
    node_c = MeshNode(transport_manager=make_manager())

    # Inject transports as peers
    await node_a._inject_peer(t_ab)
    await node_b._inject_peer(t_ba)
    await node_b._inject_peer(t_bc)
    await node_c._inject_peer(t_cb)

    # ── Authenticate A↔B ──────────────────────────────────────────────────
    challenge_ab = os.urandom(32)
    node_b._peers[0].invite_accepted = True
    node_b._peers[0].pending_challenge = challenge_ab
    node_a._peers[0].invite_accepted = True
    node_a._peers[0].received_challenge = challenge_ab
    await node_a.initiate_handshake(node_a._peers[0])
    t_ba.inject(t_ab.sent[-1])       # HANDSHAKE: A→B
    await _until(lambda: any(p.type == 0x09 for p in t_ba.sent))
    ack_ab = next(p for p in t_ba.sent if p.type == 0x09)
    t_ab.inject(ack_ab)              # HANDSHAKE_ACK: B→A
    await _until(lambda: node_a._peers[0].authenticated_id is not None)

    # ── Authenticate B↔C ──────────────────────────────────────────────────
    challenge_bc = os.urandom(32)
    node_c._peers[0].invite_accepted = True
    node_c._peers[0].pending_challenge = challenge_bc
    node_b._peers[1].invite_accepted = True
    node_b._peers[1].received_challenge = challenge_bc
    await node_b.initiate_handshake(node_b._peers[1])
    t_cb.inject(t_bc.sent[-1])       # HANDSHAKE: B→C
    await _until(lambda: any(p.type == 0x09 for p in t_cb.sent))
    ack_bc = next(p for p in t_cb.sent if p.type == 0x09)
    t_bc.inject(ack_bc)              # HANDSHAKE_ACK: C→B
    await _until(lambda: node_b._peers[1].authenticated_id is not None)

    # Make B's cert trusted by A and C (and vice-versa), so E2E chains verify.
    _cross_trust(node_a, node_b)
    _cross_trust(node_b, node_c)
    _cross_trust(node_a, node_c)

    return node_a, t_ab, node_b, t_ba, t_bc, node_c, t_cb


def _cross_trust(node_x: MeshNode, node_y: MeshNode) -> None:
    """Make x and y mutually trust each other's self-signed cert as a root."""
    cert_x = node_x._identity.self_signed_cert()
    cert_y = node_y._identity.self_signed_cert()
    node_y._cert_store.add(cert_x)
    node_y._cert_store.add_root(node_x.id)
    node_x._cert_store.add(cert_y)
    node_x._cert_store.add_root(node_y.id)


async def _relay_once(src: FakeTransport, dst: FakeTransport,
                      sent_before: int = 0) -> list[Packet]:
    """Inject all new packets from src.sent[sent_before:] into dst."""
    new_pkts = src.sent[sent_before:]
    for p in new_pkts:
        dst.inject(p)
    await asyncio.sleep(0.1)
    return new_pkts


# ---------------------------------------------------------------------------
# 12.1 — Handshake E2E
# ---------------------------------------------------------------------------

class TestE2EHandshake:
    async def test_e2e_handshake_establishes_session(self):
        node_a, t_ab, node_b, t_ba, t_bc, node_c, t_cb = await _make_chain()

        # A initiates E2E handshake to C
        before_ab = len(t_ab.sent)
        await node_a._initiate_e2e_handshake(node_c.id)
        assert len(t_ab.sent) > before_ab

        # Relay A→B→C
        before_bc = len(t_bc.sent)
        t_ba.inject(t_ab.sent[-1])
        await asyncio.sleep(0.1)
        # B should forward to C
        assert len(t_bc.sent) > before_bc
        before_cb = len(t_cb.sent)
        t_cb.inject(t_bc.sent[-1])
        await asyncio.sleep(0.1)

        # C should have replied (E2E_HANDSHAKE_ACK going back C→B→A)
        assert len(t_cb.sent) > before_cb
        ack_c = next(p for p in t_cb.sent[before_cb:] if p.type == E2E_HANDSHAKE_ACK)
        before_ba = len(t_ba.sent)
        t_bc.inject(ack_c)
        await asyncio.sleep(0.1)
        assert len(t_ba.sent) > before_ba
        ack_b = next(p for p in t_ba.sent[before_ba:] if p.type == E2E_HANDSHAKE_ACK)
        t_ab.inject(ack_b)
        await asyncio.sleep(0.1)

        assert node_c.id in node_a._e2e_sessions
        assert node_a.id in node_c._e2e_sessions

        await node_a.stop()
        await node_b.stop()
        await node_c.stop()

    async def test_e2e_handshake_invalid_signature_dropped(self):
        node_a, t_ab, node_b, t_ba, t_bc, node_c, t_cb = await _make_chain()

        await node_a._initiate_e2e_handshake(node_c.id)
        raw = t_ab.sent[-1]

        # Corrupt the packet payload (flip last byte of signature)
        corrupted_payload = bytearray(raw.payload)
        corrupted_payload[-1] ^= 0xFF
        corrupted_pkt = Packet.create(
            E2E_HANDSHAKE, raw.src_id, raw.dst_id, bytes(corrupted_payload)
        )
        t_ba.inject(corrupted_pkt)
        await asyncio.sleep(0.1)
        t_cb.inject(t_bc.sent[-1] if t_bc.sent else corrupted_pkt)
        await asyncio.sleep(0.1)

        assert node_a.id not in node_c._e2e_sessions

        await node_a.stop()
        await node_b.stop()
        await node_c.stop()

    async def test_e2e_handshake_no_chain_dropped(self):
        """A node whose chain isn't anchored in any of B's trusted roots is rejected."""
        node_a, fake_a = await make_node()
        node_b, fake_b = await make_node()
        # Wire up routing manually WITHOUT the invite flow so B never issues a
        # cert for A — B's roots remain {B.id} and A cannot produce a chain
        # ending at a root B trusts.
        shared = os.urandom(32)
        node_a._peers[0].authenticated_id = node_b.id
        node_a._peers[0].session = SessionKey(shared)
        node_b._peers[0].authenticated_id = node_a.id
        node_b._peers[0].session = SessionKey(shared)

        await node_a._initiate_e2e_handshake(node_b.id)
        hs_pkt = next(p for p in fake_a.sent if p.type == E2E_HANDSHAKE)
        fake_b.inject(hs_pkt)
        await asyncio.sleep(0.1)

        # B's roots = {B.id}; A's chain = [A_self_signed] anchored at A.id → rejected
        assert node_a.id not in node_b._e2e_sessions

        await node_a.stop()
        await node_b.stop()

    async def test_e2e_handshake_replay_nonce_rejected(self):
        """ACK with a nonce that doesn't match any pending handshake → drop."""
        node_a, fake_a = await make_node()
        node_b, fake_b = await make_node()
        _cross_trust(node_a, node_b)
        await _make_authed_pair(node_a, fake_a, node_b, fake_b)

        # Inject a fake ACK with random nonce (not matching any pending)
        from src.node import _encode_e2e_handshake_ack, _encode_chain
        fake_nonce = os.urandom(32)
        ct = os.urandom(32)
        dsa_pub = node_b._identity.dsa_public_key
        chain = node_b._cert_store.get_chain_to_root(node_b.id) or []
        sig = node_b._identity.sign(fake_nonce + ct + dsa_pub)
        payload = _encode_e2e_handshake_ack(fake_nonce, ct, dsa_pub, chain, sig)
        pkt = Packet.create(E2E_HANDSHAKE_ACK, node_b.id.raw, node_a.id.raw, payload)
        node_a._peers[0].authenticated_id = node_b.id   # mark peer as authenticated
        fake_a.inject(pkt)
        await asyncio.sleep(0.1)

        # No session should have been established
        assert node_b.id not in node_a._e2e_sessions

        await node_a.stop()
        await node_b.stop()


# ---------------------------------------------------------------------------
# 12.2 — Data E2E
# ---------------------------------------------------------------------------

class TestE2EData:
    async def test_send_data_buffers_until_handshake(self):
        node_a, fake_a = await make_node()
        node_b, fake_b = await make_node()
        _cross_trust(node_a, node_b)
        await _make_authed_pair(node_a, fake_a, node_b, fake_b)

        # No E2E session yet — send_data must buffer
        await node_a.send_data(node_b.id, b"buffered")
        assert node_b.id in node_a._e2e_pending_data
        assert node_a._e2e_pending_data[node_b.id] == [b"buffered"]

        await node_a.stop()
        await node_b.stop()

    async def test_send_data_uses_session_after_handshake(self):
        node_a, fake_a = await make_node()
        node_b, fake_b = await make_node()
        _cross_trust(node_a, node_b)
        await _make_authed_pair(node_a, fake_a, node_b, fake_b)

        # Trigger handshake
        before = len(fake_a.sent)
        await node_a.send_data(node_b.id, b"hello")
        hs_pkt = next(p for p in fake_a.sent[before:] if p.type == E2E_HANDSHAKE)
        fake_b.inject(hs_pkt)
        await asyncio.sleep(0.1)
        ack = next(p for p in fake_b.sent if p.type == E2E_HANDSHAKE_ACK)
        fake_a.inject(ack)
        await asyncio.sleep(0.1)

        assert node_b.id in node_a._e2e_sessions
        # Pending data should have been flushed as a DATA packet
        data_pkts = [p for p in fake_a.sent if p.type == DATA]
        assert len(data_pkts) >= 1

        await node_a.stop()
        await node_b.stop()

    async def test_relay_cannot_decrypt_data(self):
        node_a, t_ab, node_b, t_ba, t_bc, node_c, t_cb = await _make_chain()

        # Establish E2E session A↔C manually
        shared = os.urandom(32)
        node_a._e2e_sessions[node_c.id] = SessionKey(shared)
        node_c._e2e_sessions[node_a.id] = SessionKey(shared)

        before = len(t_ab.sent)
        await node_a.send_data(node_c.id, b"secret")
        data_pkt = next(p for p in t_ab.sent[before:] if p.type == DATA)

        # B receives the packet (as relay) — should not be able to decrypt
        assert node_a.id not in node_b._e2e_sessions
        with pytest.raises(Exception):
            data_pkt.decrypt_payload(SessionKey(os.urandom(32)))

        await node_a.stop()
        await node_b.stop()
        await node_c.stop()

    async def test_target_decrypts_data(self):
        node_a, t_ab, node_b, t_ba, t_bc, node_c, t_cb = await _make_chain()

        shared = os.urandom(32)
        node_a._e2e_sessions[node_c.id] = SessionKey(shared)
        node_c._e2e_sessions[node_a.id] = SessionKey(shared)

        before = len(t_ab.sent)
        await node_a.send_data(node_c.id, b"hello C")
        data_pkt = next(p for p in t_ab.sent[before:] if p.type == DATA)

        # Route: A → B → C
        t_ba.inject(data_pkt)
        await asyncio.sleep(0.1)
        forwarded = next((p for p in t_bc.sent if p.type == DATA), None)
        assert forwarded is not None
        t_cb.inject(forwarded)
        received_src, received_payload = await asyncio.wait_for(
            node_c.receive_data(), timeout=1.0
        )

        assert received_src == node_a.id
        assert received_payload == b"hello C"

        await node_a.stop()
        await node_b.stop()
        await node_c.stop()

    async def test_receive_data_returns_src_id(self):
        node_a, fake_a = await make_node()
        node_b, fake_b = await make_node()
        _cross_trust(node_a, node_b)
        await _make_authed_pair(node_a, fake_a, node_b, fake_b)

        shared = os.urandom(32)
        node_a._e2e_sessions[node_b.id] = SessionKey(shared)
        node_b._e2e_sessions[node_a.id] = SessionKey(shared)

        before = len(fake_a.sent)
        await node_a.send_data(node_b.id, b"payload")
        data_pkt = next(p for p in fake_a.sent[before:] if p.type == DATA)
        fake_b.inject(data_pkt)

        src, payload = await asyncio.wait_for(node_b.receive_data(), timeout=1.0)

        assert src == node_a.id
        assert payload == b"payload"

        await node_a.stop()
        await node_b.stop()


# ---------------------------------------------------------------------------
# 12.3 — Routing / TTL
# ---------------------------------------------------------------------------

class TestE2ETTL:
    async def test_e2e_handshake_ttl_decremented(self):
        node_a, t_ab, node_b, t_ba, t_bc, node_c, t_cb = await _make_chain()

        await node_a._initiate_e2e_handshake(node_c.id)
        original_ttl = t_ab.sent[-1].ttl

        t_ba.inject(t_ab.sent[-1])
        await asyncio.sleep(0.1)

        forwarded = next((p for p in t_bc.sent if p.type == E2E_HANDSHAKE), None)
        assert forwarded is not None
        assert forwarded.ttl == original_ttl - 1

        await node_a.stop()
        await node_b.stop()
        await node_c.stop()

    async def test_e2e_handshake_ttl_zero_dropped(self):
        node_a, t_ab, node_b, t_ba, t_bc, node_c, t_cb = await _make_chain()

        await node_a._initiate_e2e_handshake(node_c.id)
        hs = t_ab.sent[-1]
        # Craft a packet with TTL=1 so B drops it instead of forwarding
        dying = Packet.create(E2E_HANDSHAKE, hs.src_id, hs.dst_id, hs.payload, ttl=1)

        before_bc = len(t_bc.sent)
        t_ba.inject(dying)
        await asyncio.sleep(0.1)

        forwarded = [p for p in t_bc.sent[before_bc:] if p.type == E2E_HANDSHAKE]
        assert forwarded == []

        await node_a.stop()
        await node_b.stop()
        await node_c.stop()

    async def test_e2e_handshake_msg_id_dedup(self):
        node_a, t_ab, node_b, t_ba, t_bc, node_c, t_cb = await _make_chain()

        await node_a._initiate_e2e_handshake(node_c.id)
        hs = t_ab.sent[-1]

        before_bc = len(t_bc.sent)
        t_ba.inject(hs)
        await asyncio.sleep(0.05)
        t_ba.inject(hs)   # duplicate
        await asyncio.sleep(0.1)

        forwarded = [p for p in t_bc.sent[before_bc:] if p.type == E2E_HANDSHAKE]
        assert len(forwarded) == 1

        await node_a.stop()
        await node_b.stop()
        await node_c.stop()


# ---------------------------------------------------------------------------
# 12.3b — Simultaneous open (glare)
# ---------------------------------------------------------------------------

async def _pump_pair(fake_a: FakeTransport, fake_b: FakeTransport,
                     rounds: int = 8) -> None:
    """Shuttle every newly-sent packet across the A↔B link until quiescent."""
    ia = ib = 0
    for _ in range(rounds):
        new_a, ia = fake_a.sent[ia:], len(fake_a.sent)
        new_b, ib = fake_b.sent[ib:], len(fake_b.sent)
        for p in new_a:
            fake_b.inject(p)
        for p in new_b:
            fake_a.inject(p)
        await asyncio.sleep(0.05)


class TestE2EGlare:
    async def test_simultaneous_open_converges(self):
        """Both peers initiate an E2E handshake at once. They must settle on a
        single shared key — proven by data flowing correctly in both
        directions — instead of racing to two mismatched sessions."""
        node_a, fake_a = await make_node()
        node_b, fake_b = await make_node()
        _cross_trust(node_a, node_b)
        await _make_authed_pair(node_a, fake_a, node_b, fake_b)

        # Glare: both sides kick off a handshake before either has replied.
        await node_a.send_data(node_b.id, b"a->b")
        await node_b.send_data(node_a.id, b"b->a")
        await _pump_pair(fake_a, fake_b)

        assert node_b.id in node_a._e2e_sessions
        assert node_a.id in node_b._e2e_sessions

        # The queued payloads must arrive intact on both ends.
        src_b, data_b = await asyncio.wait_for(node_b.receive_data(), timeout=1.0)
        src_a, data_a = await asyncio.wait_for(node_a.receive_data(), timeout=1.0)
        assert (src_b, data_b) == (node_a.id, b"a->b")
        assert (src_a, data_a) == (node_b.id, b"b->a")

        # And a fresh message still round-trips on the converged key.
        await node_a.send_data(node_b.id, b"again")
        await _pump_pair(fake_a, fake_b)
        src, data = await asyncio.wait_for(node_b.receive_data(), timeout=1.0)
        assert (src, data) == (node_a.id, b"again")

        await node_a.stop()
        await node_b.stop()


# ---------------------------------------------------------------------------
# 12.4 — Error cases
# ---------------------------------------------------------------------------

class TestE2EErrors:
    async def test_send_to_self_raises(self):
        node, fake = await make_node()
        with pytest.raises(ValueError):
            await node.send_data(node.id, b"oops")
        await node.stop()

    async def test_handshake_to_unknown_target_no_session(self):
        """If there's no routing peer, handshake is silently dropped (no crash)."""
        node_a, fake_a = await make_node()
        unknown = NodeID(os.urandom(20))
        # No peers with authenticated_id → _route_outbound drops silently
        await node_a._initiate_e2e_handshake(unknown)
        # State is still set (pending) but no session
        assert unknown not in node_a._e2e_sessions
        await node_a.stop()
